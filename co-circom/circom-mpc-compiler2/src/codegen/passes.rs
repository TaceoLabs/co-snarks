//! Post-lowering bytecode passes.
//!
//! Lowering emits absolute instruction targets, so any pass that removes instructions
//! must update every control-flow target in the body. This module owns that bookkeeping:
//! passes describe which old instructions survive and [`compact`] rebuilds the body and
//! remaps all targets through old instruction boundaries. Keeping target rewriting here
//! avoids each optimization growing a subtly different jump-fixup implementation.

use ark_ff::PrimeField;
use circom_mpc_vm2::driver::apply_bin;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::isa::{BinOp, Dst, Instr, Src};
use eyre::{Result, bail, eyre};
use std::collections::{HashMap, VecDeque};

mod batch;
mod copy;
mod cse;
mod dce;
mod memory;

/// Runs the post-lowering pipeline for one template or function body.
///
/// The pipeline validates and constructs a CFG, then repeatedly propagates constants,
/// forwards frame-local constants, simplifies control flow, and eliminates dead register
/// definitions and variable stores. Once that fixed point is reached, dependency-safe
/// interactive multiplications are batched.
pub(super) fn run<F: PrimeField>(
    instrs: Vec<Instr>,
    body_name: &str,
    num_field_regs: usize,
    constants: &mut Vec<F>,
    constant_ids: &mut HashMap<F, u32>,
    max_batch_size: usize,
) -> Result<Vec<Instr>> {
    let mut instrs = instrs;
    let mut folded = 0usize;
    let mut unreachable = 0usize;
    let mut removed_dead = 0usize;
    let mut propagated_register_copies = 0usize;
    let mut removed_redundant_moves = 0usize;
    let mut forwarded_var_loads = 0usize;
    let mut removed_dead_var_stores = 0usize;
    let mut reused_common_subexpressions = 0usize;

    // Every transformation is monotone: operands only become constants or canonical
    // register sources, instructions only simplify, and bytecode only disappears.
    // Repeating the inexpensive passes exposes second-order wins such as a forwarded var
    // constant selecting a branch, whose dead arm then makes another definition dead.
    loop {
        let cfg = ControlFlowGraph::build(&instrs)
            .map_err(|error| eyre!("invalid bytecode for {body_name}: {error}"))?;
        let (next, folded_now) =
            fold_constants(instrs, &cfg, num_field_regs, constants, constant_ids)?;
        instrs = next;
        folded += folded_now;

        let cfg = ControlFlowGraph::build(&instrs)
            .map_err(|error| eyre!("invalid optimized bytecode for {body_name}: {error}"))?;
        let reachable = cfg.reachable_instructions(instrs.len());
        let unreachable_now = reachable.iter().filter(|keep| !**keep).count();
        if unreachable_now != 0 {
            instrs = compact(instrs, &reachable)?;
            unreachable += unreachable_now;
        }

        let (next, fallthrough_now) = remove_fallthrough_jumps(instrs)?;
        instrs = next;
        folded += fallthrough_now;

        let (next, copies_now, moves_now) = copy::propagate_register_copies(instrs)?;
        instrs = next;
        propagated_register_copies += copies_now;
        removed_redundant_moves += moves_now;

        let (next, forwarded_now) = memory::forward_var_values(instrs)?;
        instrs = next;
        forwarded_var_loads += forwarded_now;

        let (next, dead_stores_now) = memory::eliminate_dead_var_stores(instrs)?;
        instrs = next;
        removed_dead_var_stores += dead_stores_now;

        let (next, cse_now) = cse::eliminate_common_subexpressions(instrs, num_field_regs)?;
        instrs = next;
        reused_common_subexpressions += cse_now;

        let (next, dead_regs_now) = dce::eliminate_dead_register_defs(instrs)?;
        instrs = next;
        removed_dead += dead_regs_now;

        if folded_now
            + unreachable_now
            + fallthrough_now
            + copies_now
            + moves_now
            + forwarded_now
            + dead_stores_now
            + cse_now
            + dead_regs_now
            == 0
        {
            break;
        }
    }

    let (instrs, bin_batches, bin_batch_lanes) =
        batch::batch_independent_ops(instrs, max_batch_size)?;
    let cfg = ControlFlowGraph::build(&instrs)
        .map_err(|error| eyre!("invalid optimized bytecode for {body_name}: {error}"))?;
    tracing::trace!(
        body = body_name,
        instructions = instrs.len(),
        basic_blocks = cfg.blocks.len(),
        cfg_edges = cfg.edge_count(),
        folded_instructions = folded,
        removed_unreachable = unreachable,
        removed_dead_register_defs = removed_dead,
        propagated_register_copies,
        removed_redundant_moves,
        forwarded_var_loads,
        removed_dead_var_stores,
        reused_common_subexpressions,
        bin_batches,
        bin_batch_lanes,
        "ran post-lowering bytecode passes"
    );
    Ok(instrs)
}

/// A maximal straight-line instruction range and its possible successors.
#[derive(Debug, PartialEq, Eq)]
struct BasicBlock {
    start: usize,
    end: usize,
    successors: Vec<Successor>,
}

/// A CFG edge either enters another basic block or leaves the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Successor {
    Block(usize),
    Exit,
}

/// Control-flow view of a lowered body.
#[derive(Debug, PartialEq, Eq)]
struct ControlFlowGraph {
    blocks: Vec<BasicBlock>,
}

impl ControlFlowGraph {
    fn build(instrs: &[Instr]) -> Result<Self> {
        validate_targets(instrs)?;
        if instrs.is_empty() {
            return Ok(Self { blocks: Vec::new() });
        }

        // A dense marker array is linear and cache-friendly. Bytecode bodies are dense
        // instruction vectors, so a tree/set of sparse leaders only adds allocations
        // and pointer chasing here.
        let mut leaders = vec![false; instrs.len() + 1];
        leaders[0] = true;
        leaders[instrs.len()] = true;
        for (ip, instr) in instrs.iter().enumerate() {
            if let Some(target) = target(instr) {
                leaders[target as usize] = true;
            }
            if is_block_terminator(instr) {
                leaders[ip + 1] = true;
            }
        }
        let leaders = leaders
            .into_iter()
            .enumerate()
            .filter_map(|(ip, is_leader)| is_leader.then_some(ip))
            .collect::<Vec<_>>();
        let mut block_at = vec![usize::MAX; instrs.len()];
        for (block, range) in leaders.windows(2).enumerate() {
            for slot in &mut block_at[range[0]..range[1]] {
                *slot = block;
            }
        }

        let mut blocks = Vec::with_capacity(leaders.len() - 1);
        for range in leaders.windows(2) {
            let start = range[0];
            let end = range[1];
            if start == end {
                continue;
            }
            let successors = successors(instrs, end - 1, &block_at);
            blocks.push(BasicBlock {
                start,
                end,
                successors,
            });
        }
        Ok(Self { blocks })
    }

    fn edge_count(&self) -> usize {
        self.blocks.iter().map(|block| block.successors.len()).sum()
    }

    fn reachable_instructions(&self, instruction_count: usize) -> Vec<bool> {
        let mut keep = vec![false; instruction_count];
        if self.blocks.is_empty() {
            return keep;
        }

        let mut seen = vec![false; self.blocks.len()];
        let mut pending = vec![0usize];
        while let Some(block_id) = pending.pop() {
            if seen[block_id] {
                continue;
            }
            seen[block_id] = true;
            let block = &self.blocks[block_id];
            keep[block.start..block.end].fill(true);
            for successor in &block.successors {
                if let Successor::Block(next) = successor
                    && !seen[*next]
                {
                    pending.push(*next);
                }
            }
        }
        keep
    }
}

/// Computes sparse constant facts at every basic-block entry.
///
/// Only known constants are stored. The first incoming edge seeds a block and later
/// incoming edges intersect that map, so a fact survives a join exactly when every path
/// agrees on its value. Maps can only shrink after that initial seed, which makes loops
/// converge without allocating `blocks * num_field_regs` lattice entries.
fn constant_inputs<F: PrimeField>(
    instrs: &[Instr],
    cfg: &ControlFlowGraph,
    num_field_regs: usize,
    constants: &mut Vec<F>,
    constant_ids: &mut HashMap<F, u32>,
) -> Result<Vec<HashMap<u16, u32>>> {
    if cfg.blocks.is_empty() {
        return Ok(Vec::new());
    }

    let mut inputs = vec![None; cfg.blocks.len()];
    // Body-entry registers have no incoming values. Keeping the implicit entry edge
    // empty also prevents a back-edge targeting block zero from inventing facts.
    inputs[0] = Some(HashMap::new());
    let mut pending = VecDeque::from([0usize]);
    let mut queued = vec![false; cfg.blocks.len()];
    queued[0] = true;
    let mut driver = None;

    while let Some(block_id) = pending.pop_front() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        let mut known = inputs[block_id].clone().unwrap_or_default();
        for instr in &instrs[block.start..block.end] {
            transfer_constants(
                instr,
                &mut known,
                num_field_regs,
                constants,
                constant_ids,
                &mut driver,
            )?;
        }

        for successor in &block.successors {
            let Successor::Block(next) = successor else {
                continue;
            };
            let changed = if let Some(input) = &mut inputs[*next] {
                let old_len = input.len();
                input.retain(|reg, value| known.get(reg) == Some(value));
                input.len() != old_len
            } else {
                inputs[*next] = Some(known.clone());
                true
            };
            if changed && !queued[*next] {
                queued[*next] = true;
                pending.push_back(*next);
            }
        }
    }

    Ok(inputs.into_iter().map(Option::unwrap_or_default).collect())
}

/// Folds scalar constants using the SCCP facts computed above. Besides ordinary
/// arithmetic, this selects constant public/shared branches and rewrites their structured
/// control-flow scaffolding, allowing the outer fixed point to remove newly unreachable
/// blocks and propagate again through the smaller CFG.
fn fold_constants<F: PrimeField>(
    mut instrs: Vec<Instr>,
    cfg: &ControlFlowGraph,
    num_field_regs: usize,
    constants: &mut Vec<F>,
    constant_ids: &mut HashMap<F, u32>,
) -> Result<(Vec<Instr>, usize)> {
    let known_inputs = constant_inputs(&instrs, cfg, num_field_regs, constants, constant_ids)?;
    let mut known = HashMap::new();
    let mut keep = vec![true; instrs.len()];
    let mut constant_branches = Vec::new();
    let mut folded = 0usize;
    // Signed-comparison setup computes a field-dependent boundary. Most bodies have no
    // literal binary expression to fold, so construct the plain driver lazily.
    let mut driver = None;

    for (block_id, block) in cfg.blocks.iter().enumerate() {
        known.clone_from(&known_inputs[block_id]);
        for ip in block.start..block.end {
            match instrs[ip].clone() {
                Instr::Bin { op, dst, a, b } => {
                    let a = resolve_src(a, &known);
                    let b = resolve_src(b, &known);
                    let replacement =
                        fold_bin(op, a, b, constants, &mut driver).map(|folded| match folded {
                            Folded::Value(value) => {
                                intern_constant(value, constants, constant_ids).map(Src::Const)
                            }
                            Folded::Source(src) => Ok(src),
                        });
                    if let Some(src) = replacement.transpose()? {
                        if src == Src::Reg(dst) {
                            keep[ip] = false;
                        } else {
                            instrs[ip] = Instr::Mov {
                                dst: Dst::Reg(dst),
                                src,
                            };
                        }
                        set_known(&mut known, dst, constant_id(src));
                        folded += 1;
                    } else {
                        instrs[ip] = Instr::Bin { op, dst, a, b };
                        set_known(&mut known, dst, None);
                    }
                }
                Instr::Neg { dst, a } => {
                    let a = resolve_src(a, &known);
                    if let Some(value) = constant(a, constants) {
                        let id = intern_constant(-value, constants, constant_ids)?;
                        instrs[ip] = Instr::Mov {
                            dst: Dst::Reg(dst),
                            src: Src::Const(id),
                        };
                        set_known(&mut known, dst, Some(id));
                        folded += 1;
                    } else {
                        instrs[ip] = Instr::Neg { dst, a };
                        set_known(&mut known, dst, None);
                    }
                }
                Instr::Mov { dst, src } => {
                    let src = resolve_src(src, &known);
                    instrs[ip] = Instr::Mov { dst, src };
                    if let Dst::Reg(dst) = dst {
                        if src == Src::Reg(dst) {
                            keep[ip] = false;
                            folded += 1;
                        }
                        set_known(&mut known, dst, constant_id(src));
                    }
                }
                Instr::BinBatch { op, mut lanes } => {
                    for lane in &mut lanes {
                        lane.a = resolve_src(lane.a, &known);
                        lane.b = resolve_src(lane.b, &known);
                        set_known(&mut known, lane.dst, None);
                        if let Some(Dst::Reg(dst)) = lane.store {
                            set_known(&mut known, dst, None);
                        }
                    }
                    instrs[ip] = Instr::BinBatch { op, lanes };
                }
                Instr::EqN { dst, a, b, n } => {
                    let replacement = if n == 0 || a == b {
                        Some(intern_constant(F::ONE, constants, constant_ids)?)
                    } else if n == 1 {
                        let a = resolve_src(a, &known);
                        let b = resolve_src(b, &known);
                        match (constant(a, constants), constant(b, constants)) {
                            (Some(a), Some(b)) => {
                                Some(intern_constant(F::from(a == b), constants, constant_ids)?)
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    if let Some(id) = replacement {
                        instrs[ip] = Instr::Mov {
                            dst: Dst::Reg(dst),
                            src: Src::Const(id),
                        };
                        set_known(&mut known, dst, Some(id));
                        folded += 1;
                    } else {
                        set_known(&mut known, dst, None);
                    }
                }
                Instr::LoadN { dst, src, n: 1 } => {
                    let src = resolve_src(src, &known);
                    instrs[ip] = Instr::Mov {
                        dst: Dst::Reg(dst),
                        src,
                    };
                    set_known(&mut known, dst, constant_id(src));
                    folded += 1;
                }
                Instr::BinN {
                    op,
                    dst,
                    a,
                    b,
                    n: 1,
                } => {
                    instrs[ip] = Instr::Bin {
                        op,
                        dst,
                        a: resolve_src(a, &known),
                        b: resolve_src(b, &known),
                    };
                    set_known(&mut known, dst, None);
                    folded += 1;
                }
                Instr::LoadN { dst, src, n } => {
                    for k in 0..n {
                        let fact = source_constant_at(src, k, &known, constants);
                        set_known_u32(&mut known, u32::from(dst) + k, fact);
                    }
                }
                Instr::BinN { op, dst, a, b, n } => {
                    for k in 0..n {
                        let fact =
                            match (resolve_src_at(a, k, &known), resolve_src_at(b, k, &known)) {
                                (Some(a), Some(b)) => folded_constant_id(
                                    op,
                                    a,
                                    b,
                                    constants,
                                    constant_ids,
                                    &mut driver,
                                )?,
                                _ => None,
                            };
                        set_known_u32(&mut known, u32::from(dst) + k, fact);
                    }
                }
                Instr::StoreN {
                    dst: Dst::Reg(dst),
                    src,
                    n,
                } => {
                    let facts = (0..n)
                        .map(|k| known.get(&u16_at(src, k)).copied())
                        .collect::<Vec<_>>();
                    for (k, fact) in facts.into_iter().enumerate() {
                        set_known_u32(&mut known, u32::from(dst) + k as u32, fact);
                    }
                }
                Instr::OutputSub { dst, n, .. } => {
                    clear_known_range(&mut known, dst, n);
                }
                Instr::CallFn { ret, ret_n, .. } => {
                    clear_known_range(&mut known, ret, ret_n);
                }
                Instr::ToIndex { dst, src } => {
                    instrs[ip] = Instr::ToIndex {
                        dst,
                        src: resolve_src(src, &known),
                    };
                }
                Instr::JmpIfZero { cond, target } => {
                    let cond = resolve_src(cond, &known);
                    if let Some(value) = constant(cond, constants) {
                        if value == F::ZERO {
                            instrs[ip] = Instr::Jmp { target };
                        } else {
                            keep[ip] = false;
                        }
                        folded += 1;
                    } else {
                        instrs[ip] = Instr::JmpIfZero { cond, target };
                    }
                }
                Instr::SharedIf { cond, else_target } => {
                    let cond = resolve_src(cond, &known);
                    instrs[ip] = Instr::SharedIf { cond, else_target };
                    if let Some(value) = constant(cond, constants) {
                        constant_branches.push((ip, value != F::ZERO));
                    }
                }
                Instr::SharedIfBit { cond, else_target } => {
                    let cond = resolve_src(cond, &known);
                    instrs[ip] = Instr::SharedIfBit { cond, else_target };
                    if let Some(value) = constant(cond, constants) {
                        constant_branches.push((ip, value != F::ZERO));
                    }
                }
                Instr::Assert { cond, line } => {
                    instrs[ip] = Instr::Assert {
                        cond: resolve_src(cond, &known),
                        line,
                    };
                }
                Instr::Log { src } => {
                    instrs[ip] = Instr::Log {
                        src: resolve_src(src, &known),
                    };
                }
                Instr::ISet { .. }
                | Instr::IAdd { .. }
                | Instr::IMul { .. }
                | Instr::StoreN { .. }
                | Instr::Jmp { .. }
                | Instr::SharedElse { .. }
                | Instr::SharedEnd
                | Instr::CreateCmp { .. }
                | Instr::InputSub { .. }
                | Instr::Ret { .. }
                | Instr::Return
                | Instr::LogStr { .. }
                | Instr::LogFlush { .. } => {}
            }
        }
    }

    for (ip, take_truthy) in constant_branches {
        fold_structured_branch(&instrs, &mut keep, ip, take_truthy)?;
        folded += 1;
    }

    if keep.iter().all(|keep| *keep) {
        Ok((instrs, folded))
    } else {
        Ok((compact(instrs, &keep)?, folded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Folded<F> {
    Value(F),
    Source(Src),
}

fn fold_bin<F: PrimeField>(
    op: BinOp,
    a: Src,
    b: Src,
    constants: &[F],
    driver: &mut Option<PlainDriver<F>>,
) -> Option<Folded<F>> {
    let av = constant(a, constants);
    let bv = constant(b, constants);
    if let (Some(av), Some(bv)) = (av, bv) {
        let valid = match op {
            BinOp::Div | BinOp::IntDiv | BinOp::Mod => bv != F::ZERO,
            BinOp::BoolAnd | BinOp::BoolOr => is_bit(av) && is_bit(bv),
            // Avoid turning an attacker-controlled constant shift into excessive
            // compile-time allocation. Zero shifts are handled as identities below.
            BinOp::ShiftR | BinOp::ShiftL => false,
            _ => true,
        };
        if valid {
            return apply_bin(driver.get_or_insert_with(PlainDriver::new), op, &av, &bv)
                .ok()
                .map(Folded::Value);
        }
    }

    if a == b {
        return match op {
            BinOp::Sub | BinOp::Neq | BinOp::Lt | BinOp::Gt | BinOp::BitXor => {
                Some(Folded::Value(F::ZERO))
            }
            BinOp::Eq | BinOp::Le | BinOp::Ge => Some(Folded::Value(F::ONE)),
            BinOp::BitOr | BinOp::BitAnd => Some(Folded::Source(a)),
            _ => None,
        };
    }

    match op {
        BinOp::Add => {
            if av == Some(F::ZERO) {
                Some(Folded::Source(b))
            } else if bv == Some(F::ZERO) {
                Some(Folded::Source(a))
            } else {
                None
            }
        }
        BinOp::Sub if bv == Some(F::ZERO) => Some(Folded::Source(a)),
        BinOp::Mul => {
            if av == Some(F::ZERO) || bv == Some(F::ZERO) {
                Some(Folded::Value(F::ZERO))
            } else if av == Some(F::ONE) {
                Some(Folded::Source(b))
            } else if bv == Some(F::ONE) {
                Some(Folded::Source(a))
            } else {
                None
            }
        }
        BinOp::Div if bv == Some(F::ONE) => Some(Folded::Source(a)),
        BinOp::Pow if bv == Some(F::ZERO) => Some(Folded::Value(F::ONE)),
        BinOp::Pow if bv == Some(F::ONE) => Some(Folded::Source(a)),
        BinOp::BitOr | BinOp::BitXor if av == Some(F::ZERO) => Some(Folded::Source(b)),
        BinOp::BitOr | BinOp::BitXor if bv == Some(F::ZERO) => Some(Folded::Source(a)),
        BinOp::BitAnd if av == Some(F::ZERO) || bv == Some(F::ZERO) => Some(Folded::Value(F::ZERO)),
        BinOp::ShiftR | BinOp::ShiftL if bv == Some(F::ZERO) => Some(Folded::Source(a)),
        _ => None,
    }
}

/// Sparse SCCP transfer for one instruction. Definitions overwrite the current physical
/// register fact; values that cannot be proven constant simply remove it from the map.
fn transfer_constants<F: PrimeField>(
    instr: &Instr,
    known: &mut HashMap<u16, u32>,
    num_field_regs: usize,
    constants: &mut Vec<F>,
    constant_ids: &mut HashMap<F, u32>,
    driver: &mut Option<PlainDriver<F>>,
) -> Result<()> {
    match instr {
        Instr::Bin { op, dst, a, b } => {
            let a = resolve_src(*a, known);
            let b = resolve_src(*b, known);
            let fact = folded_constant_id(*op, a, b, constants, constant_ids, driver)?;
            set_known_bounded(known, *dst, fact, num_field_regs);
        }
        Instr::Neg { dst, a } => {
            let fact = constant(resolve_src(*a, known), constants)
                .map(|value| intern_constant(-value, constants, constant_ids))
                .transpose()?;
            set_known_bounded(known, *dst, fact, num_field_regs);
        }
        Instr::EqN { dst, a, b, n } => {
            let fact = if *n == 0 || a == b {
                Some(intern_constant(F::ONE, constants, constant_ids)?)
            } else {
                let mut equal = true;
                let mut all_known = true;
                for k in 0..*n {
                    match (
                        source_constant_at(*a, k, known, constants),
                        source_constant_at(*b, k, known, constants),
                    ) {
                        (Some(a), Some(b)) => {
                            equal &= constants[a as usize] == constants[b as usize]
                        }
                        _ => {
                            all_known = false;
                            break;
                        }
                    }
                }
                all_known
                    .then(|| {
                        intern_constant(
                            if equal { F::ONE } else { F::ZERO },
                            constants,
                            constant_ids,
                        )
                    })
                    .transpose()?
            };
            set_known_bounded(known, *dst, fact, num_field_regs);
        }
        Instr::Mov {
            dst: Dst::Reg(dst),
            src,
        } => {
            let fact = constant_id(resolve_src(*src, known));
            set_known_bounded(known, *dst, fact, num_field_regs);
        }
        Instr::LoadN { dst, src, n } => {
            let facts = (0..*n)
                .map(|k| source_constant_at(*src, k, known, constants))
                .collect::<Vec<_>>();
            for (k, fact) in facts.into_iter().enumerate() {
                set_known_u32_bounded(known, u32::from(*dst) + k as u32, fact, num_field_regs);
            }
        }
        Instr::StoreN {
            dst: Dst::Reg(dst),
            src,
            n,
        } => {
            let facts = (0..*n)
                .map(|k| known.get(&u16_at(*src, k)).copied())
                .collect::<Vec<_>>();
            for (k, fact) in facts.into_iter().enumerate() {
                set_known_u32_bounded(known, u32::from(*dst) + k as u32, fact, num_field_regs);
            }
        }
        Instr::BinN { op, dst, a, b, n } => {
            let mut facts = Vec::with_capacity(*n as usize);
            for k in 0..*n {
                let fact = match (resolve_src_at(*a, k, known), resolve_src_at(*b, k, known)) {
                    (Some(a), Some(b)) => {
                        folded_constant_id(*op, a, b, constants, constant_ids, driver)?
                    }
                    _ => None,
                };
                facts.push(fact);
            }
            for (k, fact) in facts.into_iter().enumerate() {
                set_known_u32_bounded(known, u32::from(*dst) + k as u32, fact, num_field_regs);
            }
        }
        Instr::BinBatch { op, lanes } => {
            // The VM snapshots every lane input before writing any destination.
            let before = known.clone();
            let facts = lanes
                .iter()
                .map(|lane| {
                    folded_constant_id(
                        *op,
                        resolve_src(lane.a, &before),
                        resolve_src(lane.b, &before),
                        constants,
                        constant_ids,
                        driver,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            for (lane, fact) in lanes.iter().zip(facts) {
                set_known_bounded(known, lane.dst, fact, num_field_regs);
                if let Some(Dst::Reg(dst)) = lane.store {
                    set_known_bounded(known, dst, fact, num_field_regs);
                }
            }
        }
        Instr::OutputSub { dst, n, .. }
        | Instr::CallFn {
            ret: dst, ret_n: n, ..
        } => {
            clear_known_range(known, *dst, *n);
        }
        Instr::Mov { .. }
        | Instr::StoreN { .. }
        | Instr::ISet { .. }
        | Instr::IAdd { .. }
        | Instr::IMul { .. }
        | Instr::ToIndex { .. }
        | Instr::Jmp { .. }
        | Instr::JmpIfZero { .. }
        | Instr::SharedIf { .. }
        | Instr::SharedIfBit { .. }
        | Instr::SharedElse { .. }
        | Instr::SharedEnd
        | Instr::CreateCmp { .. }
        | Instr::InputSub { .. }
        | Instr::Ret { .. }
        | Instr::Return
        | Instr::Assert { .. }
        | Instr::Log { .. }
        | Instr::LogStr { .. }
        | Instr::LogFlush { .. } => {}
    }
    Ok(())
}

fn folded_constant_id<F: PrimeField>(
    op: BinOp,
    a: Src,
    b: Src,
    constants: &mut Vec<F>,
    constant_ids: &mut HashMap<F, u32>,
    driver: &mut Option<PlainDriver<F>>,
) -> Result<Option<u32>> {
    fold_bin(op, a, b, constants, driver)
        .map(|folded| match folded {
            Folded::Value(value) => intern_constant(value, constants, constant_ids).map(Some),
            Folded::Source(src) => Ok(constant_id(src)),
        })
        .transpose()
        .map(Option::flatten)
}

fn fold_structured_branch(
    instrs: &[Instr],
    keep: &mut [bool],
    if_ip: usize,
    take_truthy: bool,
) -> Result<()> {
    let else_ip = match &instrs[if_ip] {
        Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
            *else_target as usize
        }
        _ => bail!("constant branch at {if_ip} is not SharedIf/SharedIfBit"),
    };

    if matches!(instrs.get(else_ip), Some(Instr::SharedEnd)) {
        if take_truthy {
            keep[if_ip] = false;
            keep[else_ip] = false;
        } else {
            keep[if_ip..=else_ip].fill(false);
        }
        return Ok(());
    }

    let shared_else_ip = else_ip
        .checked_sub(1)
        .ok_or_else(|| eyre!("constant branch at {if_ip} has invalid else target {else_ip}"))?;
    let end_ip = match instrs.get(shared_else_ip) {
        Some(Instr::SharedElse { end_target }) => *end_target as usize,
        _ => bail!("constant branch at {if_ip} does not have SharedElse before target {else_ip}"),
    };
    if !matches!(instrs.get(end_ip), Some(Instr::SharedEnd)) {
        bail!("constant branch at {if_ip} does not end at SharedEnd {end_ip}");
    }

    if take_truthy {
        keep[if_ip] = false;
        keep[shared_else_ip..=end_ip].fill(false);
    } else {
        keep[if_ip..else_ip].fill(false);
        keep[end_ip] = false;
    }
    Ok(())
}

/// Removes unconditional jumps whose remapped target is already the next instruction.
/// Compaction can expose another such jump, so repeat until the body stabilizes.
fn remove_fallthrough_jumps(mut instrs: Vec<Instr>) -> Result<(Vec<Instr>, usize)> {
    let mut removed = 0usize;
    loop {
        let keep = instrs
            .iter()
            .enumerate()
            .map(
                |(ip, instr)| !matches!(instr, Instr::Jmp { target } if *target as usize == ip + 1),
            )
            .collect::<Vec<_>>();
        let count = keep.iter().filter(|keep| !**keep).count();
        if count == 0 {
            return Ok((instrs, removed));
        }
        removed += count;
        instrs = compact(instrs, &keep)?;
    }
}

fn resolve_src(src: Src, known: &HashMap<u16, u32>) -> Src {
    match src {
        Src::Reg(reg) => known.get(&reg).copied().map(Src::Const).unwrap_or(src),
        _ => src,
    }
}

fn resolve_src_at(src: Src, k: u32, known: &HashMap<u16, u32>) -> Option<Src> {
    Some(match src {
        Src::Reg(reg) => known
            .get(&u16::try_from(u32::from(reg).checked_add(k)?).ok()?)
            .copied()
            .map(Src::Const)
            .unwrap_or(Src::Reg(u16::try_from(u32::from(reg) + k).ok()?)),
        Src::Const(id) => Src::Const(id.checked_add(k)?),
        Src::Var(addr) => Src::Var(offset_addr(addr, k)?),
        Src::Signal(addr) => Src::Signal(offset_addr(addr, k)?),
    })
}

fn offset_addr(addr: circom_mpc_vm2::isa::Addr, k: u32) -> Option<circom_mpc_vm2::isa::Addr> {
    use circom_mpc_vm2::isa::Addr;
    Some(match addr {
        Addr::Const(slot) => Addr::Const(slot.checked_add(k)?),
        Addr::Affine {
            ireg,
            stride,
            offset,
        } => Addr::Affine {
            ireg,
            stride,
            offset: offset.checked_add(k)?,
        },
        Addr::Dynamic(ireg) if k == 0 => Addr::Dynamic(ireg),
        // `read_n` adds `k` after resolving a dynamic address, which has no equivalent
        // scalar `Addr` form without materializing a new integer register.
        Addr::Dynamic(_) => return None,
    })
}

fn source_constant_at<F: PrimeField>(
    src: Src,
    k: u32,
    known: &HashMap<u16, u32>,
    constants: &[F],
) -> Option<u32> {
    match src {
        Src::Reg(reg) => known.get(&u16_at(reg, k)).copied(),
        Src::Const(id) => {
            let id = id.checked_add(k)?;
            constants.get(id as usize).map(|_| id)
        }
        Src::Var(_) | Src::Signal(_) => None,
    }
}

fn u16_at(start: u16, k: u32) -> u16 {
    u16::try_from(u32::from(start) + k).expect("validated register range exceeds u16")
}

fn constant<F: PrimeField>(src: Src, constants: &[F]) -> Option<F> {
    match src {
        Src::Const(id) => constants.get(id as usize).copied(),
        _ => None,
    }
}

fn constant_id(src: Src) -> Option<u32> {
    match src {
        Src::Const(id) => Some(id),
        _ => None,
    }
}

fn is_bit<F: PrimeField>(value: F) -> bool {
    value == F::ZERO || value == F::ONE
}

fn intern_constant<F: PrimeField>(
    value: F,
    constants: &mut Vec<F>,
    constant_ids: &mut HashMap<F, u32>,
) -> Result<u32> {
    if let Some(id) = constant_ids.get(&value) {
        return Ok(*id);
    }
    let id = u32::try_from(constants.len())
        .map_err(|_| eyre!("constant table exceeds u32::MAX entries"))?;
    constants.push(value);
    constant_ids.insert(value, id);
    Ok(id)
}

fn set_known(known: &mut HashMap<u16, u32>, reg: u16, value: Option<u32>) {
    if let Some(value) = value {
        known.insert(reg, value);
    } else {
        known.remove(&reg);
    }
}

fn set_known_bounded(
    known: &mut HashMap<u16, u32>,
    reg: u16,
    value: Option<u32>,
    num_field_regs: usize,
) {
    if usize::from(reg) < num_field_regs {
        set_known(known, reg, value);
    }
}

fn set_known_u32(known: &mut HashMap<u16, u32>, reg: u32, value: Option<u32>) {
    if let Ok(reg) = u16::try_from(reg) {
        set_known(known, reg, value);
    }
}

fn set_known_u32_bounded(
    known: &mut HashMap<u16, u32>,
    reg: u32,
    value: Option<u32>,
    num_field_regs: usize,
) {
    if let Ok(reg) = u16::try_from(reg) {
        set_known_bounded(known, reg, value, num_field_regs);
    }
}

fn clear_known_range(known: &mut HashMap<u16, u32>, start: u16, n: u32) {
    for k in 0..n {
        known.remove(&u16_at(start, k));
    }
}

fn validate_targets(instrs: &[Instr]) -> Result<()> {
    for (ip, instr) in instrs.iter().enumerate() {
        let Some(target) = target(instr) else {
            continue;
        };
        if target as usize > instrs.len() {
            bail!(
                "instruction {ip} targets {target}, past body length {}",
                instrs.len()
            );
        }
    }
    Ok(())
}

fn is_block_terminator(instr: &Instr) -> bool {
    matches!(
        instr,
        Instr::Jmp { .. }
            | Instr::JmpIfZero { .. }
            | Instr::SharedIf { .. }
            | Instr::SharedIfBit { .. }
            | Instr::SharedElse { .. }
            | Instr::Ret { .. }
            | Instr::Return
    )
}

fn successors(instrs: &[Instr], ip: usize, block_at: &[usize]) -> Vec<Successor> {
    let fallthrough = || successor(ip + 1, block_at);
    let jump = |target: u32| successor(target as usize, block_at);
    match &instrs[ip] {
        Instr::Jmp { target } => vec![jump(*target)],
        Instr::JmpIfZero { target, .. }
        | Instr::SharedIf {
            else_target: target,
            ..
        }
        | Instr::SharedIfBit {
            else_target: target,
            ..
        }
        | Instr::SharedElse { end_target: target } => {
            let mut edges = vec![fallthrough(), jump(*target)];
            edges.dedup();
            edges
        }
        // A Ret exits when executed publicly, but accumulates and falls through under a
        // shared predicate. Keep both edges so data-flow passes remain conservative.
        Instr::Ret { .. } => {
            let mut edges = vec![Successor::Exit, fallthrough()];
            edges.dedup();
            edges
        }
        Instr::Return => vec![Successor::Exit],
        _ => vec![fallthrough()],
    }
}

fn successor(ip: usize, block_at: &[usize]) -> Successor {
    block_at
        .get(ip)
        .copied()
        .map(Successor::Block)
        .unwrap_or(Successor::Exit)
}

fn target(instr: &Instr) -> Option<u32> {
    match instr {
        Instr::Jmp { target } | Instr::JmpIfZero { target, .. } => Some(*target),
        Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
            Some(*else_target)
        }
        Instr::SharedElse { end_target } => Some(*end_target),
        _ => None,
    }
}

fn target_mut(instr: &mut Instr) -> Option<&mut u32> {
    match instr {
        Instr::Jmp { target } | Instr::JmpIfZero { target, .. } => Some(target),
        Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
            Some(else_target)
        }
        Instr::SharedElse { end_target } => Some(end_target),
        _ => None,
    }
}

/// Removes instructions for which `keep[old_ip]` is false and remaps every absolute
/// target. A target of a removed instruction lands on the next surviving instruction;
/// a target at the old end of the body lands at the new end.
///
/// This deletion-only primitive is sufficient for unreachable-block cleanup and DCE.
/// Passes that replace an instruction in place can mutate it before calling `compact`.
fn compact(instrs: Vec<Instr>, keep: &[bool]) -> Result<Vec<Instr>> {
    if instrs.len() != keep.len() {
        bail!(
            "keep map length {} does not match body length {}",
            keep.len(),
            instrs.len()
        );
    }
    validate_targets(&instrs)?;

    // `boundaries[old_ip]` is the new instruction boundary immediately before the old
    // instruction. It also contains the one-past-the-end boundary at `old_len`.
    let mut boundaries = Vec::with_capacity(instrs.len() + 1);
    let mut new_ip = 0usize;
    for &survives in keep {
        boundaries.push(new_ip);
        new_ip += usize::from(survives);
    }
    boundaries.push(new_ip);

    let mut out = Vec::with_capacity(new_ip);
    for (mut instr, survives) in instrs.into_iter().zip(keep.iter().copied()) {
        if !survives {
            continue;
        }
        if let Some(old_target) = target_mut(&mut instr) {
            *old_target = u32::try_from(boundaries[*old_target as usize])
                .map_err(|_| eyre!("rewritten body exceeds u32::MAX instructions"))?;
        }
        out.push(instr);
    }
    validate_targets(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use circom_mpc_vm2::isa::{Addr, Dst, RetSrc, Src};

    fn optimize(
        instrs: Vec<Instr>,
        num_field_regs: usize,
        mut constants: Vec<Fr>,
    ) -> (Vec<Instr>, Vec<Fr>) {
        let mut constant_ids = constants
            .iter()
            .copied()
            .enumerate()
            .map(|(id, value)| (value, id as u32))
            .collect();
        let instrs = run(
            instrs,
            "test",
            num_field_regs,
            &mut constants,
            &mut constant_ids,
            0,
        )
        .unwrap();
        (instrs, constants)
    }

    fn fold_only(
        instrs: Vec<Instr>,
        num_field_regs: usize,
        mut constants: Vec<Fr>,
    ) -> (Vec<Instr>, Vec<Fr>) {
        let mut constant_ids = constants
            .iter()
            .copied()
            .enumerate()
            .map(|(id, value)| (value, id as u32))
            .collect();
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        let (instrs, _) = fold_constants(
            instrs,
            &cfg,
            num_field_regs,
            &mut constants,
            &mut constant_ids,
        )
        .unwrap();
        (instrs, constants)
    }

    #[test]
    fn cfg_models_conditional_and_ret_fallthrough() {
        let instrs = vec![
            Instr::JmpIfZero {
                cond: Src::Reg(0),
                target: 3,
            },
            Instr::Ret {
                src: RetSrc::Reg(1),
                n: 1,
            },
            Instr::Jmp { target: 4 },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Const(0),
            },
        ];

        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert_eq!(cfg.blocks.len(), 4);
        assert_eq!(
            cfg.blocks[0].successors,
            vec![Successor::Block(1), Successor::Block(3)]
        );
        assert_eq!(
            cfg.blocks[1].successors,
            vec![Successor::Exit, Successor::Block(2)]
        );
        assert_eq!(cfg.blocks[2].successors, vec![Successor::Exit]);
        assert_eq!(cfg.blocks[3].successors, vec![Successor::Exit]);
    }

    #[test]
    fn rejects_target_past_end_of_body() {
        let mut constants = Vec::<Fr>::new();
        let mut constant_ids = HashMap::new();
        let error = run(
            vec![Instr::Jmp { target: 2 }],
            "bad",
            0,
            &mut constants,
            &mut constant_ids,
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("instruction 0 targets 2"));
    }

    #[test]
    fn folds_literals_propagates_register_constants_and_applies_identities() {
        let (out, constants) = fold_only(
            vec![
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 0,
                    a: Src::Const(0),
                    b: Src::Const(1),
                },
                Instr::Bin {
                    op: BinOp::Mul,
                    dst: 1,
                    a: Src::Reg(0),
                    b: Src::Const(2),
                },
                Instr::Bin {
                    op: BinOp::Mul,
                    dst: 2,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Const(3),
                },
                Instr::Bin {
                    op: BinOp::Eq,
                    dst: 3,
                    a: Src::Reg(2),
                    b: Src::Reg(2),
                },
                Instr::Return,
            ],
            4,
            vec![
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
                Fr::from(1u64),
            ],
        );

        let five = constants
            .iter()
            .position(|value| *value == Fr::from(5u64))
            .unwrap() as u32;
        let twenty = constants
            .iter()
            .position(|value| *value == Fr::from(20u64))
            .unwrap() as u32;
        assert_eq!(
            out,
            vec![
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(five),
                },
                Instr::Mov {
                    dst: Dst::Reg(1),
                    src: Src::Const(twenty),
                },
                Instr::Mov {
                    dst: Dst::Reg(2),
                    src: Src::Signal(Addr::Const(0)),
                },
                Instr::Mov {
                    dst: Dst::Reg(3),
                    src: Src::Const(3),
                },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn constant_jump_removes_unreachable_fallthrough_and_remaps_target() {
        let (out, _) = optimize(
            vec![
                Instr::JmpIfZero {
                    cond: Src::Const(0),
                    target: 3,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(1),
                },
                Instr::Jmp { target: 4 },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(2),
                },
                Instr::Return,
            ],
            0,
            vec![Fr::from(0u64), Fr::from(11u64), Fr::from(22u64)],
        );
        assert_eq!(
            out,
            vec![
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(2),
                },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn constant_shared_if_selects_one_arm_and_removes_predication_scaffold() {
        let body = |cond| {
            vec![
                Instr::SharedIfBit {
                    cond: Src::Const(cond),
                    else_target: 3,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(2),
                },
                Instr::SharedElse { end_target: 4 },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(3),
                },
                Instr::SharedEnd,
                Instr::Return,
            ]
        };
        let constants = vec![
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(10u64),
            Fr::from(20u64),
        ];

        let (truthy, _) = optimize(body(1), 0, constants.clone());
        let (falsy, _) = optimize(body(0), 0, constants);
        assert_eq!(
            truthy,
            vec![
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(2),
                },
                Instr::Return,
            ]
        );
        assert_eq!(
            falsy,
            vec![
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(3),
                },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn sccp_propagates_matching_constants_through_a_cfg_join() {
        let (out, _) = optimize(
            vec![
                Instr::JmpIfZero {
                    cond: Src::Signal(Addr::Const(0)),
                    target: 3,
                },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(0),
                },
                Instr::Jmp { target: 4 },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(0),
                },
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 1,
                    a: Src::Reg(0),
                    b: Src::Const(1),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(1)),
                    src: Src::Reg(1),
                },
                Instr::Return,
            ],
            2,
            vec![Fr::from(2u64), Fr::from(3u64)],
        );
        let five = out.iter().find_map(|instr| match instr {
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Const(id),
            } => Some(*id),
            _ => None,
        });
        assert!(five.is_some(), "joined constant was not folded: {out:?}");
        assert!(!out.iter().any(|instr| matches!(instr, Instr::Bin { .. })));
    }

    #[test]
    fn sccp_drops_a_fact_when_joining_different_constants() {
        let (out, _) = optimize(
            vec![
                Instr::JmpIfZero {
                    cond: Src::Signal(Addr::Const(0)),
                    target: 3,
                },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(0),
                },
                Instr::Jmp { target: 4 },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(1),
                },
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 1,
                    a: Src::Reg(0),
                    b: Src::Const(2),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(1)),
                    src: Src::Reg(1),
                },
                Instr::Return,
            ],
            2,
            vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)],
        );
        assert!(
            out.iter()
                .any(|instr| matches!(instr, Instr::Bin { a: Src::Reg(0), .. }))
        );
    }

    #[test]
    fn sccp_accounts_for_a_loop_backedge() {
        let (out, _) = optimize(
            vec![
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(0),
                },
                Instr::JmpIfZero {
                    cond: Src::Signal(Addr::Const(0)),
                    target: 4,
                },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(1),
                },
                Instr::Jmp { target: 1 },
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 1,
                    a: Src::Reg(0),
                    b: Src::Const(2),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(1)),
                    src: Src::Reg(1),
                },
                Instr::Return,
            ],
            2,
            vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)],
        );
        assert!(
            out.iter()
                .any(|instr| matches!(instr, Instr::Bin { a: Src::Reg(0), .. }))
        );
    }

    #[test]
    fn fixed_point_forwards_var_constant_then_removes_its_store() {
        let (out, _) = optimize(
            vec![
                Instr::Mov {
                    dst: Dst::Var(Addr::Const(0)),
                    src: Src::Const(0),
                },
                Instr::Jmp { target: 2 },
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 0,
                    a: Src::Var(Addr::Const(0)),
                    b: Src::Const(1),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Reg(0),
                },
                Instr::Return,
            ],
            1,
            vec![Fr::from(2u64), Fr::from(3u64)],
        );
        assert_eq!(
            out,
            vec![
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(2),
                },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn fixed_point_forwards_var_register_and_removes_the_store() {
        // `var x = a*b; out1 <== x; out2 <== x + x;` — the var slot mirrors r0, every
        // read forwards to the register, and the store (plus the slot) disappears.
        let (out, _) = optimize(
            vec![
                Instr::Bin {
                    op: BinOp::Mul,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::Mov {
                    dst: Dst::Var(Addr::Const(0)),
                    src: Src::Reg(0),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Var(Addr::Const(0)),
                },
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 1,
                    a: Src::Var(Addr::Const(0)),
                    b: Src::Var(Addr::Const(0)),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(3)),
                    src: Src::Reg(1),
                },
                Instr::Return,
            ],
            2,
            vec![],
        );
        assert!(
            !out.iter().any(|instr| matches!(
                instr,
                Instr::Mov {
                    dst: Dst::Var(_),
                    ..
                } | Instr::Mov {
                    src: Src::Var(_),
                    ..
                }
            )),
            "no var store or var read should survive: {out:?}"
        );
        assert!(out.iter().any(|instr| matches!(
            instr,
            Instr::Bin {
                op: BinOp::Add,
                a: Src::Reg(0),
                b: Src::Reg(0),
                ..
            }
        )));
    }

    #[test]
    fn fixed_point_deduplicates_repeated_interactive_multiplication() {
        // Two identical signal products stored to two different signals: CSE turns the
        // second Bin into a register Mov, copy propagation folds it into the store, and
        // DCE removes the Mov — one interactive multiplication remains.
        let (out, _) = optimize(
            vec![
                Instr::Bin {
                    op: BinOp::Mul,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Reg(0),
                },
                Instr::Bin {
                    op: BinOp::Mul,
                    dst: 1,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(3)),
                    src: Src::Reg(1),
                },
                Instr::Return,
            ],
            2,
            vec![],
        );
        assert_eq!(
            out,
            vec![
                Instr::Bin {
                    op: BinOp::Mul,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Reg(0),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(3)),
                    src: Src::Reg(0),
                },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn compact_remaps_every_absolute_target_kind() {
        let instrs = vec![
            Instr::Jmp { target: 7 },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Const(0),
            },
            Instr::JmpIfZero {
                cond: Src::Reg(0),
                target: 7,
            },
            Instr::SharedIf {
                cond: Src::Reg(0),
                else_target: 7,
            },
            Instr::SharedIfBit {
                cond: Src::Reg(0),
                else_target: 7,
            },
            Instr::SharedElse { end_target: 7 },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Const(1),
            },
            Instr::Return,
        ];

        let out = compact(instrs, &[true, false, true, true, true, true, false, true]).unwrap();
        assert_eq!(
            out,
            vec![
                Instr::Jmp { target: 5 },
                Instr::JmpIfZero {
                    cond: Src::Reg(0),
                    target: 5,
                },
                Instr::SharedIf {
                    cond: Src::Reg(0),
                    else_target: 5,
                },
                Instr::SharedIfBit {
                    cond: Src::Reg(0),
                    else_target: 5,
                },
                Instr::SharedElse { end_target: 5 },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn target_of_removed_instruction_advances_to_next_survivor() {
        let out = compact(
            vec![
                Instr::Jmp { target: 1 },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(0),
                },
                Instr::Return,
            ],
            &[true, false, true],
        )
        .unwrap();
        assert_eq!(out, vec![Instr::Jmp { target: 1 }, Instr::Return]);
    }
}
