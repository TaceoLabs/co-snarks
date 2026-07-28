//! Conservative scalar-variable propagation and dead-store elimination.
//!
//! Constant-addressed `Var` slots are the VM's frame-local memory and cannot alias
//! signals or another function/component frame. Exact slots therefore admit ordinary
//! forward and backward data-flow. Dynamic/affine writes, calls, and shared-control
//! boundaries deliberately discard forward facts. In particular, writes under a shared
//! predicate are buffered until a barrier and are not visible to later bytecode in that
//! region, so forwarding through them would be incorrect.
//!
//! Forwarded facts come in two kinds ([`VarValue`]): a slot holds a known interned
//! constant, or a slot holds *the same value as a field register* (store-to-load
//! forwarding — the slot was last written from that register and neither has changed
//! since). Register facts additionally die whenever their register is redefined. A use
//! is rewritten with the facts holding *before* its instruction executes, matching the
//! VM's read-operands-then-write-destination order — so `Mov Var(x), r0` followed by
//! `Bin r0, Var(x), ...` still forwards to `Bin r0, r0, ...` even though the consuming
//! instruction redefines `r0` itself. Like copy propagation's alias facts, a register
//! fact is a *sameness* claim, not a value claim, so it survives a CFG join whenever
//! every incoming path established it, even if the runtime value differs per path.

use super::{ControlFlowGraph, Successor, compact};
use circom_mpc_vm2::isa::{Addr, Dst, Instr, RetSrc, Src};
use eyre::Result;
use std::collections::{HashMap, HashSet, VecDeque};

/// What an exact var slot is known to hold: an interned constant, or the same value as
/// a field register (valid until either the slot or the register is written again).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VarValue {
    Const(u32),
    Reg(u16),
}

impl VarValue {
    fn to_src(self) -> Src {
        match self {
            VarValue::Const(id) => Src::Const(id),
            VarValue::Reg(reg) => Src::Reg(reg),
        }
    }
}

type KnownVars = HashMap<u32, VarValue>;

pub(super) fn forward_var_values(mut instrs: Vec<Instr>) -> Result<(Vec<Instr>, usize)> {
    let cfg = ControlFlowGraph::build(&instrs)?;
    if cfg.blocks.is_empty() {
        return Ok((instrs, 0));
    }
    let shared = shared_region_mask(&instrs);
    let inputs = var_value_inputs(&instrs, &cfg, &shared);
    let mut forwarded = 0usize;

    for (block_id, block) in cfg.blocks.iter().enumerate() {
        let mut known = inputs[block_id].clone();
        for ip in block.start..block.end {
            if shared[ip] {
                known.clear();
                continue;
            }
            forwarded += rewrite_sources(&mut instrs[ip], &known);
            transfer_known_vars(&instrs[ip], &mut known);
        }
    }
    Ok((instrs, forwarded))
}

fn var_value_inputs(instrs: &[Instr], cfg: &ControlFlowGraph, shared: &[bool]) -> Vec<KnownVars> {
    let mut inputs = vec![None; cfg.blocks.len()];
    inputs[0] = Some(KnownVars::new());
    let mut pending = VecDeque::from([0usize]);
    let mut queued = vec![false; cfg.blocks.len()];
    queued[0] = true;

    while let Some(block_id) = pending.pop_front() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        let mut known = inputs[block_id].clone().unwrap_or_default();
        for ip in block.start..block.end {
            if shared[ip] {
                known.clear();
            } else {
                transfer_known_vars(&instrs[ip], &mut known);
            }
        }
        for successor in &block.successors {
            let Successor::Block(next) = successor else {
                continue;
            };
            let changed = if let Some(input) = &mut inputs[*next] {
                let old_len = input.len();
                input.retain(|slot, value| known.get(slot) == Some(value));
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

    inputs.into_iter().map(Option::unwrap_or_default).collect()
}

fn transfer_known_vars(instr: &Instr, known: &mut KnownVars) {
    match instr {
        // Callees have separate frames, but a call is also an execution/protocol
        // boundary. Keeping this invalidation explicit makes the pass robust if the VM's
        // call convention later gains by-reference frame access.
        Instr::CallFn { .. }
        | Instr::SharedIf { .. }
        | Instr::SharedIfBit { .. }
        | Instr::SharedElse { .. }
        | Instr::SharedEnd => known.clear(),
        Instr::Mov {
            dst: Dst::Var(Addr::Const(slot)),
            src,
        } => {
            if let Some(value) = source_value(*src, known) {
                known.insert(*slot, value);
            } else {
                known.remove(slot);
            }
        }
        Instr::Mov {
            dst: Dst::Var(_), ..
        }
        | Instr::StoreN {
            dst: Dst::Var(Addr::Affine { .. } | Addr::Dynamic(_)),
            ..
        } => known.clear(),
        Instr::Mov {
            dst: Dst::Reg(reg), ..
        } => kill_reg_facts(known, *reg, 1),
        Instr::StoreN {
            dst: Dst::Var(Addr::Const(slot)),
            src,
            n,
        } => {
            // The stored registers are not redefined by the store, so every element
            // yields a fresh slot ↔ register fact.
            for k in 0..*n {
                match (slot.checked_add(k), u16::try_from(u32::from(*src) + k)) {
                    (Some(slot), Ok(reg)) => {
                        known.insert(slot, VarValue::Reg(reg));
                    }
                    _ => {
                        known.clear();
                        break;
                    }
                }
            }
        }
        Instr::StoreN {
            dst: Dst::Reg(reg),
            n,
            ..
        } => kill_reg_facts(known, *reg, *n),
        Instr::Bin { dst, .. } | Instr::Neg { dst, .. } | Instr::EqN { dst, .. } => {
            kill_reg_facts(known, *dst, 1);
        }
        Instr::LoadN { dst, n, .. }
        | Instr::BinN { dst, n, .. }
        | Instr::OutputSub { dst, n, .. } => kill_reg_facts(known, *dst, *n),
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes {
                kill_reg_facts(known, lane.dst, 1);
                match lane.store {
                    Some(Dst::Var(Addr::Const(slot))) => {
                        // The lane writes its scalar temporary and the store from it,
                        // so the slot holds the temporary's value afterwards.
                        known.insert(slot, VarValue::Reg(lane.dst));
                    }
                    Some(Dst::Var(_)) => known.clear(),
                    Some(Dst::Reg(reg)) => kill_reg_facts(known, reg, 1),
                    Some(Dst::Signal(_)) | None => {}
                }
            }
        }
        _ => {}
    }
}

fn source_value(src: Src, known: &KnownVars) -> Option<VarValue> {
    match src {
        Src::Const(id) => Some(VarValue::Const(id)),
        Src::Reg(reg) => Some(VarValue::Reg(reg)),
        Src::Var(Addr::Const(slot)) => known.get(&slot).copied(),
        Src::Var(_) | Src::Signal(_) => None,
    }
}

/// Drops every fact claiming a slot holds the same value as one of the `n` registers
/// starting at `start` — those registers are being redefined.
fn kill_reg_facts(known: &mut KnownVars, start: u16, n: u32) {
    known.retain(|_, value| match value {
        VarValue::Reg(reg) => {
            let reg = u32::from(*reg);
            reg < u32::from(start) || reg >= u32::from(start) + n
        }
        VarValue::Const(_) => true,
    });
}

fn rewrite_sources(instr: &mut Instr, known: &KnownVars) -> usize {
    let mut rewritten = 0usize;
    let mut rewrite = |src: &mut Src| {
        if let Src::Var(Addr::Const(slot)) = *src
            && let Some(value) = known.get(&slot)
        {
            *src = value.to_src();
            rewritten += 1;
        }
    };

    match instr {
        Instr::Bin { a, b, .. } => {
            rewrite(a);
            rewrite(b);
        }
        Instr::Neg { a, .. } => rewrite(a),
        Instr::EqN { a, b, n, .. } | Instr::BinN { a, b, n, .. } if *n == 1 => {
            rewrite(a);
            rewrite(b);
        }
        Instr::Mov { src, .. }
        | Instr::ToIndex { src, .. }
        | Instr::Log { src }
        | Instr::JmpIfZero { cond: src, .. }
        | Instr::SharedIf { cond: src, .. }
        | Instr::SharedIfBit { cond: src, .. }
        | Instr::Assert { cond: src, .. } => rewrite(src),
        Instr::LoadN { dst, src, n } if *n == 1 => {
            rewrite(src);
            if matches!(src, Src::Const(_) | Src::Reg(_)) {
                *instr = Instr::Mov {
                    dst: Dst::Reg(*dst),
                    src: *src,
                };
            }
        }
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes {
                rewrite(&mut lane.a);
                rewrite(&mut lane.b);
            }
        }
        Instr::Ret {
            src: src @ RetSrc::Var(Addr::Const(_)),
            n: 1,
        } => {
            // A scalar `return v` reading a var that mirrors a register can return the
            // register directly. `RetSrc` has no constant form, so constant facts stay.
            let RetSrc::Var(Addr::Const(slot)) = src else {
                unreachable!("matched above");
            };
            if let Some(VarValue::Reg(reg)) = known.get(slot) {
                *src = RetSrc::Reg(*reg);
                rewritten += 1;
            }
        }
        _ => {}
    }
    rewritten
}

/// Removes exact var stores whose values cannot reach a later read. Stores within a
/// possibly-shared region are conditional: when live they do not kill the previous value,
/// because the VM's merge still needs that value for the untaken arm.
pub(super) fn eliminate_dead_var_stores(instrs: Vec<Instr>) -> Result<(Vec<Instr>, usize)> {
    let cfg = ControlFlowGraph::build(&instrs)?;
    if cfg.blocks.is_empty() {
        return Ok((instrs, 0));
    }
    let shared = shared_region_mask(&instrs);
    let live_in = solve_var_liveness(&instrs, &cfg, &shared);
    let mut keep = vec![true; instrs.len()];
    let mut live = LiveVars::default();

    for block in &cfg.blocks {
        live.clear();
        for successor in &block.successors {
            if let Successor::Block(next) = successor {
                live.union_with(&live_in[*next]);
            }
        }
        for ip in (block.start..block.end).rev() {
            if is_dead_exact_store(&instrs[ip], &live) {
                keep[ip] = false;
                continue;
            }
            transfer_live(&instrs[ip], shared[ip], &mut live);
        }
    }

    let removed = keep.iter().filter(|keep| !**keep).count();
    if removed == 0 {
        Ok((instrs, 0))
    } else {
        Ok((compact(instrs, &keep)?, removed))
    }
}

fn solve_var_liveness(instrs: &[Instr], cfg: &ControlFlowGraph, shared: &[bool]) -> Vec<LiveVars> {
    let mut predecessors = vec![Vec::new(); cfg.blocks.len()];
    for (block_id, block) in cfg.blocks.iter().enumerate() {
        for successor in &block.successors {
            if let Successor::Block(next) = successor
                && !predecessors[*next].contains(&block_id)
            {
                predecessors[*next].push(block_id);
            }
        }
    }

    let mut live_in = vec![LiveVars::default(); cfg.blocks.len()];
    let mut pending = (0..cfg.blocks.len()).rev().collect::<Vec<_>>();
    let mut queued = vec![true; cfg.blocks.len()];
    let mut live = LiveVars::default();
    while let Some(block_id) = pending.pop() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        live.clear();
        for successor in &block.successors {
            if let Successor::Block(next) = successor {
                live.union_with(&live_in[*next]);
            }
        }
        for ip in (block.start..block.end).rev() {
            transfer_live(&instrs[ip], shared[ip], &mut live);
        }
        if live != live_in[block_id] {
            live_in[block_id] = live.clone();
            for predecessor in &predecessors[block_id] {
                if !queued[*predecessor] {
                    queued[*predecessor] = true;
                    pending.push(*predecessor);
                }
            }
        }
    }
    live_in
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LiveVars {
    Exact(HashSet<u32>),
    All,
}

impl Default for LiveVars {
    fn default() -> Self {
        Self::Exact(HashSet::new())
    }
}

impl LiveVars {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn union_with(&mut self, other: &Self) {
        match (&mut *self, other) {
            (Self::All, _) => {}
            (_, Self::All) => *self = Self::All,
            (Self::Exact(dst), Self::Exact(src)) => dst.extend(src),
        }
    }

    fn add(&mut self, addr: Addr, n: u32) {
        let Self::Exact(slots) = self else {
            return;
        };
        let Addr::Const(start) = addr else {
            *self = Self::All;
            return;
        };
        for k in 0..n {
            let Some(slot) = start.checked_add(k) else {
                *self = Self::All;
                return;
            };
            slots.insert(slot);
        }
    }

    fn kill(&mut self, start: u32, n: u32) {
        let Self::Exact(slots) = self else {
            // Conservatively retain `All`; representing all-except-a-range would add
            // complexity for the uncommon dynamic-read case.
            return;
        };
        for k in 0..n {
            if let Some(slot) = start.checked_add(k) {
                slots.remove(&slot);
            }
        }
    }

    fn range_is_live(&self, start: u32, n: u32) -> bool {
        match self {
            Self::All => true,
            Self::Exact(slots) => (0..n).any(|k| {
                start
                    .checked_add(k)
                    .is_some_and(|slot| slots.contains(&slot))
            }),
        }
    }
}

fn is_dead_exact_store(instr: &Instr, live: &LiveVars) -> bool {
    match instr {
        Instr::Mov {
            dst: Dst::Var(Addr::Const(slot)),
            ..
        } => !live.range_is_live(*slot, 1),
        Instr::StoreN {
            dst: Dst::Var(Addr::Const(slot)),
            n,
            ..
        } => !live.range_is_live(*slot, *n),
        _ => false,
    }
}

fn transfer_live(instr: &Instr, conditional_store: bool, live: &mut LiveVars) {
    match instr {
        Instr::Mov {
            dst: Dst::Var(Addr::Const(slot)),
            src,
        } => {
            if !live.range_is_live(*slot, 1) {
                return;
            }
            if !conditional_store {
                live.kill(*slot, 1);
            }
            add_src(live, *src, 1);
            return;
        }
        Instr::StoreN {
            dst: Dst::Var(Addr::Const(slot)),
            n,
            ..
        } => {
            if live.range_is_live(*slot, *n) && !conditional_store {
                live.kill(*slot, *n);
            }
            return;
        }
        Instr::BinBatch { lanes, .. } if !conditional_store => {
            for lane in lanes {
                if let Some(Dst::Var(Addr::Const(slot))) = lane.store {
                    live.kill(slot, 1);
                }
            }
        }
        _ => {}
    }
    add_var_reads(live, instr);
}

fn add_var_reads(live: &mut LiveVars, instr: &Instr) {
    match instr {
        Instr::Bin { a, b, .. } => {
            add_src(live, *a, 1);
            add_src(live, *b, 1);
        }
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes {
                add_src(live, lane.a, 1);
                add_src(live, lane.b, 1);
            }
        }
        Instr::Neg { a, .. } => add_src(live, *a, 1),
        Instr::EqN { a, b, n, .. } | Instr::BinN { a, b, n, .. } => {
            add_src(live, *a, *n);
            add_src(live, *b, *n);
        }
        Instr::Mov { src, .. } => add_src(live, *src, 1),
        Instr::LoadN { src, n, .. } => add_src(live, *src, *n),
        Instr::ToIndex { src, .. }
        | Instr::JmpIfZero { cond: src, .. }
        | Instr::SharedIf { cond: src, .. }
        | Instr::SharedIfBit { cond: src, .. }
        | Instr::Assert { cond: src, .. }
        | Instr::Log { src } => add_src(live, *src, 1),
        Instr::Ret {
            src: RetSrc::Var(addr),
            n,
        } => live.add(*addr, *n),
        _ => {}
    }
}

fn add_src(live: &mut LiveVars, src: Src, n: u32) {
    if let Src::Var(addr) = src {
        live.add(addr, n);
    }
}

fn shared_region_mask(instrs: &[Instr]) -> Vec<bool> {
    let mut depth = 0usize;
    instrs
        .iter()
        .map(|instr| {
            let inside = depth != 0;
            match instr {
                Instr::SharedIf { .. } | Instr::SharedIfBit { .. } => depth += 1,
                Instr::SharedEnd => depth = depth.saturating_sub(1),
                _ => {}
            }
            inside
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use circom_mpc_vm2::isa::{BinOp, FnId};

    #[test]
    fn forwards_constant_var_across_unconditional_block() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(3)),
                src: Src::Const(7),
            },
            Instr::Jmp { target: 2 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Var(Addr::Const(3)),
            },
            Instr::Return,
        ];
        let (out, forwarded) = forward_var_values(instrs).unwrap();
        assert_eq!(forwarded, 1);
        assert_eq!(
            out[2],
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(7),
            }
        );
    }

    #[test]
    fn forwards_register_value_stored_to_var() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(0)),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(3)),
                src: Src::Reg(0),
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Var(Addr::Const(3)),
            },
            Instr::Return,
        ];
        let (out, forwarded) = forward_var_values(instrs).unwrap();
        assert_eq!(forwarded, 1);
        assert_eq!(
            out[2],
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Reg(0),
            }
        );
    }

    #[test]
    fn same_instruction_register_redefinition_still_forwards() {
        // The consuming Bin redefines r0 itself, but the VM reads operands before
        // writing the destination, so the pre-instruction fact applies to its uses.
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(0)),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(3)),
                src: Src::Reg(0),
            },
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Var(Addr::Const(3)),
                b: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Var(Addr::Const(3)),
            },
            Instr::Return,
        ];
        let (out, forwarded) = forward_var_values(instrs).unwrap();
        // The Bin's operand forwards; the later read must NOT (r0 was redefined).
        assert_eq!(forwarded, 1);
        assert!(matches!(out[2], Instr::Bin { a: Src::Reg(0), .. }));
        assert_eq!(
            out[3],
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Var(Addr::Const(3)),
            }
        );
    }

    #[test]
    fn storen_records_per_element_register_facts() {
        let instrs = vec![
            Instr::LoadN {
                dst: 0,
                src: Src::Signal(Addr::Const(0)),
                n: 3,
            },
            Instr::StoreN {
                dst: Dst::Var(Addr::Const(10)),
                src: 0,
                n: 3,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(5)),
                src: Src::Var(Addr::Const(11)),
            },
            Instr::Return,
        ];
        let (out, forwarded) = forward_var_values(instrs).unwrap();
        assert_eq!(forwarded, 1);
        assert_eq!(
            out[2],
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(5)),
                src: Src::Reg(1),
            }
        );
    }

    #[test]
    fn scalar_var_return_forwards_to_register() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Reg(2),
                src: Src::Signal(Addr::Const(0)),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Reg(2),
            },
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(0)),
                n: 1,
            },
        ];
        let (out, forwarded) = forward_var_values(instrs).unwrap();
        assert_eq!(forwarded, 1);
        assert_eq!(
            out[2],
            Instr::Ret {
                src: RetSrc::Reg(2),
                n: 1,
            }
        );
    }

    #[test]
    fn call_invalidates_forward_facts() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(3)),
                src: Src::Const(7),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 0,
                ret: 0,
                ret_n: 0,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Var(Addr::Const(3)),
            },
            Instr::Return,
        ];
        let (out, forwarded) = forward_var_values(instrs.clone()).unwrap();
        assert_eq!(forwarded, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn shared_region_does_not_forward_buffered_or_preexisting_writes() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::SharedIfBit {
                cond: Src::Signal(Addr::Const(0)),
                else_target: 4,
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(1),
            },
            Instr::SharedElse { end_target: 6 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Var(Addr::Const(0)),
            },
            Instr::Jmp { target: 6 },
            Instr::SharedEnd,
            Instr::Return,
        ];
        let (out, forwarded) = forward_var_values(instrs.clone()).unwrap();
        assert_eq!(forwarded, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn eliminates_overwritten_and_terminal_var_stores() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(1),
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Var(Addr::Const(0)),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(1)),
                src: Src::Const(2),
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_var_stores(instrs).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(out.len(), 3);
        assert!(matches!(
            out[0],
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(1)
            }
        ));
    }

    #[test]
    fn conditional_store_does_not_kill_value_needed_by_untaken_arm() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::SharedIfBit {
                cond: Src::Signal(Addr::Const(0)),
                else_target: 4,
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(1),
            },
            Instr::SharedElse { end_target: 5 },
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Const(0),
                b: Src::Const(0),
            },
            Instr::SharedEnd,
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(1)),
                src: Src::Var(Addr::Const(0)),
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_var_stores(instrs).unwrap();
        assert_eq!(removed, 0);
        assert!(matches!(
            out[0],
            Instr::Mov {
                dst: Dst::Var(_),
                ..
            }
        ));
        assert!(matches!(
            out[2],
            Instr::Mov {
                dst: Dst::Var(_),
                ..
            }
        ));
    }

    #[test]
    fn dynamic_read_keeps_all_earlier_exact_stores() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(9)),
                src: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Var(Addr::Dynamic(0)),
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_var_stores(instrs.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, instrs);
    }
}
