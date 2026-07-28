//! Integer-register constant propagation into addressing modes.
//!
//! Unrolled loop iterations (and constant-folded index arithmetic in general) leave
//! chains like `Bin Add r, Const, Const` → `ToIndex ir, Reg(r)` → `Var(Dynamic(ir))`:
//! SCCP folds the field side to a constant, but the *address* stays dynamic and the
//! `ToIndex` conversion stays in the bytecode. This pass runs the same style of
//! forward dataflow over the integer registers: `ISet`, integer arithmetic over known
//! registers, and `ToIndex` of an interned constant all yield known values, and every
//! addressing-mode use of a known register is rewritten to its resolved form —
//! `Addr::Dynamic(ir)` and `Addr::Affine {ir, ..}` become `Addr::Const`, integer
//! operands become immediates, and a known trip counter folds `IJmpIfZero`. The now
//! unused defining instructions are removed by the existing dead-code pass, and
//! `Var(Const)` addresses unlock the memory pass's exact-slot facts.
//!
//! Values are tracked in `u64` (folds reject anything that doesn't fit the target
//! encoding), and a `ToIndex` whose constant doesn't fit an index is left untouched so
//! its runtime error behavior is preserved.

use super::{ControlFlowGraph, Successor, compact};
use ark_ff::PrimeField;
use circom_mpc_vm2::isa::{Addr, Dst, ISrc, Instr, RetSrc, Src};
use eyre::Result;
use std::collections::{HashMap, VecDeque};

type KnownIRegs = HashMap<u8, u64>;

/// Propagates known integer-register values into addressing modes and integer
/// operands. Returns the rewritten body and the number of rewrites.
pub(super) fn propagate_index_constants<F: PrimeField>(
    mut instrs: Vec<Instr>,
    constants: &[F],
) -> Result<(Vec<Instr>, usize)> {
    // Cheap pre-check: without an integer definition there is nothing to propagate.
    if !instrs.iter().any(|instr| {
        matches!(
            instr,
            Instr::ISet { .. }
                | Instr::IAdd { .. }
                | Instr::IMul { .. }
                | Instr::ISub { .. }
                | Instr::ToIndex { .. }
        )
    }) {
        return Ok((instrs, 0));
    }

    let cfg = ControlFlowGraph::build(&instrs)?;
    if cfg.blocks.is_empty() {
        return Ok((instrs, 0));
    }
    let inputs = known_ireg_inputs(&instrs, &cfg, constants);
    let mut rewritten = 0usize;
    let mut keep = vec![true; instrs.len()];

    for (block_id, block) in cfg.blocks.iter().enumerate() {
        let mut known = inputs[block_id].clone();
        for ip in block.start..block.end {
            rewritten += rewrite_instr(&mut instrs[ip], &known);
            // A branch on a known counter resolves statically: zero jumps, non-zero
            // falls through (the instruction disappears; compaction remaps targets).
            if let Instr::IJmpIfZero { reg, target } = instrs[ip]
                && let Some(value) = known.get(&reg)
            {
                if *value == 0 {
                    instrs[ip] = Instr::Jmp { target };
                } else {
                    keep[ip] = false;
                }
                rewritten += 1;
            }
            transfer(&instrs[ip], &mut known, constants);
        }
    }

    if keep.iter().all(|keep| *keep) {
        Ok((instrs, rewritten))
    } else {
        Ok((compact(instrs, &keep)?, rewritten))
    }
}

/// Standard worklist dataflow with intersection joins (see `constant_inputs` for the
/// scheme): a fact survives a join only when every incoming path agrees on the value.
fn known_ireg_inputs<F: PrimeField>(
    instrs: &[Instr],
    cfg: &ControlFlowGraph,
    constants: &[F],
) -> Vec<KnownIRegs> {
    let mut inputs = vec![None; cfg.blocks.len()];
    inputs[0] = Some(KnownIRegs::new());
    let mut pending = VecDeque::from([0usize]);
    let mut queued = vec![false; cfg.blocks.len()];
    queued[0] = true;

    while let Some(block_id) = pending.pop_front() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        let mut known = inputs[block_id].clone().unwrap_or_default();
        for instr in &instrs[block.start..block.end] {
            transfer(instr, &mut known, constants);
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

    inputs.into_iter().map(Option::unwrap_or_default).collect()
}

fn transfer<F: PrimeField>(instr: &Instr, known: &mut KnownIRegs, constants: &[F]) {
    match instr {
        Instr::ISet { dst, val } => {
            known.insert(*dst, u64::from(*val));
        }
        Instr::IAdd { dst, a, b } => {
            let fact = isrc_value(*a, known)
                .zip(isrc_value(*b, known))
                .and_then(|(a, b)| a.checked_add(b));
            set_known(known, *dst, fact);
        }
        Instr::IMul { dst, a, b } => {
            let fact = isrc_value(*a, known)
                .zip(isrc_value(*b, known))
                .and_then(|(a, b)| a.checked_mul(b));
            set_known(known, *dst, fact);
        }
        Instr::ISub { dst, a, b } => {
            // Mirrors the VM's saturating semantics exactly.
            let fact = isrc_value(*a, known)
                .zip(isrc_value(*b, known))
                .map(|(a, b)| a.saturating_sub(b));
            set_known(known, *dst, fact);
        }
        Instr::ToIndex { dst, src } => {
            // Only a constant that is a valid index folds; anything else (including a
            // constant too large for an index, whose runtime error must be preserved)
            // leaves the register unknown.
            let fact = match src {
                Src::Const(id) => constants
                    .get(*id as usize)
                    .and_then(|value| field_to_index(*value)),
                _ => None,
            };
            set_known(known, *dst, fact);
        }
        _ => {}
    }
}

/// The canonical limb value of `value` when it fits an index, mirroring the plain
/// driver's `to_usize`.
fn field_to_index<F: PrimeField>(value: F) -> Option<u64> {
    let repr = value.into_bigint();
    let limbs = repr.as_ref();
    if limbs[1..].iter().any(|&limb| limb != 0) {
        return None;
    }
    Some(limbs[0])
}

fn isrc_value(src: ISrc, known: &KnownIRegs) -> Option<u64> {
    match src {
        ISrc::Const(value) => Some(u64::from(value)),
        ISrc::Reg(reg) => known.get(&reg).copied(),
    }
}

fn set_known(known: &mut KnownIRegs, reg: u8, value: Option<u64>) {
    match value {
        Some(value) => {
            known.insert(reg, value);
        }
        None => {
            known.remove(&reg);
        }
    }
}

fn rewrite_addr(addr: &mut Addr, known: &KnownIRegs, rewritten: &mut usize) {
    if let Some(resolved) = resolve_addr(*addr, known) {
        *addr = resolved;
        *rewritten += 1;
    }
}

fn rewrite_src(src: &mut Src, known: &KnownIRegs, rewritten: &mut usize) {
    match src {
        Src::Var(a) | Src::Signal(a) => rewrite_addr(a, known, rewritten),
        Src::Reg(_) | Src::Const(_) => {}
    }
}

fn rewrite_dst(dst: &mut Dst, known: &KnownIRegs, rewritten: &mut usize) {
    match dst {
        Dst::Var(a) | Dst::Signal(a) => rewrite_addr(a, known, rewritten),
        Dst::Reg(_) => {}
    }
}

/// Rewrites every use of a known integer register in `instr` to its resolved constant
/// form, counting the rewrites.
fn rewrite_instr(instr: &mut Instr, known: &KnownIRegs) -> usize {
    let mut rewritten = 0usize;
    let n = &mut rewritten;
    match instr {
        Instr::Bin { a, b, .. } => {
            rewrite_src(a, known, n);
            rewrite_src(b, known, n);
        }
        Instr::Neg { a, .. } => rewrite_src(a, known, n),
        Instr::EqN { a, b, .. } | Instr::BinN { a, b, .. } => {
            rewrite_src(a, known, n);
            rewrite_src(b, known, n);
        }
        Instr::Mov { dst, src } => {
            rewrite_dst(dst, known, n);
            rewrite_src(src, known, n);
        }
        Instr::LoadN { src, .. } => rewrite_src(src, known, n),
        Instr::StoreN { dst, .. } => rewrite_dst(dst, known, n),
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes.iter_mut() {
                rewrite_src(&mut lane.a, known, n);
                rewrite_src(&mut lane.b, known, n);
                if let Some(store) = &mut lane.store {
                    rewrite_dst(store, known, n);
                }
            }
        }
        Instr::ToIndex { src, .. }
        | Instr::JmpIfZero { cond: src, .. }
        | Instr::SharedIf { cond: src, .. }
        | Instr::SharedIfBit { cond: src, .. }
        | Instr::Assert { cond: src, .. }
        | Instr::Log { src } => rewrite_src(src, known, n),
        Instr::InputSub { addr, .. } | Instr::OutputSub { addr, .. } => {
            rewrite_addr(addr, known, n)
        }
        Instr::Ret {
            src: RetSrc::Var(addr),
            ..
        } => rewrite_addr(addr, known, n),
        _ => {}
    }

    // Integer operands of integer arithmetic and component indices become immediates.
    let mut isrc = |src: &mut ISrc| {
        if let ISrc::Reg(reg) = src
            && let Some(value) = known.get(reg)
            && let Ok(value) = u32::try_from(*value)
        {
            *src = ISrc::Const(value);
            rewritten += 1;
        }
    };
    match instr {
        Instr::IAdd { a, b, .. } | Instr::IMul { a, b, .. } | Instr::ISub { a, b, .. } => {
            isrc(a);
            isrc(b);
        }
        Instr::InputSub { cmp, .. } | Instr::OutputSub { cmp, .. } => isrc(cmp),
        _ => {}
    }

    rewritten
}

/// Resolves an [`Addr`] against known integer registers, when everything needed is
/// known and the result fits the encoding.
fn resolve_addr(addr: Addr, known: &KnownIRegs) -> Option<Addr> {
    match addr {
        Addr::Const(_) => None,
        Addr::Affine {
            ireg,
            stride,
            offset,
        } => {
            let value = known.get(&ireg)?;
            let resolved = value
                .checked_mul(u64::from(stride))?
                .checked_add(u64::from(offset))?;
            u32::try_from(resolved).ok().map(Addr::Const)
        }
        Addr::Dynamic(ireg) => {
            let value = known.get(&ireg)?;
            u32::try_from(*value).ok().map(Addr::Const)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use circom_mpc_vm2::isa::BinOp;

    fn run(instrs: Vec<Instr>, constants: Vec<Fr>) -> (Vec<Instr>, usize) {
        propagate_index_constants(instrs, &constants).unwrap()
    }

    #[test]
    fn folds_toindex_of_constant_into_static_address() {
        let (out, rewritten) = run(
            vec![
                Instr::ToIndex {
                    dst: 0,
                    src: Src::Const(0),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Dynamic(0)),
                    src: Src::Const(1),
                },
                Instr::Return,
            ],
            vec![Fr::from(7u64), Fr::from(3u64)],
        );
        assert!(rewritten > 0);
        assert_eq!(
            out[1],
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(7)),
                src: Src::Const(1),
            }
        );
    }

    #[test]
    fn folds_integer_arithmetic_chains_and_affine_addresses() {
        let (out, _) = run(
            vec![
                Instr::ISet { dst: 0, val: 2 },
                Instr::IMul {
                    dst: 1,
                    a: ISrc::Reg(0),
                    b: ISrc::Const(5),
                },
                Instr::IAdd {
                    dst: 1,
                    a: ISrc::Reg(1),
                    b: ISrc::Const(3),
                },
                Instr::Mov {
                    dst: Dst::Var(Addr::Affine {
                        ireg: 1,
                        stride: 2,
                        offset: 1,
                    }),
                    src: Src::Const(0),
                },
                Instr::Return,
            ],
            vec![Fr::from(0u64)],
        );
        assert_eq!(
            out[3],
            Instr::Mov {
                dst: Dst::Var(Addr::Const(27)), // (2*5+3)*2 + 1
                src: Src::Const(0),
            }
        );
    }

    #[test]
    fn loop_backedge_join_keeps_counter_unknown() {
        // ISet ctr; head: IJmpIfZero; body writes through Dynamic(ctr); ISub; Jmp head.
        let instrs = vec![
            Instr::ISet { dst: 0, val: 3 },
            Instr::IJmpIfZero { reg: 0, target: 5 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Dynamic(0)),
                src: Src::Const(0),
            },
            Instr::ISub {
                dst: 0,
                a: ISrc::Reg(0),
                b: ISrc::Const(1),
            },
            Instr::Jmp { target: 1 },
            Instr::Return,
        ];
        let (out, _) = run(instrs.clone(), vec![Fr::from(0u64)]);
        assert_eq!(out, instrs, "a rolled loop's counter must stay dynamic");
    }

    #[test]
    fn known_zero_counter_folds_ijmpifzero_to_jmp() {
        let (out, _) = run(
            vec![
                Instr::ISet { dst: 0, val: 0 },
                Instr::IJmpIfZero { reg: 0, target: 3 },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(0)),
                    src: Src::Const(0),
                },
                Instr::Return,
            ],
            vec![Fr::from(0u64)],
        );
        assert!(matches!(out[1], Instr::Jmp { target: 3 }));
    }

    #[test]
    fn oversized_toindex_constant_is_left_untouched() {
        let (out, rewritten) = run(
            vec![
                Instr::ToIndex {
                    dst: 0,
                    src: Src::Const(0),
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Dynamic(0)),
                    src: Src::Const(0),
                },
                Instr::Return,
            ],
            vec![-Fr::from(1u64)],
        );
        assert_eq!(rewritten, 0);
        assert!(matches!(
            out[1],
            Instr::Mov {
                dst: Dst::Signal(Addr::Dynamic(0)),
                ..
            }
        ));
    }

    #[test]
    fn integer_operands_become_immediates() {
        let (out, _) = run(
            vec![
                Instr::ISet { dst: 0, val: 4 },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Signal(Addr::Const(9)),
                },
                Instr::ToIndex {
                    dst: 1,
                    src: Src::Reg(0),
                },
                Instr::IAdd {
                    dst: 1,
                    a: ISrc::Reg(1),
                    b: ISrc::Reg(0),
                },
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 1,
                    a: Src::Var(Addr::Dynamic(1)),
                    b: Src::Const(0),
                },
                Instr::Return,
            ],
            vec![Fr::from(0u64)],
        );
        // ir0 is known (4); ir1 is a runtime index — the IAdd's second operand becomes
        // an immediate while the dynamic address correctly stays dynamic.
        assert!(matches!(
            out[3],
            Instr::IAdd {
                b: ISrc::Const(4),
                ..
            }
        ));
        assert!(matches!(
            out[4],
            Instr::Bin {
                a: Src::Var(Addr::Dynamic(1)),
                ..
            }
        ));
    }
}
