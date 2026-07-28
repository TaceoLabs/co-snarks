//! CFG-wide "is a bit" data-flow upgrading [`Instr::SharedIf`] to [`Instr::SharedIfBit`].
//!
//! Lowering only emits `SharedIfBit` when the branch condition's top-level IR node is
//! boolean by definition (see [`crate::codegen::expr::is_known_bit`]). A bit that reaches
//! the branch through a register — a comparison result stored to a var and forwarded back
//! by the memory pass, a boolean combined across blocks, a spliced inline callee's return
//! register — falls back to `SharedIf`, which costs the VM a full zero/non-zero
//! normalization protocol when the condition turns out to be shared at runtime. This pass
//! recovers those: a forward data-flow (same skeleton as SCCP) proves which field
//! registers hold a value in `{0, 1}`, and every `SharedIf` whose condition register
//! carries that proof becomes `SharedIfBit`.
//!
//! Facts are deliberately register-only: var/signal slots are mutable memory whose
//! forwarding rules live in the memory pass — when that pass can prove a load equals a
//! stored register it rewrites the condition to that register, and the fact then applies
//! here. A false negative merely keeps `SharedIf`'s normalization; a false positive would
//! feed a non-bit into the VM's boolean predication primitives, so every rule below only
//! accepts operations whose result is a bit by construction.

use super::{ControlFlowGraph, Successor, constant, is_bit};
use ark_ff::PrimeField;
use circom_mpc_vm2::isa::{BinOp, Dst, Instr, Src};
use eyre::Result;
use std::collections::{HashSet, VecDeque};

type BitRegs = HashSet<u16>;

/// Rewrites every [`Instr::SharedIf`] whose condition register provably holds a bit to
/// [`Instr::SharedIfBit`], returning the number of upgraded branches.
pub(super) fn upgrade_shared_if_bits<F: PrimeField>(
    mut instrs: Vec<Instr>,
    constants: &[F],
) -> Result<(Vec<Instr>, usize)> {
    // The pass only ever rewrites `SharedIf`; skip CFG construction for bodies without
    // one (branchless bodies are the overwhelmingly common case).
    if !instrs
        .iter()
        .any(|instr| matches!(instr, Instr::SharedIf { .. }))
    {
        return Ok((instrs, 0));
    }
    let cfg = ControlFlowGraph::build(&instrs)?;
    if cfg.blocks.is_empty() {
        return Ok((instrs, 0));
    }
    let inputs = bit_inputs(&instrs, &cfg, constants);
    let mut upgraded = 0usize;

    for (block_id, block) in cfg.blocks.iter().enumerate() {
        let mut bits = inputs[block_id].clone();
        for instr in &mut instrs[block.start..block.end] {
            if let Instr::SharedIf { cond, else_target } = *instr
                && matches!(cond, Src::Reg(reg) if bits.contains(&reg))
            {
                *instr = Instr::SharedIfBit { cond, else_target };
                upgraded += 1;
            }
            transfer(instr, &mut bits, constants);
        }
    }

    Ok((instrs, upgraded))
}

/// Sparse forward data-flow computing the bit-register set at every block entry. As with
/// SCCP, the first incoming edge seeds a block and later edges intersect facts, so a
/// register survives a join only when every path proves it a bit.
fn bit_inputs<F: PrimeField>(
    instrs: &[Instr],
    cfg: &ControlFlowGraph,
    constants: &[F],
) -> Vec<BitRegs> {
    let mut inputs = vec![None; cfg.blocks.len()];
    inputs[0] = Some(BitRegs::new());
    let mut pending = VecDeque::from([0usize]);
    let mut queued = vec![false; cfg.blocks.len()];
    queued[0] = true;

    while let Some(block_id) = pending.pop_front() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        let mut bits = inputs[block_id].clone().unwrap_or_default();
        for instr in &instrs[block.start..block.end] {
            transfer(instr, &mut bits, constants);
        }
        for successor in &block.successors {
            let Successor::Block(next) = successor else {
                continue;
            };
            let changed = if let Some(input) = &mut inputs[*next] {
                let old_len = input.len();
                input.retain(|reg| bits.contains(reg));
                input.len() != old_len
            } else {
                inputs[*next] = Some(bits.clone());
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

/// Whether reading `src` under the current facts is guaranteed to produce a bit. Var and
/// signal slots are never facts here (see the module docs).
fn src_is_bit<F: PrimeField>(src: Src, bits: &BitRegs, constants: &[F]) -> bool {
    match src {
        Src::Reg(reg) => bits.contains(&reg),
        Src::Const(_) => constant(src, constants).is_some_and(is_bit),
        Src::Var(_) | Src::Signal(_) => false,
    }
}

/// Forward transfer for one instruction: definitions whose result is a bit by
/// construction add their destination register, every other definition kills it.
fn transfer<F: PrimeField>(instr: &Instr, bits: &mut BitRegs, constants: &[F]) {
    match instr {
        Instr::Bin { op, dst, a, b } => {
            let bit = match op {
                // Comparison results are bits regardless of their operands.
                BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge | BinOp::Eq | BinOp::Neq => true,
                // The boolean connectives assume bit inputs (the Rep3 driver computes
                // e.g. `a * b` for `BoolAnd`), so their output is only a bit when both
                // inputs are.
                BinOp::BoolAnd | BinOp::BoolOr => {
                    src_is_bit(*a, bits, constants) && src_is_bit(*b, bits, constants)
                }
                _ => false,
            };
            set(bits, *dst, bit);
        }
        Instr::EqN { dst, .. } => {
            bits.insert(*dst);
        }
        Instr::Mov {
            dst: Dst::Reg(dst),
            src,
        } => {
            let bit = src_is_bit(*src, bits, constants);
            set(bits, *dst, bit);
        }
        Instr::Neg { dst, .. } => {
            bits.remove(dst);
        }
        Instr::BinBatch { op, lanes } => {
            // The VM snapshots every lane input before writing any destination.
            let before = bits.clone();
            for lane in lanes {
                let bit = match op {
                    BinOp::Eq | BinOp::Neq => true,
                    BinOp::BoolAnd | BinOp::BoolOr => {
                        src_is_bit(lane.a, &before, constants)
                            && src_is_bit(lane.b, &before, constants)
                    }
                    _ => false,
                };
                set(bits, lane.dst, bit);
                if let Some(Dst::Reg(dst)) = lane.store {
                    set(bits, dst, bit);
                }
            }
        }
        Instr::BinN { op, dst, n, .. } => {
            let bit = matches!(
                op,
                BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge | BinOp::Eq | BinOp::Neq
            );
            for k in 0..*n {
                set_u32(bits, u32::from(*dst) + k, bit);
            }
        }
        Instr::StoreN {
            dst: Dst::Reg(dst),
            src,
            n,
        } => {
            let facts = (0..*n)
                .map(|k| bits.contains(&super::u16_at(*src, k)))
                .collect::<Vec<_>>();
            for (k, bit) in facts.into_iter().enumerate() {
                set_u32(bits, u32::from(*dst) + k as u32, bit);
            }
        }
        Instr::LoadN { dst, n, .. } | Instr::OutputSub { dst, n, .. } => {
            for k in 0..*n {
                set_u32(bits, u32::from(*dst) + k, false);
            }
        }
        Instr::CallFn { ret, ret_n, .. } => {
            for k in 0..*ret_n {
                set_u32(bits, u32::from(*ret) + k, false);
            }
        }
        _ => {}
    }
}

fn set(bits: &mut BitRegs, reg: u16, bit: bool) {
    if bit {
        bits.insert(reg);
    } else {
        bits.remove(&reg);
    }
}

fn set_u32(bits: &mut BitRegs, reg: u32, bit: bool) {
    if let Ok(reg) = u16::try_from(reg) {
        set(bits, reg, bit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use circom_mpc_vm2::isa::Addr;

    fn upgrade(instrs: Vec<Instr>, constants: Vec<Fr>) -> (Vec<Instr>, usize) {
        upgrade_shared_if_bits(instrs, &constants).unwrap()
    }

    #[test]
    fn comparison_result_condition_upgrades() {
        let (out, upgraded) = upgrade(
            vec![
                Instr::Bin {
                    op: BinOp::Lt,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::SharedIf {
                    cond: Src::Reg(0),
                    else_target: 3,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Const(0),
                },
                Instr::SharedEnd,
            ],
            vec![Fr::from(1u64)],
        );
        assert_eq!(upgraded, 1);
        assert!(matches!(out[1], Instr::SharedIfBit { .. }));
    }

    #[test]
    fn arithmetic_result_condition_stays_shared_if() {
        let (out, upgraded) = upgrade(
            vec![
                Instr::Bin {
                    op: BinOp::Add,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::SharedIf {
                    cond: Src::Reg(0),
                    else_target: 3,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Const(0),
                },
                Instr::SharedEnd,
            ],
            vec![Fr::from(1u64)],
        );
        assert_eq!(upgraded, 0);
        assert!(matches!(out[1], Instr::SharedIf { .. }));
    }

    #[test]
    fn bool_and_needs_both_operands_proven() {
        let (out, upgraded) = upgrade(
            vec![
                Instr::Bin {
                    op: BinOp::Lt,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                // Reg(1) is never defined in this body, so it is not provably a bit.
                Instr::Bin {
                    op: BinOp::BoolAnd,
                    dst: 2,
                    a: Src::Reg(0),
                    b: Src::Reg(1),
                },
                Instr::SharedIf {
                    cond: Src::Reg(2),
                    else_target: 4,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Const(0),
                },
                Instr::SharedEnd,
                Instr::Bin {
                    op: BinOp::Gt,
                    dst: 1,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::Bin {
                    op: BinOp::BoolAnd,
                    dst: 3,
                    a: Src::Reg(0),
                    b: Src::Reg(1),
                },
                Instr::SharedIf {
                    cond: Src::Reg(3),
                    else_target: 9,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(2)),
                    src: Src::Const(0),
                },
                Instr::SharedEnd,
            ],
            vec![Fr::from(1u64)],
        );
        assert_eq!(upgraded, 1, "only the second BoolAnd has two proven bits");
        assert!(matches!(out[2], Instr::SharedIf { .. }));
        assert!(matches!(out[7], Instr::SharedIfBit { .. }));
    }

    #[test]
    fn fact_survives_join_only_when_every_path_proves_it() {
        // One path redefines r0 with `taken_path_op` before both paths meet at the
        // SharedIf; the fact must survive the join only when that redefinition is
        // itself a bit.
        let mk = |taken_path_op: BinOp| {
            vec![
                Instr::Bin {
                    op: BinOp::Lt,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::JmpIfZero {
                    cond: Src::Signal(Addr::Const(2)),
                    target: 3,
                },
                Instr::Jmp { target: 4 },
                Instr::Bin {
                    op: taken_path_op,
                    dst: 0,
                    a: Src::Signal(Addr::Const(0)),
                    b: Src::Signal(Addr::Const(1)),
                },
                Instr::SharedIf {
                    cond: Src::Reg(0),
                    else_target: 6,
                },
                Instr::Mov {
                    dst: Dst::Signal(Addr::Const(3)),
                    src: Src::Const(0),
                },
                Instr::SharedEnd,
            ]
        };
        let (out, upgraded) = upgrade(mk(BinOp::Eq), vec![Fr::from(1u64)]);
        assert_eq!(upgraded, 1);
        assert!(matches!(out[4], Instr::SharedIfBit { .. }));

        let (out, upgraded) = upgrade(mk(BinOp::Add), vec![Fr::from(1u64)]);
        assert_eq!(upgraded, 0);
        assert!(matches!(out[4], Instr::SharedIf { .. }));
    }
}
