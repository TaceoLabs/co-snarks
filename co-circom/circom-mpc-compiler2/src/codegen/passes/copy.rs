//! CFG-wide field-register copy propagation.
//!
//! Facts are deliberately limited to register aliases (`r_dst == r_src`). Constants are
//! handled by SCCP, while vars/signals are mutable and require the separate memory pass.
//! Every fact points directly at its canonical source register; redefining that source
//! invalidates all aliases which captured its old value.

use super::{ControlFlowGraph, Successor, compact};
use circom_mpc_vm2::isa::{Dst, Instr, RetSrc, Src};
use eyre::Result;
use std::collections::{HashMap, VecDeque};

type Copies = HashMap<u16, u16>;

/// Rewrites register operands to their canonical copies and removes register `Mov`s
/// which assign a value the destination already holds.
pub(super) fn propagate_register_copies(
    mut instrs: Vec<Instr>,
) -> Result<(Vec<Instr>, usize, usize)> {
    // Direct lowering rarely needs register-to-register moves. Avoid even constructing
    // a CFG for the overwhelmingly common no-candidate body.
    if !instrs.iter().any(|instr| {
        matches!(
            instr,
            Instr::Mov {
                dst: Dst::Reg(_),
                src: Src::Reg(_)
            }
        )
    }) {
        return Ok((instrs, 0, 0));
    }
    let cfg = ControlFlowGraph::build(&instrs)?;
    if cfg.blocks.is_empty() {
        return Ok((instrs, 0, 0));
    }
    let inputs = copy_inputs(&instrs, &cfg);
    let mut keep = vec![true; instrs.len()];
    let mut propagated = 0usize;
    let mut removed = 0usize;

    for (block_id, block) in cfg.blocks.iter().enumerate() {
        let mut copies = inputs[block_id].clone();
        for ip in block.start..block.end {
            propagated += rewrite_uses(&mut instrs[ip], &copies);
            if redundant_register_mov(&instrs[ip], &copies) {
                keep[ip] = false;
                removed += 1;
            } else {
                transfer(&instrs[ip], &mut copies);
            }
        }
    }

    if removed == 0 {
        Ok((instrs, propagated, 0))
    } else {
        Ok((compact(instrs, &keep)?, propagated, removed))
    }
}

/// Sparse forward data-flow. As with SCCP, the first incoming edge seeds a block and
/// later edges intersect facts, so aliases survive joins only when every path agrees.
fn copy_inputs(instrs: &[Instr], cfg: &ControlFlowGraph) -> Vec<Copies> {
    let mut inputs = vec![None; cfg.blocks.len()];
    inputs[0] = Some(Copies::new());
    let mut pending = VecDeque::from([0usize]);
    let mut queued = vec![false; cfg.blocks.len()];
    queued[0] = true;

    while let Some(block_id) = pending.pop_front() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        let mut copies = inputs[block_id].clone().unwrap_or_default();
        for instr in &instrs[block.start..block.end] {
            transfer(instr, &mut copies);
        }
        for successor in &block.successors {
            let Successor::Block(next) = successor else {
                continue;
            };
            let changed = if let Some(input) = &mut inputs[*next] {
                let old_len = input.len();
                input.retain(|dst, src| copies.get(dst) == Some(src));
                input.len() != old_len
            } else {
                inputs[*next] = Some(copies.clone());
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

fn transfer(instr: &Instr, copies: &mut Copies) {
    if let Instr::Mov {
        dst: Dst::Reg(dst),
        src: Src::Reg(src),
    } = instr
    {
        let src = resolve_reg(*src, copies);
        if resolve_reg(*dst, copies) == src {
            return;
        }
        kill_reg(*dst, copies);
        if *dst != src {
            copies.insert(*dst, src);
        }
        return;
    }

    match instr {
        Instr::Bin { dst, .. } | Instr::Neg { dst, .. } | Instr::EqN { dst, .. } => {
            kill_reg(*dst, copies);
        }
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes {
                kill_reg(lane.dst, copies);
                if let Some(Dst::Reg(dst)) = lane.store {
                    kill_reg(dst, copies);
                }
            }
        }
        Instr::Mov {
            dst: Dst::Reg(dst), ..
        } => kill_reg(*dst, copies),
        Instr::LoadN { dst, n, .. }
        | Instr::BinN { dst, n, .. }
        | Instr::OutputSub { dst, n, .. } => kill_range(*dst, *n, copies),
        Instr::StoreN {
            dst: Dst::Reg(dst),
            n,
            ..
        } => kill_range(*dst, *n, copies),
        Instr::CallFn { ret, ret_n, .. } => kill_range(*ret, *ret_n, copies),
        _ => {}
    }
}

fn redundant_register_mov(instr: &Instr, copies: &Copies) -> bool {
    match instr {
        Instr::Mov {
            dst: Dst::Reg(dst),
            src: Src::Reg(src),
        } => resolve_reg(*dst, copies) == resolve_reg(*src, copies),
        _ => false,
    }
}

fn rewrite_uses(instr: &mut Instr, copies: &Copies) -> usize {
    let mut rewritten = 0usize;
    match instr {
        Instr::Bin { a, b, .. } => {
            rewritten += rewrite_src(a, 1, copies);
            rewritten += rewrite_src(b, 1, copies);
        }
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes {
                rewritten += rewrite_src(&mut lane.a, 1, copies);
                rewritten += rewrite_src(&mut lane.b, 1, copies);
            }
        }
        Instr::Neg { a, .. } => rewritten += rewrite_src(a, 1, copies),
        Instr::EqN { a, b, n, .. } | Instr::BinN { a, b, n, .. } => {
            rewritten += rewrite_src(a, *n, copies);
            rewritten += rewrite_src(b, *n, copies);
        }
        Instr::Mov { src, .. }
        | Instr::ToIndex { src, .. }
        | Instr::JmpIfZero { cond: src, .. }
        | Instr::SharedIf { cond: src, .. }
        | Instr::SharedIfBit { cond: src, .. }
        | Instr::Assert { cond: src, .. }
        | Instr::Log { src } => rewritten += rewrite_src(src, 1, copies),
        Instr::LoadN { src, n, .. } => {
            // The VM copies a register-backed LoadN forwards rather than snapshotting
            // all inputs. Changing its source range could change overlap behavior.
            if *n == 1 || !matches!(src, Src::Reg(_)) {
                rewritten += rewrite_src(src, *n, copies);
            }
        }
        Instr::StoreN { dst, src, n } => {
            // Register-to-register StoreN has memmove semantics; preserve its exact
            // overlap relationship. Memory destinations cannot alias field registers.
            if *n == 1 || !matches!(dst, Dst::Reg(_)) {
                rewritten += rewrite_reg_range(src, *n, copies);
            }
        }
        Instr::InputSub { src, n, .. } => rewritten += rewrite_reg_range(src, *n, copies),
        Instr::CallFn {
            args_start, args_n, ..
        } => rewritten += rewrite_reg_range(args_start, *args_n, copies),
        Instr::Ret {
            src: RetSrc::Reg(src),
            n,
        } => rewritten += rewrite_reg_range(src, *n, copies),
        _ => {}
    }
    rewritten
}

fn rewrite_src(src: &mut Src, n: u32, copies: &Copies) -> usize {
    let Src::Reg(reg) = src else {
        return 0;
    };
    let Some(resolved) = resolve_range(*reg, n, copies) else {
        return 0;
    };
    if resolved == *reg {
        0
    } else {
        *reg = resolved;
        1
    }
}

fn rewrite_reg_range(start: &mut u16, n: u32, copies: &Copies) -> usize {
    let Some(resolved) = resolve_range(*start, n, copies) else {
        return 0;
    };
    if resolved == *start {
        0
    } else {
        *start = resolved;
        1
    }
}

fn resolve_range(start: u16, n: u32, copies: &Copies) -> Option<u16> {
    if n == 0 {
        return Some(start);
    }
    let resolved = resolve_reg(start, copies);
    for k in 1..n {
        let reg = u16::try_from(u32::from(start).checked_add(k)?).ok()?;
        let expected = u16::try_from(u32::from(resolved).checked_add(k)?).ok()?;
        if resolve_reg(reg, copies) != expected {
            return None;
        }
    }
    Some(resolved)
}

fn resolve_reg(mut reg: u16, copies: &Copies) -> u16 {
    // Transfers canonicalize every inserted fact, so one lookup is normally enough.
    // Retain the loop to make intersection/debug-constructed inputs robust.
    let mut remaining = copies.len();
    while let Some(next) = copies.get(&reg).copied() {
        if next == reg || remaining == 0 {
            break;
        }
        reg = next;
        remaining -= 1;
    }
    reg
}

fn kill_reg(reg: u16, copies: &mut Copies) {
    copies.remove(&reg);
    copies.retain(|_, source| *source != reg);
}

fn kill_range(start: u16, n: u32, copies: &mut Copies) {
    for k in 0..n {
        let reg = u16::try_from(u32::from(start) + k)
            .expect("validated register definition range exceeds u16");
        kill_reg(reg, copies);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circom_mpc_vm2::isa::{Addr, BinOp, FnId};

    fn unknown(dst: u16) -> Instr {
        Instr::Mov {
            dst: Dst::Reg(dst),
            src: Src::Signal(Addr::Const(u32::from(dst))),
        }
    }

    #[test]
    fn propagates_a_straight_line_copy() {
        let instrs = vec![
            unknown(0),
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Bin {
                op: BinOp::Add,
                dst: 2,
                a: Src::Reg(1),
                b: Src::Reg(1),
            },
            Instr::Return,
        ];
        let (out, propagated, removed) = propagate_register_copies(instrs).unwrap();
        assert_eq!((propagated, removed), (2, 0));
        assert!(matches!(
            out[2],
            Instr::Bin {
                a: Src::Reg(0),
                b: Src::Reg(0),
                ..
            }
        ));
    }

    #[test]
    fn source_overwrite_invalidates_captured_aliases() {
        let instrs = vec![
            unknown(0),
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            unknown(0),
            Instr::Neg {
                dst: 2,
                a: Src::Reg(1),
            },
            Instr::Return,
        ];
        let (out, propagated, _) = propagate_register_copies(instrs).unwrap();
        assert_eq!(propagated, 0);
        assert!(matches!(out[3], Instr::Neg { a: Src::Reg(1), .. }));
    }

    #[test]
    fn canonical_alias_survives_intermediate_register_overwrite() {
        let instrs = vec![
            unknown(0),
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Mov {
                dst: Dst::Reg(2),
                src: Src::Reg(1),
            },
            unknown(1),
            Instr::Neg {
                dst: 3,
                a: Src::Reg(2),
            },
            Instr::Return,
        ];
        let (out, propagated, _) = propagate_register_copies(instrs).unwrap();
        assert_eq!(propagated, 2);
        assert!(matches!(out[4], Instr::Neg { a: Src::Reg(0), .. }));
    }

    #[test]
    fn matching_aliases_survive_a_cfg_join() {
        let instrs = vec![
            unknown(0),
            Instr::JmpIfZero {
                cond: Src::Signal(Addr::Const(9)),
                target: 4,
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Jmp { target: 5 },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Neg {
                dst: 2,
                a: Src::Reg(1),
            },
            Instr::Return,
        ];
        let (out, _, _) = propagate_register_copies(instrs).unwrap();
        assert!(
            out.iter()
                .any(|instr| matches!(instr, Instr::Neg { a: Src::Reg(0), .. }))
        );
    }

    #[test]
    fn differing_aliases_are_dropped_at_a_cfg_join() {
        let instrs = vec![
            unknown(0),
            unknown(3),
            Instr::JmpIfZero {
                cond: Src::Signal(Addr::Const(9)),
                target: 5,
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Jmp { target: 6 },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(3),
            },
            Instr::Neg {
                dst: 2,
                a: Src::Reg(1),
            },
            Instr::Return,
        ];
        let (out, _, _) = propagate_register_copies(instrs).unwrap();
        assert!(
            out.iter()
                .any(|instr| matches!(instr, Instr::Neg { a: Src::Reg(1), .. }))
        );
    }

    #[test]
    fn removes_repeated_register_move() {
        let instrs = vec![
            unknown(0),
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            },
            Instr::Return,
        ];
        let (out, _, removed) = propagate_register_copies(instrs).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn rewrites_only_complete_contiguous_ranges() {
        let contiguous = vec![
            unknown(0),
            unknown(1),
            Instr::Mov {
                dst: Dst::Reg(10),
                src: Src::Reg(0),
            },
            Instr::Mov {
                dst: Dst::Reg(11),
                src: Src::Reg(1),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 10,
                args_n: 2,
                ret: 20,
                ret_n: 0,
            },
            Instr::Return,
        ];
        let (out, propagated, _) = propagate_register_copies(contiguous).unwrap();
        assert_eq!(propagated, 1);
        assert!(matches!(out[4], Instr::CallFn { args_start: 0, .. }));

        let noncontiguous = vec![
            unknown(0),
            unknown(2),
            Instr::Mov {
                dst: Dst::Reg(10),
                src: Src::Reg(0),
            },
            Instr::Mov {
                dst: Dst::Reg(11),
                src: Src::Reg(2),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 10,
                args_n: 2,
                ret: 20,
                ret_n: 0,
            },
            Instr::Return,
        ];
        let (out, _, _) = propagate_register_copies(noncontiguous).unwrap();
        assert!(matches!(out[4], Instr::CallFn { args_start: 10, .. }));
    }

    #[test]
    fn preserves_vector_register_copy_overlap_semantics() {
        let instrs = vec![
            unknown(0),
            unknown(1),
            Instr::Mov {
                dst: Dst::Reg(10),
                src: Src::Reg(0),
            },
            Instr::Mov {
                dst: Dst::Reg(11),
                src: Src::Reg(1),
            },
            Instr::StoreN {
                dst: Dst::Reg(1),
                src: 10,
                n: 2,
            },
            Instr::LoadN {
                dst: 1,
                src: Src::Reg(10),
                n: 2,
            },
            Instr::Return,
        ];
        let (out, _, _) = propagate_register_copies(instrs).unwrap();
        assert!(matches!(out[4], Instr::StoreN { src: 10, .. }));
        assert!(matches!(
            out[5],
            Instr::LoadN {
                src: Src::Reg(10),
                ..
            }
        ));
    }
}
