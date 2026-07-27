//! Dependency-safe fusion of irregular scalar multiplication/store pairs.
//!
//! Codegen's stack allocator commonly emits adjacent `Bin`/`Mov` pairs that reuse the
//! same temporary register. [`Instr::BinN`] cannot represent independent pairs when their
//! operands or destinations are not consecutive. This pass combines such pairs into
//! [`Instr::BinBatch`] lanes without gather/scatter bytecode.
//!
//! The pass intentionally does not hoist multiplications across other instructions. A
//! corpus experiment found that broad same-block hoisting grouped much more bytecode but
//! did not reduce Rep3 calls: most added groups contained only one communicating lane and
//! therefore only added plain-case allocation work. Adjacent pair fusion retains the
//! measured communication wins while staying small and predictable.

use super::{ControlFlowGraph, compact};
use circom_mpc_vm2::isa::{Addr, BinLane, BinOp, Dst, Instr, Src};
use eyre::Result;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Location {
    Reg(u16),
    Var(u32),
    Signal(u32),
}

struct Candidate {
    bin_ip: usize,
    mov_ip: usize,
    lane: BinLane,
    reads: [Option<Location>; 2],
    writes: [Location; 2],
}

/// Replaces adjacent, dependency-free `Mul`/`Mov` pairs with irregular batches.
pub(super) fn batch_independent_muls(
    mut instrs: Vec<Instr>,
    max_batch_size: usize,
) -> Result<(Vec<Instr>, usize, usize)> {
    if max_batch_size < 2 {
        return Ok((instrs, 0, 0));
    }

    let cfg = ControlFlowGraph::build(&instrs)?;
    let mut keep = vec![true; instrs.len()];
    let mut batches = 0usize;
    let mut batched_lanes = 0usize;

    for block in &cfg.blocks {
        let mut group = Vec::new();
        let mut ip = block.start;
        while ip < block.end {
            if let Some(candidate) = candidate(&instrs, ip, block.end) {
                if group.len() == max_batch_size || has_raw_dependency(&group, &candidate) {
                    flush_group(
                        &mut instrs,
                        &mut keep,
                        &mut group,
                        &mut batches,
                        &mut batched_lanes,
                    );
                }
                group.push(candidate);
                ip += 2;
            } else {
                flush_group(
                    &mut instrs,
                    &mut keep,
                    &mut group,
                    &mut batches,
                    &mut batched_lanes,
                );
                ip += 1;
            }
        }
        flush_group(
            &mut instrs,
            &mut keep,
            &mut group,
            &mut batches,
            &mut batched_lanes,
        );
    }

    if batches == 0 {
        Ok((instrs, 0, 0))
    } else {
        Ok((compact(instrs, &keep)?, batches, batched_lanes))
    }
}

fn candidate(instrs: &[Instr], ip: usize, block_end: usize) -> Option<Candidate> {
    if ip + 1 >= block_end {
        return None;
    }
    let Instr::Bin {
        op: BinOp::Mul,
        dst,
        a,
        b,
    } = instrs[ip]
    else {
        return None;
    };
    let Instr::Mov {
        dst: store,
        src: Src::Reg(src),
    } = instrs[ip + 1]
    else {
        return None;
    };
    if src != dst {
        return None;
    }

    let a_loc = src_location(a)?;
    let b_loc = src_location(b)?;
    let store_loc = dst_location(store)?;
    Some(Candidate {
        bin_ip: ip,
        mov_ip: ip + 1,
        lane: BinLane {
            dst,
            store: Some(store),
            a,
            b,
        },
        reads: [a_loc, b_loc],
        writes: [Location::Reg(dst), store_loc],
    })
}

/// A later lane may not read a value produced by an earlier lane in the same batch.
/// Anti-dependencies are safe because the VM gathers every input before scattering any
/// output, and repeated writes are safe because results are scattered in source order.
fn has_raw_dependency(group: &[Candidate], next: &Candidate) -> bool {
    next.reads.iter().flatten().any(|read| {
        group
            .iter()
            .any(|candidate| candidate.writes.contains(read))
    })
}

fn flush_group(
    instrs: &mut [Instr],
    keep: &mut [bool],
    group: &mut Vec<Candidate>,
    batches: &mut usize,
    batched_lanes: &mut usize,
) {
    if group.len() >= 2 {
        let first_ip = group[0].bin_ip;
        let lanes = group
            .iter()
            .map(|candidate| candidate.lane)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        instrs[first_ip] = Instr::BinBatch {
            op: BinOp::Mul,
            lanes,
        };
        for candidate in group.iter() {
            if candidate.bin_ip != first_ip {
                keep[candidate.bin_ip] = false;
            }
            keep[candidate.mov_ip] = false;
        }
        *batches += 1;
        *batched_lanes += group.len();
    }
    group.clear();
}

/// Returns `None` for dynamic/affine addresses: without alias analysis they cannot safely
/// participate in a reordered batch. Constants have no mutable location and are encoded
/// as `Some(None)`.
fn src_location(src: Src) -> Option<Option<Location>> {
    match src {
        Src::Reg(reg) => Some(Some(Location::Reg(reg))),
        Src::Const(_) => Some(None),
        Src::Var(Addr::Const(slot)) => Some(Some(Location::Var(slot))),
        Src::Signal(Addr::Const(slot)) => Some(Some(Location::Signal(slot))),
        Src::Var(_) | Src::Signal(_) => None,
    }
}

fn dst_location(dst: Dst) -> Option<Location> {
    match dst {
        Dst::Reg(reg) => Some(Location::Reg(reg)),
        Dst::Var(Addr::Const(slot)) => Some(Location::Var(slot)),
        Dst::Signal(Addr::Const(slot)) => Some(Location::Signal(slot)),
        Dst::Var(_) | Dst::Signal(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(input: u32, output: u32) -> [Instr; 2] {
        [
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Var(Addr::Const(input)),
                b: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(output)),
                src: Src::Reg(0),
            },
        ]
    }

    #[test]
    fn batches_independent_pairs_with_reused_temporary() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain(pair(1, 11))
            .chain([Instr::Return])
            .collect();
        let (batched, batches, lanes) = batch_independent_muls(instrs, 16).unwrap();
        assert_eq!((batches, lanes), (1, 2));
        assert!(matches!(
            &batched[..],
            [Instr::BinBatch { lanes, .. }, Instr::Return] if lanes.len() == 2
        ));
    }

    #[test]
    fn intervening_instruction_ends_the_group() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain([Instr::Neg {
                dst: 3,
                a: Src::Const(0),
            }])
            .chain(pair(1, 11))
            .chain([Instr::Return])
            .collect::<Vec<_>>();
        let (batched, batches, lanes) = batch_independent_muls(instrs.clone(), 16).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
    }

    #[test]
    fn raw_dependency_starts_a_new_level() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain(pair(10, 11))
            .chain(pair(2, 12))
            .chain([Instr::Return])
            .collect();
        let (batched, batches, lanes) = batch_independent_muls(instrs, 16).unwrap();
        assert_eq!((batches, lanes), (1, 2));
        assert!(matches!(batched[0], Instr::Bin { .. }));
        assert!(matches!(batched[1], Instr::Mov { .. }));
        assert!(matches!(&batched[2], Instr::BinBatch { lanes, .. } if lanes.len() == 2));
    }

    #[test]
    fn configurable_cap_splits_large_group() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain(pair(1, 11))
            .chain(pair(2, 12))
            .chain(pair(3, 13))
            .chain(pair(4, 14))
            .chain([Instr::Return])
            .collect();
        let (_batched, batches, lanes) = batch_independent_muls(instrs, 2).unwrap();
        assert_eq!((batches, lanes), (2, 4));
    }

    #[test]
    fn disabled_pass_leaves_input_unchanged() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain(pair(1, 11))
            .chain([Instr::Return])
            .collect::<Vec<_>>();
        let (batched, batches, lanes) = batch_independent_muls(instrs.clone(), 0).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
    }

    #[test]
    fn dynamic_address_is_left_scalar() {
        let mut instrs = pair(0, 10).to_vec();
        instrs.extend([
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Var(Addr::Dynamic(0)),
                b: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(11)),
                src: Src::Reg(0),
            },
            Instr::Return,
        ]);
        let (batched, batches, lanes) = batch_independent_muls(instrs.clone(), 16).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
    }
}
