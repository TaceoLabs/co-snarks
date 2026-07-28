//! Dependency-safe fusion of irregular scalar binary operations into batches.
//!
//! Codegen's stack allocator commonly emits adjacent `Bin`/`Mov` pairs that reuse the
//! same temporary register, as well as adjacent bare `Bin`s whose results feed a later
//! instruction (e.g. the two products of `a*b + c*d`). [`Instr::BinN`] cannot represent
//! independent operations when their operands or destinations are not consecutive. This
//! pass combines them into [`Instr::BinBatch`] lanes without gather/scatter bytecode: a
//! `Bin` immediately followed by a `Mov` of its result absorbs that `Mov` as the lane's
//! `store`; a bare `Bin` becomes a store-less lane.
//!
//! Only operations the MPC drivers can actually vectorize are batched (see
//! [`is_batchable`]): `Mul`, `BoolAnd`, `Eq`, and `Neq` map onto
//! `Rep3Driver::bin_many`'s single-round groups, while every other op falls back to a
//! scalar loop there — batching those would only add gather overhead. A batch's lanes
//! all share one op, so a run of mixed batchable ops splits at each op change.
//!
//! The pass intentionally does not hoist operations across other instructions. A corpus
//! experiment found that broad same-block hoisting of multiplications grouped much more
//! bytecode but did not reduce Rep3 calls: most added groups contained only one
//! communicating lane and therefore only added plain-case allocation work. Adjacent
//! fusion retains the measured communication wins while staying small and predictable.

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
    op: BinOp,
    bin_ip: usize,
    /// Index of an immediately following `Mov` absorbed as the lane's `store`, if any.
    mov_ip: Option<usize>,
    lane: BinLane,
    reads: [Option<Location>; 2],
    writes: [Option<Location>; 2],
}

/// Ops whose lanes an MPC driver executes in one vectorized communication round.
/// `Rep3Driver::bin_many` batches exactly these four; every other op falls back to its
/// scalar loop there, so batching it would only add gather/scatter overhead.
fn is_batchable(op: BinOp) -> bool {
    matches!(op, BinOp::Mul | BinOp::BoolAnd | BinOp::Eq | BinOp::Neq)
}

/// Replaces adjacent, dependency-free batchable operations (bare, or paired with a
/// result-`Mov`) with irregular batches.
pub(super) fn batch_independent_ops(
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
        let mut group: Vec<Candidate> = Vec::new();
        let mut ip = block.start;
        while ip < block.end {
            if let Some(candidate) = candidate(&instrs, ip, block.end) {
                if group.len() == max_batch_size
                    || group.first().is_some_and(|first| first.op != candidate.op)
                    || has_raw_dependency(&group, &candidate)
                {
                    flush_group(
                        &mut instrs,
                        &mut keep,
                        &mut group,
                        &mut batches,
                        &mut batched_lanes,
                    );
                }
                ip += if candidate.mov_ip.is_some() { 2 } else { 1 };
                group.push(candidate);
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
    let Instr::Bin { op, dst, a, b } = instrs[ip] else {
        return None;
    };
    if !is_batchable(op) {
        return None;
    }
    let a_loc = src_location(a)?;
    let b_loc = src_location(b)?;

    // Absorb an immediately following `Mov` of the result when its destination is a
    // location the dependency check can reason about. A `Mov` to a dynamic/affine
    // address is simply not absorbed: the `Bin` still becomes a store-less lane on its
    // own, and grouping naturally stops at the unabsorbed `Mov`.
    let store = if ip + 1 < block_end {
        match instrs[ip + 1] {
            Instr::Mov {
                dst: store,
                src: Src::Reg(src),
            } if src == dst => dst_location(store).map(|loc| (store, loc)),
            _ => None,
        }
    } else {
        None
    };

    Some(match store {
        Some((store, store_loc)) => Candidate {
            op,
            bin_ip: ip,
            mov_ip: Some(ip + 1),
            lane: BinLane {
                dst,
                store: Some(store),
                a,
                b,
            },
            reads: [a_loc, b_loc],
            writes: [Some(Location::Reg(dst)), Some(store_loc)],
        },
        None => Candidate {
            op,
            bin_ip: ip,
            mov_ip: None,
            lane: BinLane {
                dst,
                store: None,
                a,
                b,
            },
            reads: [a_loc, b_loc],
            writes: [Some(Location::Reg(dst)), None],
        },
    })
}

/// A later lane may not read a value produced by an earlier lane in the same batch.
/// Anti-dependencies are safe because the VM gathers every input before scattering any
/// output, and repeated writes are safe because results are scattered in source order.
fn has_raw_dependency(group: &[Candidate], next: &Candidate) -> bool {
    next.reads.iter().flatten().any(|read| {
        group
            .iter()
            .any(|candidate| candidate.writes.iter().flatten().any(|write| write == read))
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
        let op = group[0].op;
        let lanes = group
            .iter()
            .map(|candidate| candidate.lane)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        instrs[first_ip] = Instr::BinBatch { op, lanes };
        for candidate in group.iter() {
            if candidate.bin_ip != first_ip {
                keep[candidate.bin_ip] = false;
            }
            if let Some(mov_ip) = candidate.mov_ip {
                keep[mov_ip] = false;
            }
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
        op_pair(BinOp::Mul, input, output)
    }

    fn op_pair(op: BinOp, input: u32, output: u32) -> [Instr; 2] {
        [
            Instr::Bin {
                op,
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

    fn bare(dst: u16, a: u32, b: u32) -> Instr {
        Instr::Bin {
            op: BinOp::Mul,
            dst,
            a: Src::Signal(Addr::Const(a)),
            b: Src::Signal(Addr::Const(b)),
        }
    }

    #[test]
    fn batches_independent_pairs_with_reused_temporary() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain(pair(1, 11))
            .chain([Instr::Return])
            .collect();
        let (batched, batches, lanes) = batch_independent_ops(instrs, 16).unwrap();
        assert_eq!((batches, lanes), (1, 2));
        assert!(matches!(
            &batched[..],
            [Instr::BinBatch { lanes, .. }, Instr::Return] if lanes.len() == 2
        ));
    }

    #[test]
    fn batches_adjacent_bare_bins_as_storeless_lanes() {
        // The two products of `a*b + c*d`: adjacent bare Bins into distinct registers,
        // consumed by a later Add — no Movs to absorb.
        let instrs = vec![
            bare(0, 0, 1),
            bare(1, 2, 3),
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Reg(0),
                b: Src::Reg(1),
            },
            Instr::Return,
        ];
        let (batched, batches, lanes) = batch_independent_ops(instrs, 16).unwrap();
        assert_eq!((batches, lanes), (1, 2));
        assert!(matches!(
            &batched[0],
            Instr::BinBatch { op: BinOp::Mul, lanes }
                if lanes.len() == 2 && lanes.iter().all(|lane| lane.store.is_none())
        ));
        assert!(matches!(batched[1], Instr::Bin { op: BinOp::Add, .. }));
    }

    #[test]
    fn batches_batchable_non_mul_ops() {
        for op in [BinOp::BoolAnd, BinOp::Eq, BinOp::Neq] {
            let instrs = op_pair(op, 0, 10)
                .into_iter()
                .chain(op_pair(op, 1, 11))
                .chain([Instr::Return])
                .collect();
            let (batched, batches, lanes) = batch_independent_ops(instrs, 16).unwrap();
            assert_eq!((batches, lanes), (1, 2), "op {op:?} must batch");
            assert!(matches!(
                &batched[0],
                Instr::BinBatch { op: batch_op, lanes } if *batch_op == op && lanes.len() == 2
            ));
        }
    }

    #[test]
    fn non_batchable_op_is_left_scalar() {
        let instrs = op_pair(BinOp::Add, 0, 10)
            .into_iter()
            .chain(op_pair(BinOp::Add, 1, 11))
            .chain([Instr::Return])
            .collect::<Vec<_>>();
        let (batched, batches, lanes) = batch_independent_ops(instrs.clone(), 16).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
    }

    #[test]
    fn mixed_ops_split_into_homogeneous_batches() {
        let instrs = op_pair(BinOp::Mul, 0, 10)
            .into_iter()
            .chain(op_pair(BinOp::Mul, 1, 11))
            .chain(op_pair(BinOp::BoolAnd, 2, 12))
            .chain(op_pair(BinOp::BoolAnd, 3, 13))
            .chain([Instr::Return])
            .collect();
        let (batched, batches, lanes) = batch_independent_ops(instrs, 16).unwrap();
        assert_eq!((batches, lanes), (2, 4));
        assert!(matches!(
            &batched[0],
            Instr::BinBatch { op: BinOp::Mul, .. }
        ));
        assert!(matches!(
            &batched[1],
            Instr::BinBatch {
                op: BinOp::BoolAnd,
                ..
            }
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
        let (batched, batches, lanes) = batch_independent_ops(instrs.clone(), 16).unwrap();
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
        let (batched, batches, lanes) = batch_independent_ops(instrs, 16).unwrap();
        assert_eq!((batches, lanes), (1, 2));
        assert!(matches!(batched[0], Instr::Bin { .. }));
        assert!(matches!(batched[1], Instr::Mov { .. }));
        assert!(matches!(&batched[2], Instr::BinBatch { lanes, .. } if lanes.len() == 2));
    }

    #[test]
    fn bare_bin_result_read_by_later_lane_starts_a_new_batch() {
        // The second Bin reads the first's destination register: gathering both before
        // scattering would read the stale value, so they must not share a batch.
        let instrs = vec![
            bare(0, 0, 1),
            Instr::Bin {
                op: BinOp::Mul,
                dst: 1,
                a: Src::Reg(0),
                b: Src::Signal(Addr::Const(2)),
            },
            Instr::Return,
        ];
        let (batched, batches, lanes) = batch_independent_ops(instrs.clone(), 16).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
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
        let (_batched, batches, lanes) = batch_independent_ops(instrs, 2).unwrap();
        assert_eq!((batches, lanes), (2, 4));
    }

    #[test]
    fn disabled_pass_leaves_input_unchanged() {
        let instrs = pair(0, 10)
            .into_iter()
            .chain(pair(1, 11))
            .chain([Instr::Return])
            .collect::<Vec<_>>();
        let (batched, batches, lanes) = batch_independent_ops(instrs.clone(), 0).unwrap();
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
        let (batched, batches, lanes) = batch_independent_ops(instrs.clone(), 16).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
    }

    #[test]
    fn unabsorbable_dynamic_mov_destination_ends_the_group() {
        // The Bin itself is batchable, but its result-Mov writes through a dynamic
        // address the dependency check can't reason about: the Mov must stay scalar,
        // and adjacency ends there.
        let instrs = vec![
            bare(0, 0, 1),
            Instr::Mov {
                dst: Dst::Var(Addr::Dynamic(0)),
                src: Src::Reg(0),
            },
            bare(1, 2, 3),
            Instr::Return,
        ];
        let (batched, batches, lanes) = batch_independent_ops(instrs.clone(), 16).unwrap();
        assert_eq!((batches, lanes), (0, 0));
        assert_eq!(batched, instrs);
    }
}
