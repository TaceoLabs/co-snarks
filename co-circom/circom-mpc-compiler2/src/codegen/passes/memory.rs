//! Conservative scalar-variable propagation and dead-store elimination.
//!
//! Constant-addressed `Var` slots are the VM's frame-local memory and cannot alias
//! signals or another function/component frame. Exact slots therefore admit ordinary
//! forward and backward data-flow. Dynamic/affine writes, calls, and shared-control
//! boundaries deliberately discard forward facts. In particular, writes under a shared
//! predicate are buffered until a barrier and are not visible to later bytecode in that
//! region, so forwarding through them would be incorrect.

use super::{ControlFlowGraph, Successor, compact};
use circom_mpc_vm2::isa::{Addr, Dst, Instr, RetSrc, Src};
use eyre::Result;
use std::collections::{HashMap, HashSet, VecDeque};

type KnownVars = HashMap<u32, u32>;

pub(super) fn forward_constant_vars(mut instrs: Vec<Instr>) -> Result<(Vec<Instr>, usize)> {
    let cfg = ControlFlowGraph::build(&instrs)?;
    if cfg.blocks.is_empty() {
        return Ok((instrs, 0));
    }
    let shared = shared_region_mask(&instrs);
    let inputs = constant_var_inputs(&instrs, &cfg, &shared);
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

fn constant_var_inputs(
    instrs: &[Instr],
    cfg: &ControlFlowGraph,
    shared: &[bool],
) -> Vec<KnownVars> {
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
            if let Some(value) = known_constant(*src, known) {
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
        Instr::StoreN {
            dst: Dst::Var(Addr::Const(slot)),
            n,
            ..
        } => remove_range(known, *slot, *n),
        Instr::BinBatch { lanes, .. } => {
            for lane in lanes {
                match lane.store {
                    Some(Dst::Var(Addr::Const(slot))) => {
                        known.remove(&slot);
                    }
                    Some(Dst::Var(_)) => known.clear(),
                    Some(Dst::Reg(_) | Dst::Signal(_)) | None => {}
                }
            }
        }
        _ => {}
    }
}

fn known_constant(src: Src, known: &KnownVars) -> Option<u32> {
    match src {
        Src::Const(id) => Some(id),
        Src::Var(Addr::Const(slot)) => known.get(&slot).copied(),
        Src::Reg(_) | Src::Var(_) | Src::Signal(_) => None,
    }
}

fn remove_range(known: &mut KnownVars, start: u32, n: u32) {
    for k in 0..n {
        if let Some(slot) = start.checked_add(k) {
            known.remove(&slot);
        } else {
            known.clear();
            break;
        }
    }
}

fn rewrite_sources(instr: &mut Instr, known: &KnownVars) -> usize {
    let mut rewritten = 0usize;
    let mut rewrite = |src: &mut Src| {
        if let Src::Var(Addr::Const(slot)) = *src
            && let Some(value) = known.get(&slot)
        {
            *src = Src::Const(*value);
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
            if matches!(src, Src::Const(_)) {
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
        let (out, forwarded) = forward_constant_vars(instrs).unwrap();
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
        let (out, forwarded) = forward_constant_vars(instrs.clone()).unwrap();
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
        let (out, forwarded) = forward_constant_vars(instrs.clone()).unwrap();
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
