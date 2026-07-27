//! Dead-code elimination for register-only definitions.
//!
//! The pass deliberately treats every externally observable instruction as a root:
//! stores to vars/signals, calls, component operations, assertions, logs, returns, and
//! control flow always survive. Arithmetic and loads whose only effect is defining field
//! or integer registers may be removed when every defined register is dead.
//!
//! This includes interactive MPC arithmetic. All parties execute an identical compiled
//! program (the VM verifies its execution fingerprint before Rep3 execution), so removing
//! the same unused protocol call for every party cannot desynchronize transcripts. The
//! assumption is the current semi-honest VM; a future authenticated/malicious protocol
//! may need a stricter policy.

use super::{ControlFlowGraph, Successor, compact};
use circom_mpc_vm2::isa::{Addr, Dst, ISrc, Instr, RetSrc, Src};
use eyre::Result;

const FIELD_REGS: usize = 1 << 16;
const INTEGER_REGS: usize = 1 << 8;
const INTEGER_BASE: usize = FIELD_REGS;
const REGISTER_KEYS: usize = FIELD_REGS + INTEGER_REGS;

/// Repeatedly removes dead register definitions. Repetition matters when a dead
/// definition in one block was the only cross-block user keeping another definition
/// alive in the preceding iteration.
pub(super) fn eliminate_dead_register_defs(mut instrs: Vec<Instr>) -> Result<(Vec<Instr>, usize)> {
    let mut removed_total = 0usize;
    loop {
        let cfg = ControlFlowGraph::build(&instrs)?;
        let live_in = solve_liveness(&instrs, &cfg);
        let mut keep = vec![true; instrs.len()];
        let mut live = LiveSet::new();

        for block in &cfg.blocks {
            live.clear();
            add_successor_liveness(&mut live, &block.successors, &live_in);
            for ip in (block.start..block.end).rev() {
                let instr = &instrs[ip];
                if is_removable(instr) && definitions_are_dead(&live, instr) {
                    keep[ip] = false;
                    continue;
                }
                transfer(&mut live, instr);
            }
        }

        let removed = keep.iter().filter(|keep| !**keep).count();
        if removed == 0 {
            return Ok((instrs, removed_total));
        }
        removed_total += removed;
        instrs = compact(instrs, &keep)?;
    }
}

/// Computes block live-in sets with a predecessor worklist. Sets are stored sparsely per
/// block because codegen's stack-disciplined allocator normally leaves only a handful of
/// values live at a boundary; one dense scratch bitset handles unions and transfers.
fn solve_liveness(instrs: &[Instr], cfg: &ControlFlowGraph) -> Vec<Vec<u32>> {
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

    let mut live_in = vec![Vec::new(); cfg.blocks.len()];
    let mut pending = (0..cfg.blocks.len()).rev().collect::<Vec<_>>();
    let mut queued = vec![true; cfg.blocks.len()];
    let mut live = LiveSet::new();

    while let Some(block_id) = pending.pop() {
        queued[block_id] = false;
        let block = &cfg.blocks[block_id];
        live.clear();
        add_successor_liveness(&mut live, &block.successors, &live_in);
        for ip in (block.start..block.end).rev() {
            transfer(&mut live, &instrs[ip]);
        }
        let new_live_in = live.to_sorted_vec();
        if new_live_in != live_in[block_id] {
            live_in[block_id] = new_live_in;
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

fn add_successor_liveness(live: &mut LiveSet, successors: &[Successor], live_in: &[Vec<u32>]) {
    for successor in successors {
        if let Successor::Block(block) = successor {
            live.extend(&live_in[*block]);
        }
    }
}

/// Reverse liveness transfer: definitions kill old values, then operands generate uses.
fn transfer(live: &mut LiveSet, instr: &Instr) {
    kill_definitions(live, instr);
    add_uses(live, instr);
}

fn is_removable(instr: &Instr) -> bool {
    matches!(
        instr,
        Instr::Bin { .. }
            | Instr::Neg { .. }
            | Instr::EqN { .. }
            | Instr::Mov {
                dst: Dst::Reg(_),
                ..
            }
            | Instr::LoadN { .. }
            | Instr::StoreN {
                dst: Dst::Reg(_),
                ..
            }
            | Instr::BinN { .. }
            | Instr::ISet { .. }
            | Instr::IAdd { .. }
            | Instr::IMul { .. }
            | Instr::ToIndex { .. }
    )
}

fn definitions_are_dead(live: &LiveSet, instr: &Instr) -> bool {
    match instr {
        Instr::Bin { dst, .. } | Instr::Neg { dst, .. } | Instr::EqN { dst, .. } => {
            !live.contains_field(*dst)
        }
        Instr::Mov {
            dst: Dst::Reg(dst), ..
        } => !live.contains_field(*dst),
        Instr::LoadN { dst, n, .. } | Instr::BinN { dst, n, .. } => {
            live.field_range_is_empty(*dst, *n)
        }
        Instr::StoreN {
            dst: Dst::Reg(dst),
            n,
            ..
        } => live.field_range_is_empty(*dst, *n),
        Instr::ISet { dst, .. }
        | Instr::IAdd { dst, .. }
        | Instr::IMul { dst, .. }
        | Instr::ToIndex { dst, .. } => !live.contains_integer(*dst),
        _ => false,
    }
}

fn kill_definitions(live: &mut LiveSet, instr: &Instr) {
    match instr {
        Instr::Bin { dst, .. } | Instr::Neg { dst, .. } | Instr::EqN { dst, .. } => {
            live.remove_field(*dst);
        }
        Instr::Mov {
            dst: Dst::Reg(dst), ..
        } => live.remove_field(*dst),
        Instr::LoadN { dst, n, .. }
        | Instr::BinN { dst, n, .. }
        | Instr::OutputSub { dst, n, .. } => live.remove_field_range(*dst, *n),
        Instr::StoreN {
            dst: Dst::Reg(dst),
            n,
            ..
        } => live.remove_field_range(*dst, *n),
        Instr::CallFn { ret, ret_n, .. } => live.remove_field_range(*ret, *ret_n),
        Instr::ISet { dst, .. }
        | Instr::IAdd { dst, .. }
        | Instr::IMul { dst, .. }
        | Instr::ToIndex { dst, .. } => live.remove_integer(*dst),
        _ => {}
    }
}

fn add_uses(live: &mut LiveSet, instr: &Instr) {
    match instr {
        Instr::Bin { a, b, .. } => {
            live.add_src(*a, 1);
            live.add_src(*b, 1);
        }
        Instr::Neg { a, .. } => live.add_src(*a, 1),
        Instr::EqN { a, b, n, .. } | Instr::BinN { a, b, n, .. } => {
            live.add_src(*a, *n);
            live.add_src(*b, *n);
        }
        Instr::Mov { dst, src } => {
            live.add_dst_address(*dst);
            live.add_src(*src, 1);
        }
        Instr::LoadN { src, n, .. } => live.add_src(*src, *n),
        Instr::StoreN { dst, src, n } => {
            live.add_dst_address(*dst);
            live.add_field_range(*src, *n);
        }
        Instr::ISet { .. } => {}
        Instr::IAdd { a, b, .. } | Instr::IMul { a, b, .. } => {
            live.add_isrc(*a);
            live.add_isrc(*b);
        }
        Instr::ToIndex { src, .. } => live.add_src(*src, 1),
        Instr::Jmp { .. } => {}
        Instr::JmpIfZero { cond, .. }
        | Instr::SharedIf { cond, .. }
        | Instr::SharedIfBit { cond, .. }
        | Instr::Assert { cond, .. } => live.add_src(*cond, 1),
        Instr::SharedElse { .. } | Instr::SharedEnd | Instr::CreateCmp { .. } => {}
        Instr::InputSub {
            cmp, addr, src, n, ..
        } => {
            live.add_isrc(*cmp);
            live.add_addr(*addr);
            live.add_field_range(*src, *n);
        }
        Instr::OutputSub { cmp, addr, .. } => {
            live.add_isrc(*cmp);
            live.add_addr(*addr);
        }
        Instr::CallFn {
            args_start, args_n, ..
        } => live.add_field_range(*args_start, *args_n),
        Instr::Ret { src, n } => match src {
            RetSrc::Reg(reg) => live.add_field_range(*reg, *n),
            RetSrc::Var(addr) => live.add_addr(*addr),
        },
        Instr::Return | Instr::LogStr { .. } | Instr::LogFlush { .. } => {}
        Instr::Log { src } => live.add_src(*src, 1),
    }
}

/// Dense scratch bitset over disjoint field and integer register namespaces.
struct LiveSet {
    words: Vec<u64>,
}

impl LiveSet {
    fn new() -> Self {
        Self {
            words: vec![0; REGISTER_KEYS.div_ceil(64)],
        }
    }

    fn clear(&mut self) {
        self.words.fill(0);
    }

    fn extend(&mut self, keys: &[u32]) {
        for key in keys {
            self.insert(*key as usize);
        }
    }

    fn insert(&mut self, key: usize) {
        self.words[key / 64] |= 1 << (key % 64);
    }

    fn remove(&mut self, key: usize) {
        self.words[key / 64] &= !(1 << (key % 64));
    }

    fn contains(&self, key: usize) -> bool {
        self.words[key / 64] & (1 << (key % 64)) != 0
    }

    fn contains_field(&self, reg: u16) -> bool {
        self.contains(reg as usize)
    }

    fn contains_integer(&self, reg: u8) -> bool {
        self.contains(INTEGER_BASE + reg as usize)
    }

    fn add_field_range(&mut self, start: u16, n: u32) {
        for reg in field_range(start, n) {
            self.insert(reg);
        }
    }

    fn remove_field_range(&mut self, start: u16, n: u32) {
        for reg in field_range(start, n) {
            self.remove(reg);
        }
    }

    fn field_range_is_empty(&self, start: u16, n: u32) -> bool {
        field_range(start, n).all(|reg| !self.contains(reg))
    }

    fn remove_field(&mut self, reg: u16) {
        self.remove(reg as usize);
    }

    fn remove_integer(&mut self, reg: u8) {
        self.remove(INTEGER_BASE + reg as usize);
    }

    fn add_src(&mut self, src: Src, n: u32) {
        match src {
            Src::Reg(reg) => self.add_field_range(reg, n),
            Src::Var(addr) | Src::Signal(addr) => self.add_addr(addr),
            Src::Const(_) => {}
        }
    }

    fn add_dst_address(&mut self, dst: Dst) {
        if let Dst::Var(addr) | Dst::Signal(addr) = dst {
            self.add_addr(addr);
        }
    }

    fn add_addr(&mut self, addr: Addr) {
        match addr {
            Addr::Affine { ireg, .. } | Addr::Dynamic(ireg) => {
                self.insert(INTEGER_BASE + ireg as usize);
            }
            Addr::Const(_) => {}
        }
    }

    fn add_isrc(&mut self, src: ISrc) {
        if let ISrc::Reg(reg) = src {
            self.insert(INTEGER_BASE + reg as usize);
        }
    }

    fn to_sorted_vec(&self) -> Vec<u32> {
        let mut result = Vec::new();
        for (word_index, word) in self.words.iter().copied().enumerate() {
            let mut remaining = word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                result.push((word_index * 64 + bit) as u32);
                remaining &= remaining - 1;
            }
        }
        result
    }
}

fn field_range(start: u16, n: u32) -> std::ops::Range<usize> {
    let start = start as usize;
    let end = start.saturating_add(n as usize).min(FIELD_REGS);
    start..end
}

#[cfg(test)]
mod tests {
    use super::*;
    use circom_mpc_vm2::isa::{BinOp, FnId};

    #[test]
    fn removes_cascading_dead_interactive_arithmetic() {
        let (out, removed) = eliminate_dead_register_defs(vec![
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Signal(Addr::Const(0)),
                b: Src::Signal(Addr::Const(1)),
            },
            Instr::Bin {
                op: BinOp::Eq,
                dst: 1,
                a: Src::Reg(0),
                b: Src::Const(0),
            },
            Instr::Return,
        ])
        .unwrap();
        assert_eq!(removed, 2);
        assert_eq!(out, vec![Instr::Return]);
    }

    #[test]
    fn memory_store_keeps_its_register_dependency_chain() {
        let body = vec![
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
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_register_defs(body.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, body);
    }

    #[test]
    fn cross_block_uses_keep_a_definition_live() {
        let body = vec![
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Signal(Addr::Const(0)),
                b: Src::Signal(Addr::Const(1)),
            },
            Instr::JmpIfZero {
                cond: Src::Signal(Addr::Const(2)),
                target: 4,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(3)),
                src: Src::Reg(0),
            },
            Instr::Jmp { target: 5 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(4)),
                src: Src::Reg(0),
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_register_defs(body.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, body);
    }

    #[test]
    fn removes_dead_integer_address_calculations() {
        let (out, removed) = eliminate_dead_register_defs(vec![
            Instr::ISet { dst: 0, val: 7 },
            Instr::IAdd {
                dst: 1,
                a: ISrc::Reg(0),
                b: ISrc::Const(3),
            },
            Instr::Return,
        ])
        .unwrap();
        assert_eq!(removed, 2);
        assert_eq!(out, vec![Instr::Return]);
    }

    #[test]
    fn dynamic_memory_address_keeps_its_integer_definition_live() {
        let body = vec![
            Instr::ISet { dst: 0, val: 7 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Dynamic(0)),
                src: Src::Const(0),
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_register_defs(body.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, body);
    }

    #[test]
    fn one_live_vector_lane_keeps_the_whole_vector_definition() {
        let body = vec![
            Instr::BinN {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Signal(Addr::Const(0)),
                b: Src::Signal(Addr::Const(4)),
                n: 4,
            },
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(8)),
                src: 2,
                n: 1,
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_register_defs(body.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, body);
    }

    #[test]
    fn calls_remain_and_keep_argument_producers_live() {
        let body = vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(0)),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 1,
                ret: 1,
                ret_n: 1,
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_register_defs(body.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, body);
    }

    #[test]
    fn component_output_reads_remain_when_the_result_is_dead() {
        let body = vec![
            Instr::OutputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 0,
                n: 1,
            },
            Instr::Return,
        ];
        let (out, removed) = eliminate_dead_register_defs(body.clone()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(out, body);
    }
}
