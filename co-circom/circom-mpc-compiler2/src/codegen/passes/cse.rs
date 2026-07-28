//! Block-local common-subexpression elimination (local value numbering).
//!
//! A `Bin`/`Neg` whose operator and operand *values* match an earlier one in the same
//! basic block is rewritten to a register `Mov` from the earlier result. The pass never
//! rewrites uses itself: the fixed-point pipeline's copy propagation folds the `Mov`
//! into its users and dead-code elimination then removes it. Under MPC this deletes the
//! duplicated protocol operation outright — a repeated interactive multiplication or
//! comparison is repeated communication.
//!
//! Removing one of two identical interactive operations is transcript-safe for the same
//! reason dead-code elimination of interactive operations is (see `dce.rs`): all
//! parties execute an identical compiled program, so every party reuses the same first
//! result and skips the same second protocol call.
//!
//! Value identity is tracked with generation counters instead of alias analysis. Every
//! field register carries a generation bumped on (re)definition; the integer registers
//! likewise. Var/signal reads embed the generations of a per-space [`Space`] tracker:
//! an exact (`Addr::Const`) write bumps only its own slot, so the ubiquitous
//! store-compute-store pattern doesn't invalidate unrelated reads, while a write
//! through a runtime-computed address — which could alias anything — clobbers its whole
//! space. An expression's key embeds the generation of everything it read, so two
//! syntactically equal expressions match only when nothing they read could have changed
//! in between. Remaining bumps are conservative:
//!
//! - merge barriers clobber both spaces: under a shared predicate the VM cmux-merges
//!   buffered var/signal writes at every write barrier, changing memory without a
//!   store instruction. This covers `Assert`/`Log*`/`SharedEnd` as well as the
//!   component and call instructions (`CallFn`, `CreateCmp`, `InputSub`, `OutputSub`),
//!   which additionally may run other bodies that write signal RAM. `SharedEnd` also
//!   clears every available expression, because popping the predicate changes the
//!   `Div` zero-guard semantics of otherwise identical instructions.
//!
//! Error behavior is preserved: a match requires identical operand values, so if the
//! first occurrence executed without error (division by zero, unsupported shared
//! shift, ...), the second would have, too.

use super::{ControlFlowGraph, compact};
use circom_mpc_vm2::isa::{Addr, BinOp, Dst, Instr, Src};
use eyre::Result;
use std::collections::HashMap;

const INTEGER_REGS: usize = 1 << 8;

/// Rewrites repeated pure register computations to `Mov`s from the first result.
/// Returns the number of replaced instructions.
pub(super) fn eliminate_common_subexpressions(
    mut instrs: Vec<Instr>,
    num_field_regs: usize,
) -> Result<(Vec<Instr>, usize)> {
    let cfg = ControlFlowGraph::build(&instrs)?;
    let mut replaced = 0usize;
    let mut state = State::new(num_field_regs);

    for block in &cfg.blocks {
        state.reset_block();
        for instr in &mut instrs[block.start..block.end] {
            let replacement = match instr {
                Instr::Bin { op, dst, a, b } => state
                    .bin_key(*op, *a, *b)
                    .and_then(|key| state.reuse(&key, *dst)),
                Instr::Neg { dst, a } => state.neg_key(*a).and_then(|key| state.reuse(&key, *dst)),
                _ => None,
            };
            if let Some(mov) = replacement {
                *instr = mov;
                replaced += 1;
            }
            state.transfer(instr);
        }
    }

    // A reused expression writing back into its own holder register becomes a
    // self-move; drop it here instead of leaving it for the constant-folding pass.
    let keep = instrs
        .iter()
        .map(|instr| {
            !matches!(
                instr,
                Instr::Mov {
                    dst: Dst::Reg(dst),
                    src: Src::Reg(src),
                } if dst == src
            )
        })
        .collect::<Vec<_>>();
    if keep.iter().all(|keep| *keep) {
        Ok((instrs, replaced))
    } else {
        Ok((compact(instrs, &keep)?, replaced))
    }
}

/// One operand's value identity: its location plus the generation of everything the
/// read depends on. Two keys are equal exactly when the operand denotes the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum OpKey {
    Reg {
        reg: u16,
        generation: u32,
    },
    Const(u32),
    /// A var/signal read at a statically-known slot: invalidated by writes to that
    /// exact slot and by whole-space clobbers, but *not* by exact writes elsewhere.
    Exact {
        space: SpaceKind,
        slot: u32,
        space_generation: u32,
        slot_generation: u32,
    },
    /// A var/signal read through a runtime-computed address: could alias any slot, so
    /// it embeds the generation bumped by *every* write to the space.
    Indirect {
        space: SpaceKind,
        addr: AddrKey,
        generation: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SpaceKind {
    Var,
    Signal,
}

/// A non-constant [`Addr`]'s identity; `Affine`/`Dynamic` embed the referenced integer
/// register's generation, since the address itself changes when that register does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddrKey {
    Affine {
        ireg: u8,
        generation: u32,
        stride: u32,
        offset: u32,
    },
    Dynamic {
        ireg: u8,
        generation: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ExprKey {
    Bin { op: BinOp, a: OpKey, b: OpKey },
    Neg { a: OpKey },
}

/// Where an available expression's value currently lives. Valid only while the holder
/// register's generation still matches (checked on lookup, so redefining a holder
/// implicitly invalidates every entry pointing at it without any map scan).
struct Holder {
    reg: u16,
    generation: u32,
}

/// Write tracking for one memory space (the frame's vars, or signal RAM).
#[derive(Default)]
struct Space {
    /// Bumped by writes whose destination slot is not statically known, and by
    /// clobbers (calls, component runs, merge barriers). Part of every read key.
    space_generation: u32,
    /// Per-slot generations for exact (`Addr::Const`) writes.
    slot_generation: HashMap<u32, u32>,
    /// Bumped by *every* write, exact or not. Part of indirect read keys, which could
    /// alias any slot.
    any_write_generation: u32,
}

impl Space {
    fn write_exact(&mut self, slot: u32) {
        *self.slot_generation.entry(slot).or_insert(0) += 1;
        self.any_write_generation += 1;
    }

    fn write_exact_range(&mut self, start: u32, n: u32) {
        for k in 0..n {
            match start.checked_add(k) {
                Some(slot) => self.write_exact(slot),
                None => {
                    self.clobber();
                    return;
                }
            }
        }
    }

    fn clobber(&mut self) {
        self.space_generation += 1;
        self.any_write_generation += 1;
    }

    fn slot_generation(&self, slot: u32) -> u32 {
        self.slot_generation.get(&slot).copied().unwrap_or(0)
    }
}

struct State {
    reg_gen: Vec<u32>,
    ireg_gen: [u32; INTEGER_REGS],
    vars: Space,
    signals: Space,
    available: HashMap<ExprKey, Holder>,
}

impl State {
    fn new(num_field_regs: usize) -> Self {
        Self {
            reg_gen: vec![0; num_field_regs],
            ireg_gen: [0; INTEGER_REGS],
            vars: Space::default(),
            signals: Space::default(),
            available: HashMap::new(),
        }
    }

    /// Facts are block-local; generations are monotone across the whole body, so they
    /// need no reset (a stale entry can never be looked up again anyway).
    fn reset_block(&mut self) {
        self.available.clear();
    }

    fn bin_key(&self, op: BinOp, a: Src, b: Src) -> Option<ExprKey> {
        let a = self.op_key(a)?;
        let b = self.op_key(b)?;
        // Canonicalize commutative operand order so `a*b` also matches `b*a`.
        let (a, b) = if is_commutative(op) && b < a {
            (b, a)
        } else {
            (a, b)
        };
        Some(ExprKey::Bin { op, a, b })
    }

    fn neg_key(&self, a: Src) -> Option<ExprKey> {
        Some(ExprKey::Neg { a: self.op_key(a)? })
    }

    fn op_key(&self, src: Src) -> Option<OpKey> {
        Some(match src {
            Src::Reg(reg) => OpKey::Reg {
                reg,
                generation: *self.reg_gen.get(usize::from(reg))?,
            },
            Src::Const(id) => OpKey::Const(id),
            Src::Var(addr) => self.mem_key(SpaceKind::Var, &self.vars, addr),
            Src::Signal(addr) => self.mem_key(SpaceKind::Signal, &self.signals, addr),
        })
    }

    fn mem_key(&self, kind: SpaceKind, space: &Space, addr: Addr) -> OpKey {
        match addr {
            Addr::Const(slot) => OpKey::Exact {
                space: kind,
                slot,
                space_generation: space.space_generation,
                slot_generation: space.slot_generation(slot),
            },
            Addr::Affine {
                ireg,
                stride,
                offset,
            } => OpKey::Indirect {
                space: kind,
                addr: AddrKey::Affine {
                    ireg,
                    generation: self.ireg_gen[usize::from(ireg)],
                    stride,
                    offset,
                },
                generation: space.any_write_generation,
            },
            Addr::Dynamic(ireg) => OpKey::Indirect {
                space: kind,
                addr: AddrKey::Dynamic {
                    ireg,
                    generation: self.ireg_gen[usize::from(ireg)],
                },
                generation: space.any_write_generation,
            },
        }
    }

    /// If `key`'s value is still available in some register, the `Mov` replacing a
    /// recomputation into `dst`.
    fn reuse(&self, key: &ExprKey, dst: u16) -> Option<Instr> {
        let holder = self.available.get(key)?;
        if self.reg_gen.get(usize::from(holder.reg)).copied() != Some(holder.generation) {
            return None;
        }
        Some(Instr::Mov {
            dst: Dst::Reg(dst),
            src: Src::Reg(holder.reg),
        })
    }

    fn transfer(&mut self, instr: &Instr) {
        match instr {
            Instr::Bin { op, dst, a, b } => {
                // Key operand generations first: when `dst` is also an operand, the key
                // must reflect the pre-definition value (the resulting entry is then
                // unreachable, which is exactly right).
                let key = self.bin_key(*op, *a, *b);
                self.kill_reg(*dst);
                self.record(key, *dst);
            }
            Instr::Neg { dst, a } => {
                let key = self.neg_key(*a);
                self.kill_reg(*dst);
                self.record(key, *dst);
            }
            Instr::EqN { dst, .. } => self.kill_reg(*dst),
            Instr::Mov { dst, .. } => self.kill_dst(*dst),
            Instr::LoadN { dst, n, .. } | Instr::BinN { dst, n, .. } => {
                self.kill_reg_range(*dst, *n)
            }
            Instr::OutputSub { dst, n, .. } => {
                self.kill_reg_range(*dst, *n);
                // A write barrier in the VM: under a shared predicate, buffered
                // var/signal writes are cmux-merged right before it executes — and
                // unlike `InputSub`, it is legal inside a shared branch — so memory can
                // change here without any store instruction.
                self.vars.clobber();
                self.signals.clobber();
            }
            Instr::StoreN { dst, n, .. } => match dst {
                Dst::Reg(reg) => self.kill_reg_range(*reg, *n),
                Dst::Var(Addr::Const(slot)) => self.vars.write_exact_range(*slot, *n),
                Dst::Signal(Addr::Const(slot)) => self.signals.write_exact_range(*slot, *n),
                Dst::Var(_) => self.vars.clobber(),
                Dst::Signal(_) => self.signals.clobber(),
            },
            Instr::BinBatch { lanes, .. } => {
                for lane in lanes {
                    self.kill_reg(lane.dst);
                    if let Some(store) = lane.store {
                        self.kill_dst(store);
                    }
                }
            }
            Instr::ISet { dst, .. }
            | Instr::IAdd { dst, .. }
            | Instr::IMul { dst, .. }
            | Instr::ToIndex { dst, .. } => {
                self.ireg_gen[usize::from(*dst)] += 1;
            }
            Instr::CallFn { ret, ret_n, .. } => {
                self.kill_reg_range(*ret, *ret_n);
                // Execution boundary: keep parity with the memory pass's deliberately
                // conservative call handling.
                self.vars.clobber();
                self.signals.clobber();
            }
            Instr::CreateCmp { .. } | Instr::InputSub { .. } => {
                // May run a subcomponent body, which writes signal RAM — and both are
                // write barriers in the VM, merging buffered predicated writes before
                // executing, so conservatively clobber the var space too.
                self.vars.clobber();
                self.signals.clobber();
            }
            Instr::SharedEnd
            | Instr::Assert { .. }
            | Instr::Log { .. }
            | Instr::LogStr { .. }
            | Instr::LogFlush { .. } => {
                // Merge barriers: under a shared predicate the VM cmux-merges buffered
                // var/signal writes here, changing memory without a store instruction.
                self.vars.clobber();
                self.signals.clobber();
                // Popping a predicate level changes the runtime `Div` zero-guard, so an
                // identical `Div` before and after a `SharedEnd` may not be one value.
                if matches!(instr, Instr::SharedEnd) {
                    self.available.clear();
                }
            }
            // Block terminators: facts never survive past them (blocks are re-seeded).
            Instr::Jmp { .. }
            | Instr::JmpIfZero { .. }
            | Instr::SharedIf { .. }
            | Instr::SharedIfBit { .. }
            | Instr::SharedElse { .. }
            | Instr::Ret { .. }
            | Instr::Return => {}
        }
    }

    fn record(&mut self, key: Option<ExprKey>, dst: u16) {
        if let (Some(key), Some(generation)) = (key, self.reg_gen.get(usize::from(dst))) {
            self.available.insert(
                key,
                Holder {
                    reg: dst,
                    generation: *generation,
                },
            );
        }
    }

    fn kill_reg(&mut self, reg: u16) {
        if let Some(generation) = self.reg_gen.get_mut(usize::from(reg)) {
            *generation += 1;
        }
    }

    fn kill_reg_range(&mut self, start: u16, n: u32) {
        for k in 0..n {
            if let Ok(reg) = u16::try_from(u32::from(start) + k) {
                self.kill_reg(reg);
            }
        }
    }

    fn kill_dst(&mut self, dst: Dst) {
        match dst {
            Dst::Reg(reg) => self.kill_reg(reg),
            Dst::Var(Addr::Const(slot)) => self.vars.write_exact(slot),
            Dst::Signal(Addr::Const(slot)) => self.signals.write_exact(slot),
            Dst::Var(_) => self.vars.clobber(),
            Dst::Signal(_) => self.signals.clobber(),
        }
    }
}

fn is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add
            | BinOp::Mul
            | BinOp::Eq
            | BinOp::Neq
            | BinOp::BoolAnd
            | BinOp::BoolOr
            | BinOp::BitAnd
            | BinOp::BitOr
            | BinOp::BitXor
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mul(dst: u16, a: Src, b: Src) -> Instr {
        Instr::Bin {
            op: BinOp::Mul,
            dst,
            a,
            b,
        }
    }

    fn sig(slot: u32) -> Src {
        Src::Signal(Addr::Const(slot))
    }

    #[test]
    fn replaces_duplicate_computation_with_register_mov() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs, 2).unwrap();
        assert_eq!(replaced, 1);
        assert_eq!(
            out[1],
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Reg(0),
            }
        );
    }

    #[test]
    fn commutative_operands_match_in_either_order() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            mul(1, sig(1), sig(0)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs, 2).unwrap();
        assert_eq!(replaced, 1);
        assert!(matches!(
            out[1],
            Instr::Mov {
                src: Src::Reg(0),
                ..
            }
        ));
    }

    #[test]
    fn non_commutative_operand_order_does_not_match() {
        let instrs = vec![
            Instr::Bin {
                op: BinOp::Sub,
                dst: 0,
                a: sig(0),
                b: sig(1),
            },
            Instr::Bin {
                op: BinOp::Sub,
                dst: 1,
                a: sig(1),
                b: sig(0),
            },
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn signal_store_between_duplicates_prevents_reuse() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0),
            },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn exact_store_to_unrelated_slot_does_not_prevent_reuse() {
        // The canonical circom shape: every product is stored to a signal immediately.
        // A store to signal 2 must not invalidate reads of signals 0 and 1.
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(2)),
                src: Src::Reg(0),
            },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs, 2).unwrap();
        assert_eq!(replaced, 1);
        assert!(matches!(
            out[2],
            Instr::Mov {
                src: Src::Reg(0),
                ..
            }
        ));
    }

    #[test]
    fn dynamic_store_clobbers_exact_reads() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Mov {
                dst: Dst::Signal(Addr::Dynamic(0)),
                src: Src::Const(0),
            },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn exact_store_invalidates_indirect_reads() {
        let affine = Src::Signal(Addr::Affine {
            ireg: 0,
            stride: 1,
            offset: 0,
        });
        let instrs = vec![
            mul(0, affine, Src::Const(0)),
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(7)),
                src: Src::Const(0),
            },
            mul(1, affine, Src::Const(0)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn var_store_does_not_invalidate_signal_reads() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs, 2).unwrap();
        assert_eq!(replaced, 1);
        assert!(matches!(
            out[2],
            Instr::Mov {
                src: Src::Reg(0),
                ..
            }
        ));
    }

    #[test]
    fn operand_register_redefinition_prevents_reuse() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: sig(5),
            },
            mul(1, Src::Reg(0), Src::Const(0)),
            Instr::Mov {
                dst: Dst::Reg(0),
                src: sig(6),
            },
            mul(2, Src::Reg(0), Src::Const(0)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 3).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn holder_register_redefinition_prevents_reuse() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Mov {
                dst: Dst::Reg(0),
                src: sig(7),
            },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn recomputation_into_holder_register_is_dropped() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            mul(0, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs, 1).unwrap();
        assert_eq!(replaced, 1);
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], Instr::Bin { .. }));
    }

    #[test]
    fn integer_register_redefinition_invalidates_affine_operands() {
        let affine = Src::Signal(Addr::Affine {
            ireg: 0,
            stride: 1,
            offset: 0,
        });
        let instrs = vec![
            mul(0, affine, Src::Const(0)),
            Instr::IAdd {
                dst: 0,
                a: circom_mpc_vm2::isa::ISrc::Reg(0),
                b: circom_mpc_vm2::isa::ISrc::Const(1),
            },
            mul(1, affine, Src::Const(0)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn facts_do_not_cross_basic_blocks() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Jmp { target: 2 },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn output_sub_invalidates_memory_reads() {
        // OutputSub is a VM write barrier: under a shared predicate it cmux-merges
        // buffered var/signal writes before executing (and it is legal inside a shared
        // arm), so a var read before and after it may observe different values.
        let instrs = vec![
            mul(0, Src::Var(Addr::Const(0)), sig(1)),
            Instr::OutputSub {
                cmp: circom_mpc_vm2::isa::ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 5,
                n: 1,
            },
            mul(1, Src::Var(Addr::Const(0)), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 6).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn merge_barrier_invalidates_memory_reads() {
        let instrs = vec![
            mul(0, sig(0), sig(1)),
            Instr::Assert {
                cond: Src::Reg(0),
                line: 1,
            },
            mul(1, sig(0), sig(1)),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 2).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn shared_end_clears_register_only_expressions_too() {
        let instrs = vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: sig(0),
            },
            Instr::Bin {
                op: BinOp::Div,
                dst: 1,
                a: Src::Const(0),
                b: Src::Reg(0),
            },
            Instr::SharedEnd,
            Instr::Bin {
                op: BinOp::Div,
                dst: 2,
                a: Src::Const(0),
                b: Src::Reg(0),
            },
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 3).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn call_invalidates_var_and_signal_reads() {
        let instrs = vec![
            mul(0, sig(0), Src::Var(Addr::Const(0))),
            Instr::CallFn {
                fn_id: circom_mpc_vm2::isa::FnId(0),
                args_start: 0,
                args_n: 0,
                ret: 5,
                ret_n: 0,
            },
            mul(1, sig(0), Src::Var(Addr::Const(0))),
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs.clone(), 6).unwrap();
        assert_eq!(replaced, 0);
        assert_eq!(out, instrs);
    }

    #[test]
    fn neg_duplicates_are_reused() {
        let instrs = vec![
            Instr::Neg { dst: 0, a: sig(3) },
            Instr::Neg { dst: 1, a: sig(3) },
            Instr::Return,
        ];
        let (out, replaced) = eliminate_common_subexpressions(instrs, 2).unwrap();
        assert_eq!(replaced, 1);
        assert!(matches!(
            out[1],
            Instr::Mov {
                src: Src::Reg(0),
                ..
            }
        ));
    }
}
