//! Function-call inlining: splices a small callee's already-optimized bytecode into the
//! caller in place of a `CallFn`.
//!
//! Inlining removes the per-call frame/argument overhead and — more importantly — the
//! optimization barrier a call imposes: constant propagation, var-value forwarding, and
//! common-subexpression elimination all conservatively stop at `CallFn`, but see
//! straight through spliced code (the caller's post-lowering passes run over it).
//!
//! ## When a call is inlined
//!
//! - Inlining is enabled ([`InlineConfig::threshold`] > 0) and the callee's body fits
//!   under the threshold.
//! - The call site is at branch depth zero in a body that provably never runs under a
//!   shared predicate: any template (templates start every activation with an empty
//!   predication state), or a function that no call chain reaches through a branch arm
//!   ([`compute_may_inherit`]). At such sites splicing preserves semantics exactly. A
//!   body that *may* inherit a shared predicate keeps its calls: under an inherited
//!   predicate a callee's fresh-frame semantics (frame initialization is unpredicated,
//!   buffered writes merge against clean slots, `Ret` values are read post-merge)
//!   differ observably from spliced code.
//! - The callee is not a name function accelerators bind to: accelerators intercept
//!   calls **by function name at run time**, so an inlined call would silently bypass
//!   them. Names in [`PREDEFINED_FUNCTION_ACCELERATORS`] are never inlined, and
//!   [`InlineConfig::no_inline`] lets users protect custom accelerator targets. Every
//!   `FunctionCode` also stays in the program regardless of inlining, so binding itself
//!   keeps working for the calls that remain.
//! - The callee body is shape-eligible ([`inlinable`]): a single `Ret` as its final
//!   instruction, outside every `Shared*` region (so returning is a plain fall-through
//!   — a `Ret` under a shared predicate accumulates instead of returning, which spliced
//!   code cannot replicate; balanced `Shared*` regions themselves splice fine), no
//!   dynamic var addressing (a runtime-computed slot index cannot be statically
//!   rebased), and no jump past the trailing `Ret`.
//! - The caller has register/var headroom for the callee's frame.
//!
//! ## How the splice works
//!
//! The callee's field/integer registers are rebased onto freshly reserved caller blocks
//! (statement-scoped, like any call's argument block). Its var slots are rebased onto a
//! per-body **scratch var range** starting at the caller's frontend-assigned var count:
//! inline sites never overlap in time and every site initializes the slots it uses
//! (arguments, then explicit zeroes, matching a fresh frame), so one range sized for the
//! largest inlined callee serves every site in the body. The trailing `Ret` becomes
//! `Mov`s into the callsite's `ret` register block, applying the callsite-arity
//! pad/truncate semantics the VM's `resize_ret` would.

use super::CodeGen;
use ark_ff::PrimeField;
use circom_compiler::compiler_interface::Circuit as CircomCircuit;
use circom_compiler::intermediate_representation::InstructionList;
use circom_compiler::intermediate_representation::ir_interface::Instruction;
use circom_mpc_vm2::accel::PREDEFINED_FUNCTION_ACCELERATORS;
use circom_mpc_vm2::isa::{Addr, Dst, FnId, ISrc, Instr, RetSrc, Src};
use eyre::Result;
use std::collections::HashMap;

/// Computes, per `FnId`, whether any call chain can reach the function through a branch
/// arm — the only way a function body can ever run under an inherited shared predicate
/// (templates start every activation with an empty predication state, and function
/// bodies receive their caller's by reference). Seeded by every IR call site lexically
/// inside a `Branch` arm, in any body; propagated through the function call graph until
/// stable. Conservative in the same way the force-unroll policy is: any branch may turn
/// out shared at runtime.
pub(super) fn compute_may_inherit(
    circuit: &CircomCircuit,
    fn_ids: &HashMap<String, FnId>,
) -> Vec<bool> {
    let mut may_inherit = vec![false; circuit.functions.len()];
    let mut sites: Vec<(Option<usize>, usize, bool)> = Vec::new(); // (caller fn, callee, in branch)
    for templ in &circuit.templates {
        collect_call_sites(&templ.body, false, &mut |symbol, in_branch| {
            if let Some(id) = fn_ids.get(symbol) {
                sites.push((None, id.0 as usize, in_branch));
            }
        });
    }
    for (caller, fun) in circuit.functions.iter().enumerate() {
        collect_call_sites(&fun.body, false, &mut |symbol, in_branch| {
            if let Some(id) = fn_ids.get(symbol) {
                sites.push((Some(caller), id.0 as usize, in_branch));
            }
        });
    }

    loop {
        let mut changed = false;
        for (caller, callee, in_branch) in &sites {
            let tainted = *in_branch || caller.map(|c| may_inherit[c]).unwrap_or(false);
            if tainted && !may_inherit[*callee] {
                may_inherit[*callee] = true;
                changed = true;
            }
        }
        if !changed {
            return may_inherit;
        }
    }
}

/// A callee-first (post-order) lowering order over the function call graph, so a
/// function's callees are already lowered — and thus spliceable — when its own body is
/// lowered. Circom lists callers before callees, which would otherwise defeat
/// function-into-function inlining. Cycles (recursion) are broken arbitrarily; their
/// members keep real `CallFn`s for the not-yet-lowered edges.
pub(super) fn function_lowering_order(
    circuit: &CircomCircuit,
    fn_ids: &HashMap<String, FnId>,
) -> Vec<usize> {
    let mut callees = vec![Vec::new(); circuit.functions.len()];
    for (caller, fun) in circuit.functions.iter().enumerate() {
        collect_call_sites(&fun.body, false, &mut |symbol, _| {
            if let Some(id) = fn_ids.get(symbol) {
                callees[caller].push(id.0 as usize);
            }
        });
    }

    let mut order = Vec::with_capacity(circuit.functions.len());
    // 0 = unvisited, 1 = on stack (cycle guard), 2 = done.
    let mut state = vec![0u8; circuit.functions.len()];
    for start in 0..circuit.functions.len() {
        visit(start, &callees, &mut state, &mut order);
    }
    order
}

fn visit(node: usize, callees: &[Vec<usize>], state: &mut [u8], order: &mut Vec<usize>) {
    if state[node] != 0 {
        return;
    }
    state[node] = 1;
    for &callee in &callees[node] {
        if state[callee] == 0 {
            visit(callee, callees, state, order);
        }
    }
    state[node] = 2;
    order.push(node);
}

/// Walks an IR instruction list, reporting every `Call`'s callee symbol along with
/// whether the site is lexically inside a `Branch` arm.
fn collect_call_sites(
    body: &InstructionList,
    in_branch: bool,
    report: &mut impl FnMut(&str, bool),
) {
    for inst in body {
        collect_from_instruction(inst, in_branch, report);
    }
}

fn collect_from_instruction(
    inst: &Instruction,
    in_branch: bool,
    report: &mut impl FnMut(&str, bool),
) {
    match inst {
        Instruction::Call(cb) => {
            report(&cb.symbol, in_branch);
            for arg in &cb.arguments {
                collect_from_instruction(arg, in_branch, report);
            }
        }
        Instruction::Branch(bb) => {
            collect_from_instruction(&bb.cond, in_branch, report);
            collect_call_sites(&bb.if_branch, true, report);
            collect_call_sites(&bb.else_branch, true, report);
        }
        Instruction::Loop(lb) => {
            collect_from_instruction(&lb.continue_condition, in_branch, report);
            collect_call_sites(&lb.body, in_branch, report);
        }
        Instruction::Compute(cb) => {
            for operand in &cb.stack {
                collect_from_instruction(operand, in_branch, report);
            }
        }
        Instruction::Store(sb) => collect_from_instruction(&sb.src, in_branch, report),
        Instruction::Return(rb) => collect_from_instruction(&rb.value, in_branch, report),
        Instruction::Assert(ab) => collect_from_instruction(&ab.evaluate, in_branch, report),
        Instruction::Load(_)
        | Instruction::Value(_)
        | Instruction::Log(_)
        | Instruction::CreateCmp(_) => {}
    }
}

/// Attempts to inline the call described by the `CallFn` operands. Returns `true` if
/// the callee's body was spliced (the caller must not emit the `CallFn`), `false` if
/// the call must stay a real `CallFn`.
pub(super) fn try_inline_call<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    fn_id: FnId,
    args_start: u16,
    args_n: u32,
    ret: u16,
    ret_n: u32,
) -> Result<bool> {
    if cg.config.inline.threshold == 0 || cg.branch_depth > 0 || cg.current_body_may_inherit {
        return Ok(false);
    }
    // `flatten()` also skips a not-yet-lowered callee: with the callee-first lowering
    // order that only happens for recursive cycles, which keep their calls.
    let Some(callee) = cg
        .lowered_functions
        .get(fn_id.0 as usize)
        .and_then(Option::as_ref)
    else {
        return Ok(false);
    };
    if callee.instrs.len() > cg.config.inline.threshold {
        return Ok(false);
    }
    let name = cg.names.resolve(callee.name_id);
    if PREDEFINED_FUNCTION_ACCELERATORS.contains(&name)
        || cg.config.inline.no_inline.iter().any(|n| n == name)
    {
        return Ok(false);
    }
    if !inlinable(&callee.instrs) {
        return Ok(false);
    }
    // Detach from `cg` so the splice below can mutate it; the body is bounded by the
    // inline threshold, so this clone is small.
    let callee = callee.clone();

    // Register/var headroom. Register blocks are reserved like any call's argument
    // block and released by `lower_stmt`'s statement-scoped rewind.
    let num_field_regs = u32::from(callee.num_field_regs);
    let num_int_regs = u32::from(callee.num_int_regs);
    if cg.regs.mark() + num_field_regs > u32::from(u16::MAX) + 1
        || cg.iregs.mark() + num_int_regs > u32::from(u8::MAX) + 1
    {
        return Ok(false);
    }
    let var_base = cg.inline_var_base;
    if var_base.checked_add(callee.num_vars).is_none() {
        return Ok(false);
    }

    let map = RegMap {
        freg_base: if num_field_regs == 0 {
            0
        } else {
            cg.alloc_freg_n(num_field_regs)?
        },
        ireg_base: if num_int_regs == 0 {
            0
        } else {
            u8::try_from(cg.iregs.alloc_n(num_int_regs)).expect("integer headroom checked above")
        },
        var_base,
    };
    cg.inline_scratch_vars = cg.inline_scratch_vars.max(callee.num_vars);

    // Fresh-frame initialization: arguments into vars[0..args_n], zeroes everywhere
    // else (a callee may read an unwritten var and expect circom's implicit zero).
    // Dead-store elimination removes the initializations nothing reads.
    let zero_id = cg.const_id(F::ZERO)?;
    for k in 0..callee.num_vars {
        let src = if k < args_n {
            Src::Reg(u16::try_from(u32::from(args_start) + k)?)
        } else {
            Src::Const(zero_id)
        };
        cg.instrs.push(Instr::Mov {
            dst: Dst::Var(Addr::Const(var_base + k)),
            src,
        });
    }

    // Splice the body (sans trailing Ret), rebasing registers, var slots, and jump
    // targets. `inlinable` verified every shape `remap_instr` expects.
    let callee_len = callee.instrs.len();
    let offset = u32::try_from(cg.instrs.len())?;
    let mut spliced = Vec::with_capacity(callee_len);
    for instr in &callee.instrs[..callee_len - 1] {
        spliced.push(remap_instr(instr, &map, offset));
    }
    let Instr::Ret { src, n } = callee.instrs[callee_len - 1].clone() else {
        unreachable!("inlinable() requires a trailing Ret");
    };
    cg.instrs.extend(spliced);

    // The trailing Ret becomes the callsite's arity boundary: pad with zeroes /
    // truncate exactly like the VM's resize_ret. Jumps that targeted the Ret now land
    // here, on the first materialization Mov.
    for k in 0..ret_n {
        let src = if k < n {
            match src {
                RetSrc::Reg(reg) => Src::Reg(map.freg(u16::try_from(u32::from(reg) + k)?)),
                RetSrc::Var(addr) => Src::Var(map.addr_at(addr, k)),
            }
        } else {
            Src::Const(zero_id)
        };
        cg.instrs.push(Instr::Mov {
            dst: Dst::Reg(u16::try_from(u32::from(ret) + k)?),
            src,
        });
    }

    cg.inlined_calls += 1;
    Ok(true)
}

/// Whether a callee body has the exact shape [`remap_instr`] can splice: one `Ret`,
/// last, sitting *outside* every `Shared*` region — a `Ret` under a shared predicate
/// accumulates conditional returns instead of returning, which spliced code cannot
/// replicate; a trailing `Ret` at shared depth zero, by contrast, is a plain
/// fall-through, and the callee's own balanced `SharedIf…SharedEnd` regions behave
/// identically whether their buffered writes merge against fresh frame slots or the
/// caller's (site-initialized) scratch slots. Also rejected: template-only
/// instructions (invalid in functions anyway), dynamic var addressing (a
/// runtime-computed slot index cannot be statically rebased), `Signal` operands
/// (functions cannot touch signals), and any jump past the trailing `Ret`.
fn inlinable(instrs: &[Instr]) -> bool {
    let Some((Instr::Ret { src, .. }, body)) = instrs.split_last() else {
        return false;
    };
    if matches!(src, RetSrc::Var(Addr::Dynamic(_))) {
        return false;
    }
    let last = body.len();
    let target_ok = |target: u32| target as usize <= last;
    let mut shared_depth = 0usize;
    for instr in body {
        let ok = match instr {
            Instr::Ret { .. }
            | Instr::Return
            | Instr::CreateCmp { .. }
            | Instr::InputSub { .. }
            | Instr::OutputSub { .. } => false,
            Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
                shared_depth += 1;
                target_ok(*else_target) && operands_rebasable(instr)
            }
            Instr::SharedElse { end_target } => shared_depth > 0 && target_ok(*end_target),
            Instr::SharedEnd => {
                let balanced = shared_depth > 0;
                shared_depth = shared_depth.saturating_sub(1);
                balanced
            }
            Instr::Jmp { target }
            | Instr::JmpIfZero { target, .. }
            | Instr::IJmpIfZero { target, .. } => target_ok(*target) && operands_rebasable(instr),
            _ => operands_rebasable(instr),
        };
        if !ok {
            return false;
        }
    }
    // The trailing Ret must execute at shared depth zero (regions balanced before it).
    shared_depth == 0
}

/// Whether every var operand of `instr` uses statically rebasable addressing.
fn operands_rebasable(instr: &Instr) -> bool {
    let src_ok = |src: &Src| match src {
        Src::Var(Addr::Dynamic(_)) | Src::Signal(_) => false,
        Src::Reg(_) | Src::Const(_) | Src::Var(_) => true,
    };
    let dst_ok = |dst: &Dst| match dst {
        Dst::Var(Addr::Dynamic(_)) | Dst::Signal(_) => false,
        Dst::Reg(_) | Dst::Var(_) => true,
    };
    match instr {
        Instr::Bin { a, b, .. } => src_ok(a) && src_ok(b),
        Instr::Neg { a, .. } => src_ok(a),
        Instr::EqN { a, b, .. } | Instr::BinN { a, b, .. } => src_ok(a) && src_ok(b),
        Instr::Mov { dst, src } => dst_ok(dst) && src_ok(src),
        Instr::LoadN { src, .. } => src_ok(src),
        Instr::StoreN { dst, .. } => dst_ok(dst),
        Instr::BinBatch { lanes, .. } => lanes.iter().all(|lane| {
            src_ok(&lane.a) && src_ok(&lane.b) && lane.store.as_ref().is_none_or(dst_ok)
        }),
        Instr::ToIndex { src, .. }
        | Instr::JmpIfZero { cond: src, .. }
        | Instr::SharedIf { cond: src, .. }
        | Instr::SharedIfBit { cond: src, .. }
        | Instr::Assert { cond: src, .. }
        | Instr::Log { src } => src_ok(src),
        Instr::ISet { .. }
        | Instr::IAdd { .. }
        | Instr::IMul { .. }
        | Instr::ISub { .. }
        | Instr::Jmp { .. }
        | Instr::IJmpIfZero { .. }
        | Instr::SharedElse { .. }
        | Instr::SharedEnd
        | Instr::CallFn { .. }
        | Instr::LogStr { .. }
        | Instr::LogFlush { .. } => true,
        Instr::Ret { .. }
        | Instr::Return
        | Instr::CreateCmp { .. }
        | Instr::InputSub { .. }
        | Instr::OutputSub { .. } => false,
    }
}

/// The three rebases a splice applies. All additions are guaranteed in range by the
/// headroom checks in [`try_inline_call`] plus the reserved block sizes.
struct RegMap {
    freg_base: u16,
    ireg_base: u8,
    var_base: u32,
}

impl RegMap {
    fn freg(&self, reg: u16) -> u16 {
        u16::try_from(u32::from(self.freg_base) + u32::from(reg))
            .expect("field-register headroom reserved")
    }

    fn ireg(&self, reg: u8) -> u8 {
        self.ireg_base
            .checked_add(reg)
            .expect("integer-register headroom reserved")
    }

    fn isrc(&self, src: ISrc) -> ISrc {
        match src {
            ISrc::Const(value) => ISrc::Const(value),
            ISrc::Reg(reg) => ISrc::Reg(self.ireg(reg)),
        }
    }

    fn addr(&self, addr: Addr) -> Addr {
        self.addr_at(addr, 0)
    }

    fn addr_at(&self, addr: Addr, k: u32) -> Addr {
        match addr {
            Addr::Const(slot) => Addr::Const(self.var_base + slot + k),
            Addr::Affine {
                ireg,
                stride,
                offset,
            } => Addr::Affine {
                ireg: self.ireg(ireg),
                stride,
                offset: self.var_base + offset + k,
            },
            Addr::Dynamic(_) => unreachable!("inlinable() rejects dynamic var addressing"),
        }
    }

    fn src(&self, src: Src) -> Src {
        match src {
            Src::Reg(reg) => Src::Reg(self.freg(reg)),
            Src::Const(id) => Src::Const(id),
            Src::Var(addr) => Src::Var(self.addr(addr)),
            Src::Signal(_) => unreachable!("inlinable() rejects signal operands"),
        }
    }

    fn dst(&self, dst: Dst) -> Dst {
        match dst {
            Dst::Reg(reg) => Dst::Reg(self.freg(reg)),
            Dst::Var(addr) => Dst::Var(self.addr(addr)),
            Dst::Signal(_) => unreachable!("inlinable() rejects signal operands"),
        }
    }
}

/// Rebases one callee instruction onto the caller's register/var space, shifting jump
/// targets by the splice offset. The constant and string tables are compilation-global,
/// so `Const` ids and log/assert metadata pass through unchanged.
fn remap_instr(instr: &Instr, map: &RegMap, offset: u32) -> Instr {
    match instr.clone() {
        Instr::Bin { op, dst, a, b } => Instr::Bin {
            op,
            dst: map.freg(dst),
            a: map.src(a),
            b: map.src(b),
        },
        Instr::Neg { dst, a } => Instr::Neg {
            dst: map.freg(dst),
            a: map.src(a),
        },
        Instr::EqN { dst, a, b, n } => Instr::EqN {
            dst: map.freg(dst),
            a: map.src(a),
            b: map.src(b),
            n,
        },
        Instr::Mov { dst, src } => Instr::Mov {
            dst: map.dst(dst),
            src: map.src(src),
        },
        Instr::LoadN { dst, src, n } => Instr::LoadN {
            dst: map.freg(dst),
            src: map.src(src),
            n,
        },
        Instr::StoreN { dst, src, n } => Instr::StoreN {
            dst: map.dst(dst),
            src: map.freg(src),
            n,
        },
        Instr::BinN { op, dst, a, b, n } => Instr::BinN {
            op,
            dst: map.freg(dst),
            a: map.src(a),
            b: map.src(b),
            n,
        },
        Instr::BinBatch { op, mut lanes } => {
            for lane in &mut lanes {
                lane.dst = map.freg(lane.dst);
                lane.a = map.src(lane.a);
                lane.b = map.src(lane.b);
                lane.store = lane.store.map(|store| map.dst(store));
            }
            Instr::BinBatch { op, lanes }
        }
        Instr::ISet { dst, val } => Instr::ISet {
            dst: map.ireg(dst),
            val,
        },
        Instr::IAdd { dst, a, b } => Instr::IAdd {
            dst: map.ireg(dst),
            a: map.isrc(a),
            b: map.isrc(b),
        },
        Instr::IMul { dst, a, b } => Instr::IMul {
            dst: map.ireg(dst),
            a: map.isrc(a),
            b: map.isrc(b),
        },
        Instr::ISub { dst, a, b } => Instr::ISub {
            dst: map.ireg(dst),
            a: map.isrc(a),
            b: map.isrc(b),
        },
        Instr::ToIndex { dst, src } => Instr::ToIndex {
            dst: map.ireg(dst),
            src: map.src(src),
        },
        Instr::Jmp { target } => Instr::Jmp {
            target: target + offset,
        },
        Instr::JmpIfZero { cond, target } => Instr::JmpIfZero {
            cond: map.src(cond),
            target: target + offset,
        },
        Instr::IJmpIfZero { reg, target } => Instr::IJmpIfZero {
            reg: map.ireg(reg),
            target: target + offset,
        },
        Instr::SharedIf { cond, else_target } => Instr::SharedIf {
            cond: map.src(cond),
            else_target: else_target + offset,
        },
        Instr::SharedIfBit { cond, else_target } => Instr::SharedIfBit {
            cond: map.src(cond),
            else_target: else_target + offset,
        },
        Instr::SharedElse { end_target } => Instr::SharedElse {
            end_target: end_target + offset,
        },
        Instr::SharedEnd => Instr::SharedEnd,
        Instr::CallFn {
            fn_id,
            args_start,
            args_n,
            ret,
            ret_n,
        } => Instr::CallFn {
            fn_id,
            args_start: map.freg(args_start),
            args_n,
            ret: map.freg(ret),
            ret_n,
        },
        Instr::Assert { cond, line } => Instr::Assert {
            cond: map.src(cond),
            line,
        },
        Instr::Log { src } => Instr::Log { src: map.src(src) },
        Instr::LogStr { id } => Instr::LogStr { id },
        Instr::LogFlush { line } => Instr::LogFlush { line },
        Instr::Ret { .. }
        | Instr::Return
        | Instr::CreateCmp { .. }
        | Instr::InputSub { .. }
        | Instr::OutputSub { .. } => {
            unreachable!("inlinable() rejects this instruction: {instr}")
        }
    }
}
