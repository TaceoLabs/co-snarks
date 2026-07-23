//! Statement lowering: the IR buckets that appear at the top level of a template or
//! function body (as opposed to nested inside an expression — see
//! [`crate::codegen::expr`]).
//!
//! This task implements [`StoreBucket`], [`AssertBucket`], and [`LoopBucket`]; every
//! other statement kind is a `bail!` stub filled in by its own task (see the module-level
//! docs of `circom-mpc-compiler2` for the task breakdown). `Assert` is included here —
//! ahead of its own task — because it's the *only* IR shape that can carry an `Eq`
//! operator of size > 1: circom's front end lowers every `a === b`
//! (`ConstraintEquality`) straight to `AssertBucket { evaluate: ComputeBucket { op:
//! Eq(length), .. } }` regardless of array size (see the `circom` compiler's
//! `translate_constraint_equality`), so without this, this task's `EqN` lowering (see
//! [`crate::codegen::expr`]) would be unreachable by any real circuit. The lowering
//! itself is a direct port of the old stack-based compiler's `handle_assert_bucket`
//! (`circom-mpc-compiler/src/lib.rs:468-474`): dropped outright when `debug` is off,
//! otherwise its condition is lowered like any other expression and checked at runtime.
//!
//! ## Loops ([`lower_loop`])
//!
//! A `for`/`while` loop compiles to a [`LoopBucket`]: `continue_condition` is an ordinary
//! field expression, evaluated once per iteration; `body` is the loop body, with circom's
//! own front end having already desugared a `for`'s step into an ordinary `Store` at the
//! *end* of `body` (see `circom`'s `translate_while`/its `for`-to-`while` desugaring).
//!
//! Every loop lowers its `continue_condition` + a `JmpIfZero` identically (see
//! [`emit_loop_head`]/[`finish_loop`], the two paths' only shared code). What differs is
//! how the *loop variable* is addressed inside the body:
//!
//! - **Conforming** ([`detect_conforming`]): when the loop is a simple ascending counter
//!   used only as an array index, its variable is *promoted* — mirrored into a
//!   persistent integer register for the loop's extent ([`lower_conforming_loop`]). The
//!   field var slot stays authoritative (value-position reads, e.g. `sum += i`, still
//!   load it — see [`crate::codegen::expr::lower_load`]); only index-position reads
//!   resolve to `Addr::Affine` via the mirror (see
//!   [`crate::codegen::index::eval_index`]'s `folded_index_binding`). This is what makes
//!   an array access like `out[i]` inside the loop cost an affine address computation
//!   instead of a runtime `ToIndex` conversion every iteration. This is what a conforming
//!   loop falls back to when [`try_unroll_loop`] declines to unroll it (below).
//! - **Non-conforming** ([`lower_fallback_loop`]): anything else — the variable stays a
//!   plain [`Binding::FieldSlot`](crate::codegen::env::Binding::FieldSlot), and any index
//!   position using it goes through the ordinary `ToAddress`/`Instr::ToIndex`/`Dynamic`
//!   path, exactly as if no promotion logic existed at all. Semantically identical to the
//!   old stack-based VM; this is the correctness fallback for anything the conservative
//!   detector below doesn't recognize.
//!
//! ### Conformance detection is deliberately conservative
//!
//! [`detect_conforming`] only accepts the exact shape the brief specifies:
//! `continue_condition` is `Lesser(Load(Variable, k), rhs)` where `rhs` is a **constant**
//! (the brief allows "loop-invariant" more broadly — any expression with no loads of
//! vars stored inside the body — but circom monomorphizes template parameters into
//! literal constants before this crate ever sees the IR, so every KAT loop bound is
//! already a `Value`; restricting to constants keeps the detector simple without losing
//! any real coverage, confirmed by this task's KAT/end-to-end tests all exercising the
//! `Affine` path), the body's *last* top-level statement is `Store(Variable k, Add(Load(
//! Variable, k), Value(c)))` for a constant `c`, and `k` is written nowhere else in the
//! body (including recursively inside nested loop bodies — see
//! [`instruction_writes_slot`]). Anything else — most importantly, **descending loops**
//! (`Sub`-stepped) — takes the fallback path *by design*: the ISA has no `ISub`, only
//! `IAdd`/`IMul` (see `circom_mpc_vm2::isa::Instr`), so there is no mirror-update
//! instruction to emit for a decrement. Promoting descending loops would need either a
//! new ISA op or synthesizing the decrement as `IAdd` with a wrapped/negated constant —
//! deliberately left out of scope here; a real ISA change is a Plan-1-level decision, not
//! a codegen-only one.
//!
//! ### Where the persistent integer register lives
//!
//! A conforming loop's mirror register is allocated via [`CodeGen::alloc_ireg`] directly
//! inside [`lower_conforming_loop`] — not under a `mark`/`free_to` pair of its own. This
//! is safe (and required for nested loops to compose) because [`lower_stmt`] already
//! wraps *every* top-level statement — including this `LoopBucket` itself, since it's
//! just another instruction the enclosing template/function body loop or an outer loop's
//! body loop passes to [`lower_stmt`] — in exactly such a pair: the mark is taken *before*
//! [`lower_stmt_inner`] (and hence [`lower_loop`]) ever runs, so the register allocated
//! here sits *below* every mark any nested statement (including a nested `LoopBucket`,
//! with its own persistent register) takes afterwards. Freeing back to an inner mark
//! therefore never touches an outer loop's register, and the outer [`lower_stmt`]'s own
//! `free_to` — reached only once this whole loop, body included, has finished — is what
//! finally releases it. No extra bookkeeping is needed; see [`lower_stmt`]'s doc comment
//! for the general form of this discipline.
//!
//! ## Unrolling ([`try_unroll_loop`])
//!
//! A conforming loop with a statically-known bound (see [`ConformingLoop::bound`]) is a
//! candidate for a further optimization on top of mirror-`ireg` promotion: instead of
//! compiling to a loop at all, re-lower its body once per iteration with the induction
//! variable bound to [`Binding::ConstUsize`] — a plain compile-time constant. This folds
//! *every* use of the variable: index-position reads resolve straight to `Addr::Const`
//! (see [`crate::codegen::index::eval_index`]'s `folded_index_binding`), and — unlike the
//! mirrored-`ireg` rolled case — value-position reads also fold, straight to a field
//! constant (see [`crate::codegen::expr::lower_load`]), interned on demand via
//! [`CodeGen::const_id`]. No condition is evaluated, no jump is emitted, and the trailing
//! increment statement is skipped outright (its effect is exactly what the constant
//! folding for the *next* iteration already encodes).
//!
//! This only pays off when the unrolled code is small enough: [`try_unroll_loop`] computes
//! the trip count `T` ([`trip_count`]: `ceil((bound - init) / step)`, the brief's formula
//! for a `Lesser` condition), estimates one iteration's instruction count by lowering it
//! once into a scratch buffer ([`estimate_unrolled_body`]), and only commits to unrolling
//! if `estimate * T <= config.unroll.threshold` — otherwise it defers to
//! [`lower_conforming_loop`]'s rolled/mirror-promoted form, which is always correct
//! regardless of size. `threshold: 0` disables unrolling outright (skipping the estimation
//! lowering); `threshold: usize::MAX` unrolls wherever the bound is statically known,
//! however large the body.
//!
//! Nesting composes for free: re-lowering the body calls [`lower_stmt`] on each statement
//! exactly as the rolled path does, so a conforming loop nested inside an unrolling outer
//! loop makes its own independent unroll/roll decision on every outer iteration (its own
//! `detect_conforming`/[`try_unroll_loop`] call, against the same `slot`-keyed
//! [`Env`](crate::codegen::env::Env) that the outer iteration's [`Binding::ConstUsize`]
//! bind/restore pair already disciplines) — nothing about the outer loop's unrolling
//! needs to know or care whether the inner one also unrolls.
use super::env::Binding;
use super::index::static_const_slot;
use super::{CodeGen, expr, instr_kind_name};
use crate::frontend::get_size_from_size_option;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, AssertBucket, Instruction, LocationRule, LoopBucket, OperatorType, StoreBucket,
    ValueBucket, ValueType,
};
use circom_mpc_vm2::isa::{Addr, Dst, ISrc, Instr, Src};
use eyre::{Result, bail};

/// Lowers one top-level body instruction, appending to [`CodeGen::instrs`].
///
/// Integer-register scope: any `Dynamic`/`Affine` address computed while lowering `inst`
/// (see [`crate::codegen::index`]) is scoped to the *whole* statement, not to whichever
/// sub-expression happened to trigger it — a `StoreBucket`'s destination address and its
/// source expression can both need one (e.g. `a[i] <== b[j]`), and both must stay valid
/// simultaneously until every instruction referencing them has been emitted. So the
/// integer-register allocator is only rewound once, after the whole statement is done,
/// mirroring the field-register `mark`/`free_to` discipline used within a single
/// expression (see [`expr::lower_binary`]) but at statement granularity.
///
/// A [`LoopBucket`]'s persistent mirror register relies on this same discipline to
/// survive for the loop's whole extent — see [`lower_loop`]'s module-level doc comment.
pub(crate) fn lower_stmt<F: PrimeField>(cg: &mut CodeGen<'_, F>, inst: &Instruction) -> Result<()> {
    let ireg_mark = cg.iregs.mark();
    let result = lower_stmt_inner(cg, inst);
    cg.iregs.free_to(ireg_mark);
    result
}

fn lower_stmt_inner<F: PrimeField>(cg: &mut CodeGen<'_, F>, inst: &Instruction) -> Result<()> {
    match inst {
        Instruction::Store(sb) => lower_store(cg, sb),
        Instruction::Assert(ab) => lower_assert(cg, ab),
        // Mirrors the old compiler: with debug instructions disabled, logs are dropped
        // outright rather than lowered (`circom-mpc-compiler/src/lib.rs:596-611`) — so
        // only bail when they'd actually need to produce code.
        Instruction::Log(_) if !cg.config.debug => Ok(()),
        Instruction::Log(_) => bail!("not yet lowered: Log"),
        Instruction::Branch(_) => bail!("not yet lowered: Branch"),
        Instruction::Loop(lb) => lower_loop(cg, lb),
        Instruction::CreateCmp(_) => bail!("not yet lowered: CreateCmp"),
        Instruction::Call(_) => bail!("not yet lowered: Call"),
        Instruction::Return(_) => bail!("not yet lowered: Return"),
        other => bail!(
            "unexpected {} instruction in statement position",
            instr_kind_name(other)
        ),
    }
}

/// Lowers a [`StoreBucket`]: a scalar store lowers straight to [`Instr::Mov`]; an array
/// store lowers its source through [`expr::lower_expr`] (which materializes a
/// multi-element load into a register range — see [`crate::codegen::expr::lower_load`])
/// and copies out via [`Instr::StoreN`]. The destination address is resolved first (see
/// [`compute_dst`]), matching the old stack-based compiler's evaluation order.
///
/// Also updates [`CodeGen::last_const_store`] (see [`track_const_store`]) — every store
/// passes through here, top-level or nested inside a loop body, so this is the single
/// place that tracking needs to live.
fn lower_store<F: PrimeField>(cg: &mut CodeGen<'_, F>, sb: &StoreBucket) -> Result<()> {
    let size = get_size_from_size_option(&sb.context.size);
    let dst = compute_dst(cg, &sb.dest, &sb.dest_address_type)?;
    track_const_store(cg, &sb.dest_address_type, &dst, &sb.src);
    if size == 1 {
        let src = expr::lower_expr(cg, &sb.src)?;
        cg.instrs.push(Instr::Mov { dst, src });
    } else {
        let src = expr::lower_expr(cg, &sb.src)?;
        let src_reg = match src {
            Src::Reg(r) => r,
            other => {
                bail!("store of size {size} expects a materialized register source, got {other:?}")
            }
        };
        cg.instrs.push(Instr::StoreN {
            dst,
            src: src_reg,
            n: u32::try_from(size)?,
        });
    }
    Ok(())
}

/// Lowers an [`AssertBucket`]: dropped outright when `debug` is off (matching the old
/// compiler — see the module docs), otherwise its condition is lowered as an ordinary
/// expression (this is how `EqN` becomes reachable — see the module docs) and checked at
/// runtime via [`Instr::Assert`].
fn lower_assert<F: PrimeField>(cg: &mut CodeGen<'_, F>, ab: &AssertBucket) -> Result<()> {
    if !cg.config.debug {
        return Ok(());
    }
    let cond = expr::lower_expr(cg, &ab.evaluate)?;
    cg.instrs.push(Instr::Assert {
        cond,
        line: u32::try_from(ab.line)?,
    });
    Ok(())
}

/// Resolves a [`StoreBucket`]'s destination to a [`Dst`], symbolically evaluating a
/// computed index via [`expr::addr_from_location_rule`].
fn compute_dst<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    dest: &LocationRule,
    addr_ty: &AddressType,
) -> Result<Dst> {
    let addr = expr::addr_from_location_rule(cg, dest)?;
    match addr_ty {
        AddressType::Variable => Ok(Dst::Var(addr)),
        AddressType::Signal => Ok(Dst::Signal(addr)),
        AddressType::SubcmpSignal { .. } => {
            bail!("not yet lowered: subcomponent signal store (Task 8)")
        }
    }
}

/// Updates [`CodeGen::last_const_store`], the tracking [`detect_conforming`] reads to
/// find a conforming loop's induction variable's value just before the loop.
///
/// Conservative by construction: a store to a *statically-known* variable slot
/// (`dst == Dst::Var(Addr::Const(slot))`) with a plain constant source refreshes that
/// slot's tracked value; a store to a statically-known variable slot with anything else
/// as its source invalidates *that slot only*. A store whose destination address isn't
/// statically known (`Addr::Affine`/`Addr::Dynamic` — a computed array index) could,
/// for all this function can tell, land on any slot, so it conservatively clears the
/// *whole* map rather than risk leaving some other slot's stale value looking current.
/// Signal stores never touch `var` slots at all and are ignored outright.
fn track_const_store<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    addr_ty: &AddressType,
    dst: &Dst,
    src: &Instruction,
) {
    if !matches!(addr_ty, AddressType::Variable) {
        return;
    }
    let Dst::Var(Addr::Const(slot)) = dst else {
        // Computed (non-constant) destination address: conservatively assume it could
        // have overwritten anything.
        cg.last_const_store.clear();
        return;
    };
    let slot = *slot as usize;
    if let Instruction::Value(vb) = src
        && let Some(v) = const_as_u32(cg, vb)
    {
        cg.last_const_store.insert(slot, v);
        return;
    }
    cg.last_const_store.remove(&slot);
}

/// Converts a field constant [`ValueBucket`] (`parse_as == BigInt`, indexing
/// [`CodeGen::constants`]) to a `u32`, when it fits. Used only for values that end up as
/// integer-register immediates (`ISet`/`IAdd`'s `u32` payloads) — realistically always
/// small (array bounds/strides), but this is a real conversion, not an assumption, and
/// returns `None` rather than panicking if it somehow doesn't fit (the caller then
/// conservatively treats the value as unknown).
fn const_as_u32<F: PrimeField>(cg: &CodeGen<'_, F>, vb: &ValueBucket) -> Option<u32> {
    if vb.parse_as != ValueType::BigInt {
        return None;
    }
    let value = cg.constants.get(vb.value)?;
    let repr = value.into_bigint();
    let limbs = repr.as_ref();
    if limbs.iter().skip(1).any(|&limb| limb != 0) {
        return None;
    }
    u32::try_from(limbs[0]).ok()
}

/// A detected conforming loop (see [`detect_conforming`]): `slot` is the induction
/// variable's var slot, `init` its value just before the loop, `step` its per-iteration
/// increment.
struct ConformingLoop {
    /// The induction variable's var slot.
    slot: usize,
    /// The variable's value immediately before the loop.
    init: u32,
    /// The constant added to the variable each iteration.
    step: u32,
    /// The loop's constant upper bound — the `Lesser` condition's rhs — when its concrete
    /// value fits `u32`. Used only by [`trip_count`] to decide whether to unroll;
    /// conformance itself (mirror-`ireg` promotion, [`lower_conforming_loop`]) only needs
    /// the rhs to *be* a constant, not its value, so `None` here still takes the
    /// rolled/mirror path, just never the unrolled one.
    bound: Option<u32>,
}

/// Detects whether `lb` matches the conservative conforming-loop pattern (see
/// [`lower_loop`]'s module docs for the full rationale); returns `None` — take the
/// fallback path — for anything else, including descending (`Sub`-stepped) loops, which
/// are non-conforming *by design* (no `ISub` in the ISA).
fn detect_conforming<F: PrimeField>(
    cg: &CodeGen<'_, F>,
    lb: &LoopBucket,
) -> Option<ConformingLoop> {
    // `continue_condition` must be `Lesser(Load(Variable, slot), rhs)` with `rhs` a
    // constant (this task's conservative reading of "loop-invariant" — see the module
    // docs).
    let Instruction::Compute(cond_cb) = lb.continue_condition.as_ref() else {
        return None;
    };
    if cond_cb.op != OperatorType::Lesser || cond_cb.stack.len() != 2 {
        return None;
    }
    let Instruction::Load(cond_load) = cond_cb.stack[0].as_ref() else {
        return None;
    };
    if !matches!(cond_load.address_type, AddressType::Variable) {
        return None;
    }
    let LocationRule::Indexed {
        location: cond_loc, ..
    } = &cond_load.src
    else {
        return None;
    };
    let slot = static_const_slot(cond_loc)?;
    let Instruction::Value(bound_vb) = cond_cb.stack[1].as_ref() else {
        return None;
    };

    // The body's last top-level statement must be the increment:
    // `Store(Variable slot, Add(Load(Variable, slot), Value(step)))`. This is exactly
    // where circom's own `for`-to-`while` desugaring places a `for`'s step (see the
    // module docs) — a stricter-than-necessary but sufficient shape for every real KAT
    // loop this task exercises.
    let last = lb.body.last()?;
    let Instruction::Store(inc_sb) = last.as_ref() else {
        return None;
    };
    if !matches!(inc_sb.dest_address_type, AddressType::Variable) {
        return None;
    }
    let LocationRule::Indexed {
        location: inc_dest, ..
    } = &inc_sb.dest
    else {
        return None;
    };
    if static_const_slot(inc_dest)? != slot {
        return None;
    }
    let Instruction::Compute(inc_cb) = inc_sb.src.as_ref() else {
        return None;
    };
    // `Sub`-stepped (descending) loops are non-conforming by design: the ISA has no
    // `ISub`, only `IAdd`/`IMul` (see `circom_mpc_vm2::isa::Instr`), so there is no
    // mirror-update instruction available for a decrement. This is a deliberate ISA-level
    // gap, not an oversight — promoting descending loops would need a real ISA change
    // (Plan-1-level decision), not a codegen-only fix, so `op != Add` simply falls
    // through to the fallback path below.
    if inc_cb.op != OperatorType::Add || inc_cb.stack.len() != 2 {
        return None;
    }
    let Instruction::Load(inc_load) = inc_cb.stack[0].as_ref() else {
        return None;
    };
    if !matches!(inc_load.address_type, AddressType::Variable) {
        return None;
    }
    let LocationRule::Indexed {
        location: inc_load_loc,
        ..
    } = &inc_load.src
    else {
        return None;
    };
    if static_const_slot(inc_load_loc)? != slot {
        return None;
    }
    let Instruction::Value(step_vb) = inc_cb.stack[1].as_ref() else {
        return None;
    };
    let step = const_as_u32(cg, step_vb)?;

    // `slot` must be written nowhere else in the body (recursing into nested loop
    // bodies — see `instruction_writes_slot`; a nested `Branch`'s bodies aren't
    // inspected, since any loop body containing a `Branch` fails to lower regardless,
    // Branch not being implemented yet — see `lower_stmt_inner`).
    let other_writes = lb.body[..lb.body.len() - 1]
        .iter()
        .any(|inst| instruction_writes_slot(inst, slot));
    if other_writes {
        return None;
    }

    // The value of `slot` immediately before the loop must be a known constant (tracked
    // by `track_const_store` across every preceding `Store` this body has lowered so
    // far).
    let init = *cg.last_const_store.get(&slot)?;
    let bound = const_as_u32(cg, bound_vb);

    Some(ConformingLoop {
        slot,
        init,
        step,
        bound,
    })
}

/// Returns whether `inst` writes to variable slot `slot`, recursing into nested loop
/// bodies (still executed within the outer loop's iteration) but not into `Branch`/
/// `Call`/`CreateCmp` (any loop body containing one of those fails to lower regardless —
/// see [`lower_stmt_inner`] — so it's moot whether conformance is judged correctly for a
/// dead-end case).
fn instruction_writes_slot(inst: &Instruction, slot: usize) -> bool {
    match inst {
        Instruction::Store(sb) => {
            matches!(sb.dest_address_type, AddressType::Variable)
                && matches!(&sb.dest, LocationRule::Indexed { location, .. }
                    if static_const_slot(location) == Some(slot))
        }
        Instruction::Loop(inner) => inner
            .body
            .iter()
            .any(|inst| instruction_writes_slot(inst, slot)),
        _ => false,
    }
}

/// Lowers a [`LoopBucket`] (see the module docs for the overall strategy): detects
/// conformance, then dispatches to [`lower_conforming_loop`] or [`lower_fallback_loop`].
///
/// [`CodeGen::last_const_store`] is cleared both before and after: before, because
/// entering a loop body is a control-flow join — any tracking accumulated for *this*
/// loop's own conformance check must not leak into the body's lowering (a nested loop
/// inside this one must start from a clean slate); after, because the loop having run at
/// all makes every previously tracked constant stale (loops are also a control-flow join
/// from the perspective of whatever comes *after* them).
pub(crate) fn lower_loop<F: PrimeField>(cg: &mut CodeGen<'_, F>, lb: &LoopBucket) -> Result<()> {
    let conforming = detect_conforming(cg, lb);
    cg.last_const_store.clear();
    let result = match conforming {
        Some(info) => lower_conforming_or_unrolled(cg, lb, info),
        None => lower_fallback_loop(cg, lb),
    };
    cg.last_const_store.clear();
    result
}

/// Dispatches a detected-conforming loop to unrolling ([`try_unroll_loop`]) when the size
/// heuristic (module docs' "Unrolling" section) allows it, falling back to the rolled/
/// mirror-promoted form ([`lower_conforming_loop`]) otherwise.
fn lower_conforming_or_unrolled<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    lb: &LoopBucket,
    info: ConformingLoop,
) -> Result<()> {
    if try_unroll_loop(cg, lb, &info)? {
        return Ok(());
    }
    lower_conforming_loop(cg, lb, info)
}

/// The trip count `T = ceil((bound - init) / step)` of a conforming loop's `Lesser`
/// condition (see [`detect_conforming`]): `None` when the bound isn't statically known, or
/// when `step == 0` and the loop actually runs (an infinite loop already — not this
/// function's problem to make finite, and dividing by a zero step would panic).
///
/// A loop whose bound is already `<= init` never executes regardless of `step` (checked
/// first, so a `step == 0` loop that simply never runs still gets a trip count of `0`
/// rather than bailing out on the (moot) division).
fn trip_count(info: &ConformingLoop) -> Option<usize> {
    let bound = info.bound?;
    if bound <= info.init {
        return Some(0);
    }
    if info.step == 0 {
        return None;
    }
    let diff = (bound - info.init) as usize;
    let step = info.step as usize;
    Some(diff.div_ceil(step))
}

/// Estimates how many instructions one iteration of `lb`'s body — excluding its trailing
/// increment statement, which unrolling never lowers (see [`try_unroll_loop`]) — lowers to
/// when the induction variable at `slot` is bound to [`Binding::ConstUsize`], by lowering
/// it once into a scratch instruction buffer and counting.
///
/// A single representative iteration (`sample`) is enough to estimate every iteration:
/// this crate doesn't lower `Branch` yet (see [`lower_stmt_inner`]), so nothing in a loop
/// body's control flow can depend on the induction variable's concrete value — every
/// iteration lowers to the same instruction *count*, only the embedded constant operands
/// differ.
///
/// Side effects of the estimation lowering are undone before returning:
/// [`CodeGen::instrs`] is swapped out for an empty scratch buffer and restored;
/// [`CodeGen::regs`]/[`CodeGen::iregs`] (whose allocation high-water marks would otherwise
/// be inflated by register traffic that's about to be discarded, bloating the real frame
/// size) and [`CodeGen::last_const_store`] are cloned and restored; the `slot` binding is
/// restored via the usual [`Env::bind`]/[`Env::restore`] pair (mirroring
/// [`try_unroll_loop`]'s own per-iteration discipline). Interning into
/// [`CodeGen::names`]/[`CodeGen::constants`] (the latter via [`CodeGen::const_id`]) is
/// deliberately *not* rolled back — both are value-to-id caches keyed so a repeat lookup
/// (which the real lowering that follows will make anyway) returns the same id, so
/// interning early here is redundant, not a leak.
fn estimate_unrolled_body<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    lb: &LoopBucket,
    slot: usize,
    sample: usize,
) -> Result<usize> {
    let saved_instrs = std::mem::take(&mut cg.instrs);
    let saved_regs = cg.regs.clone();
    let saved_iregs = cg.iregs.clone();
    let saved_last_const_store = cg.last_const_store.clone();

    let previous_binding = cg.env.bind(slot, Binding::ConstUsize(sample));
    let last_idx = lb.body.len() - 1;
    let result = lb.body[..last_idx]
        .iter()
        .try_for_each(|inst| lower_stmt(cg, inst));
    cg.env.restore(slot, previous_binding);

    let estimate = cg.instrs.len();

    cg.instrs = saved_instrs;
    cg.regs = saved_regs;
    cg.iregs = saved_iregs;
    cg.last_const_store = saved_last_const_store;

    result?;
    Ok(estimate)
}

/// Attempts to unroll a conforming loop per the size heuristic: `threshold == 0` always
/// defers to the rolled/mirror-promoted path, skipping the estimation lowering entirely
/// (per the brief). Otherwise, if `T`, the loop's trip count ([`trip_count`]), can't be
/// determined, also defers. Otherwise, estimates one iteration's instruction count
/// ([`estimate_unrolled_body`]) and unrolls — re-lowering the body `T` times with `slot`
/// bound to [`Binding::ConstUsize`] for that iteration's concrete value, skipping the
/// trailing increment statement and emitting no condition/jump at all — only if
/// `estimate * T <= threshold`.
///
/// A single trailing `Mov` re-synchronizes the induction variable's actual field slot to
/// its final value (`init + T * step` — exactly what the rolled loop would leave behind:
/// the first value that fails the condition) once unrolling completes with `T > 0`, so any
/// code after the loop that reads the variable's real runtime value (as opposed to an
/// index-position fold, which only ever happens *inside* the loop body while `slot` is
/// bound) still sees the right answer — unrolling must be invisible to anything outside
/// the loop, not just to the values the loop body itself computes.
fn try_unroll_loop<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    lb: &LoopBucket,
    info: &ConformingLoop,
) -> Result<bool> {
    if cg.config.unroll.threshold == 0 {
        return Ok(false);
    }
    let Some(trip_count) = trip_count(info) else {
        return Ok(false);
    };

    if trip_count > 0 {
        let estimate = estimate_unrolled_body(cg, lb, info.slot, info.init as usize)?;
        let fits = estimate
            .checked_mul(trip_count)
            .is_some_and(|total| total <= cg.config.unroll.threshold);
        if !fits {
            return Ok(false);
        }
    }

    let last_idx = lb.body.len() - 1;
    for i in 0..trip_count {
        let value = info.init as usize + i * info.step as usize;
        let previous_binding = cg.env.bind(info.slot, Binding::ConstUsize(value));
        for inst in &lb.body[..last_idx] {
            lower_stmt(cg, inst)?;
        }
        cg.env.restore(info.slot, previous_binding);
    }

    if trip_count > 0 {
        let final_value = info.init as usize + trip_count * info.step as usize;
        let const_id = cg.const_id(F::from(final_value as u64))?;
        cg.instrs.push(Instr::Mov {
            dst: Dst::Var(Addr::Const(u32::try_from(info.slot)?)),
            src: Src::Const(const_id),
        });
    }

    Ok(true)
}

/// Emits the loop head shared by both the conforming and fallback paths: the
/// (already-lowered) `continue_condition`, followed by a placeholder `JmpIfZero`
/// (patched to the loop exit by [`finish_loop`] once the body's length is known — see
/// [`CodeGen::patch`]). Returns `(loop_start, jmp_idx)`.
fn emit_loop_head<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    cond: &Instruction,
) -> Result<(u32, usize)> {
    let loop_start = u32::try_from(cg.instrs.len())?;
    let cond_mark = cg.regs.mark();
    let cond_src = expr::lower_expr(cg, cond)?;
    let jmp_idx = cg.instrs.len();
    cg.instrs.push(Instr::JmpIfZero {
        cond: cond_src,
        target: u32::MAX,
    });
    cg.regs.free_to(cond_mark);
    Ok((loop_start, jmp_idx))
}

/// Emits the loop's unconditional back-edge and backpatches the head's `JmpIfZero` (see
/// [`emit_loop_head`]) to the now-known exit.
fn finish_loop<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    loop_start: u32,
    jmp_idx: usize,
) -> Result<()> {
    cg.instrs.push(Instr::Jmp { target: loop_start });
    let exit = u32::try_from(cg.instrs.len())?;
    cg.patch(jmp_idx, exit);
    Ok(())
}

/// Lowers a conforming loop: dual representation, per [`lower_loop`]'s module docs.
/// `info.slot`'s persistent mirror register survives the whole loop — see the module
/// docs' "Where the persistent integer register lives" section for why allocating it
/// here (rather than under a fresh `mark`/`free_to` pair) is exactly what nested loops
/// need.
fn lower_conforming_loop<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    lb: &LoopBucket,
    info: ConformingLoop,
) -> Result<()> {
    let ireg = cg.alloc_ireg()?;
    cg.instrs.push(Instr::ISet {
        dst: ireg,
        val: info.init,
    });

    let previous_binding = cg.env.bind(info.slot, Binding::IReg { ireg });

    let (loop_start, jmp_idx) = emit_loop_head(cg, &lb.continue_condition)?;

    // Conformance requires the increment to be the body's last statement (see
    // `detect_conforming`); emit the mirror update right there, keeping `ireg` in sync
    // with the field store the ordinary `lower_stmt` call for that same statement just
    // emitted.
    let last_idx = lb.body.len() - 1;
    for (i, inst) in lb.body.iter().enumerate() {
        lower_stmt(cg, inst)?;
        if i == last_idx {
            cg.instrs.push(Instr::IAdd {
                dst: ireg,
                a: ISrc::Reg(ireg),
                b: ISrc::Const(info.step),
            });
        }
    }

    finish_loop(cg, loop_start, jmp_idx)?;

    cg.env.restore(info.slot, previous_binding);
    Ok(())
}

/// Lowers a non-conforming loop: the variable stays a plain `FieldSlot`, so the body
/// lowers exactly as it would with no promotion logic at all (any index position using
/// the loop variable falls through `eval_index`'s `ToAddress`/`Instr::ToIndex`/`Dynamic`
/// path — see `crate::codegen::index`). Semantically identical to the old stack-based
/// VM.
fn lower_fallback_loop<F: PrimeField>(cg: &mut CodeGen<'_, F>, lb: &LoopBucket) -> Result<()> {
    let (loop_start, jmp_idx) = emit_loop_head(cg, &lb.continue_condition)?;
    for inst in lb.body.iter() {
        lower_stmt(cg, inst)?;
    }
    finish_loop(cg, loop_start, jmp_idx)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompilerConfig;

    fn cg() -> CodeGen<'static, ark_bn254::Fr> {
        let config: &'static CompilerConfig = Box::leak(Box::new(CompilerConfig::default()));
        CodeGen::new(config)
    }

    #[test]
    fn patch_rewrites_jmp_target() {
        let mut cg = cg();
        cg.instrs.push(Instr::Jmp { target: u32::MAX });
        cg.patch(0, 7);
        assert_eq!(cg.instrs[0], Instr::Jmp { target: 7 });
    }

    #[test]
    fn patch_rewrites_jmp_if_zero_target() {
        let mut cg = cg();
        cg.instrs.push(Instr::JmpIfZero {
            cond: Src::Const(0),
            target: u32::MAX,
        });
        cg.patch(0, 3);
        assert_eq!(
            cg.instrs[0],
            Instr::JmpIfZero {
                cond: Src::Const(0),
                target: 3,
            }
        );
    }

    #[test]
    #[should_panic(expected = "non-jump instruction")]
    fn patch_panics_on_non_jump_instruction() {
        let mut cg = cg();
        cg.instrs.push(Instr::Return);
        cg.patch(0, 1);
    }

    fn conforming(init: u32, bound: Option<u32>, step: u32) -> ConformingLoop {
        ConformingLoop {
            slot: 0,
            init,
            step,
            bound,
        }
    }

    #[test]
    fn trip_count_none_bound_is_undetermined() {
        assert_eq!(trip_count(&conforming(0, None, 1)), None);
    }

    #[test]
    fn trip_count_bound_already_reached_is_zero_even_with_zero_step() {
        // `bound <= init` must short-circuit to `Some(0)` before ever consulting `step`
        // (a zero step here would otherwise divide by zero).
        assert_eq!(trip_count(&conforming(5, Some(5), 0)), Some(0));
        assert_eq!(trip_count(&conforming(5, Some(3), 0)), Some(0));
    }

    #[test]
    fn trip_count_zero_step_that_would_run_is_undetermined() {
        // An infinite loop (`bound > init`, `step == 0`) has no finite trip count.
        assert_eq!(trip_count(&conforming(0, Some(5), 0)), None);
    }

    #[test]
    fn trip_count_evenly_divides() {
        assert_eq!(trip_count(&conforming(0, Some(10), 2)), Some(5));
    }

    #[test]
    fn trip_count_rounds_up() {
        // (10 - 0) / 3 = 3.33.. -> ceil to 4 (the 4th iteration's `9 < 10` still holds,
        // but its increment lands on `12`, past `bound`).
        assert_eq!(trip_count(&conforming(0, Some(10), 3)), Some(4));
    }

    #[test]
    fn trip_count_nonzero_init() {
        assert_eq!(trip_count(&conforming(2, Some(10), 4)), Some(2));
    }
}
