//! Statement lowering: the IR buckets that appear at the top level of a template or
//! function body (as opposed to nested inside an expression — see
//! [`crate::codegen::expr`]).
//!
//! This module implements [`StoreBucket`], [`AssertBucket`], [`LoopBucket`], and
//! [`BranchBucket`] lowering; every other statement kind is a `bail!` stub filled in by
//! its own task (see the module-level docs of `circom-mpc-compiler2` for the task
//! breakdown). `Assert` is included here — ahead of its own task — because it's the
//! *only* IR shape that can carry an `Eq` operator of size > 1: circom's front end lowers
//! every `a === b` (`ConstraintEquality`) straight to `AssertBucket { evaluate: ComputeBucket { op:
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
//! - **Conforming** ([`detect_conforming`]): when the loop is a simple counted counter
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
//! [`detect_conforming`] accepts ascending (`<`/`<=` plus a constant add) and descending
//! (`>`/`>=` plus a constant subtract) counters whose bound is a **constant**
//! (the brief allows "loop-invariant" more broadly — any expression with no loads of
//! vars stored inside the body — but circom monomorphizes template parameters into
//! literal constants before this crate ever sees the IR, so every KAT loop bound is
//! already a `Value`; restricting to constants keeps the detector simple without losing
//! any real coverage, confirmed by this task's KAT/end-to-end tests all exercising the
//! `Affine` path), the body's *last* top-level statement updates the same variable by a
//! constant step, and `k` is written nowhere else in the
//! body (including recursively inside nested loop bodies — see
//! [`instruction_writes_slot`]). Descending loops can be statically unrolled but still use
//! the ordinary fallback when they must remain rolled, because the integer ISA has no
//! decrement instruction.
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
//! the trip count `T` ([`trip_count`], accounting for direction and inclusive bounds),
//! estimates one iteration's instruction count by lowering it
//! once into a scratch buffer ([`estimate_unrolled_body`]), and only commits to unrolling
//! if `estimate * T <= config.unroll.threshold` — otherwise it defers to
//! [`lower_conforming_loop`]'s rolled/mirror-promoted form, which is always correct
//! regardless of size. The exception is an over-budget dependency-free elementwise loop:
//! when `T <= config.unroll.max_vectorized_loop_size`, codegen may expand it
//! speculatively and retain it only if the entire body compacts to `BinN`/`StoreN` pairs;
//! otherwise the expansion is rolled back. `threshold: 0` disables both ordinary
//! unrolling and this vectorization bypass; `threshold: usize::MAX` unrolls wherever the
//! bound is statically known, however large the body.
//!
//! A loop nested in a branch is special: the branch condition may be shared, so emitting
//! a data-dependent jump would either leak the condition or attempt to branch on a share.
//! Such loops are therefore required to have a statically known finite trip count and are
//! force-unrolled regardless of the ordinary size threshold. Unsupported data-dependent
//! branch-local loops fail during compilation rather than later during MPC execution.
//!
//! Nesting composes for free: re-lowering the body calls [`lower_stmt`] on each statement
//! exactly as the rolled path does, so a conforming loop nested inside an unrolling outer
//! loop makes its own independent unroll/roll decision on every outer iteration (its own
//! `detect_conforming`/[`try_unroll_loop`] call, against the same `slot`-keyed
//! [`Env`](crate::codegen::env::Env) that the outer iteration's [`Binding::ConstUsize`]
//! bind/restore pair already disciplines) — nothing about the outer loop's unrolling
//! needs to know or care whether the inner one also unrolls.
//!
//! ## Branches ([`lower_branch`])
//!
//! An `if`/`else` compiles to a [`BranchBucket`]; see [`lower_branch`]'s own doc comment
//! for the two instruction layouts (with and without an `else`) and the else-less
//! `SharedElse`-elision obligation. Unlike loops, there is no public/shared split at
//! *codegen* time: the target ISA's `Instr::SharedIf`/`SharedElse`/`SharedEnd` (see
//! `circom_mpc_vm2::isa`) defer that decision to the VM at runtime, so lowering a branch
//! needs no knowledge of whether its condition turns out to be public or shared. Nested
//! branches and loops compose through ordinary recursion — a `Branch` in a loop body (or
//! vice versa) is just another top-level statement handed to [`lower_stmt`] — with two
//! places that had to become explicitly `Branch`-aware to stay sound now that a loop body
//! can contain one: [`instruction_writes_slot`] (a conditional store to the induction
//! variable inside either arm makes the enclosing loop non-conforming, exactly like an
//! unconditional one would) and [`lower_branch`]'s own [`CodeGen::last_const_store`]
//! handling (a constant tracked while lowering one arm must not be trusted as the
//! definite value once the branch has been lowered, since which arm actually ran at
//! runtime is unknowable at compile time — see [`lower_branch`]'s doc comment for the
//! join discipline, which mirrors [`lower_loop`]'s own before/after clears).
use super::env::Binding;
use super::index::{self, static_const_slot};
use super::{CodeGen, expr, instr_kind_name};
use crate::frontend::get_size_from_size_option;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, AssertBucket, BranchBucket, CallBucket, CreateCmpBucket, Instruction,
    LocationRule, LogBucket, LogBucketArg, LoopBucket, OperatorType, ReturnBucket, ReturnType,
    StoreBucket, ValueBucket, ValueType,
};
use circom_mpc_vm2::isa::{Addr, BinOp, Dst, ISrc, Instr, RetSrc, Src};
use eyre::{Result, bail, eyre};

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
///
/// Field-register scope: mirrors the integer-register discipline above, one level up.
/// Sub-expression lowering already frees an operand's own registers back to a per-
/// expression mark before allocating its result (see [`expr::lower_binary`]), which keeps
/// a *single expression*'s frame bounded by its depth — but the *top-level* result
/// register that expression hands back (e.g. a `StoreBucket`'s materialized source, or a
/// `Call`'s arg/ret block) is only ever consumed by the one instruction that follows in
/// this same statement, never read again afterwards. Without rewinding here too, every
/// statement's top-level result register would stay permanently allocated, so
/// `num_field_regs` would grow with the body's *length* instead of its maximum
/// expression width. `mark`/`free_to` wrap `lower_stmt_inner` as one unit, so nested
/// `lower_stmt` recursion (branch arms, loop bodies, the unroll re-lowering/estimation
/// passes) composes LIFO exactly like the `iregs` pair does — an inner statement's
/// `free_to` never reaches below its own `mark`, so it can't release any register an
/// outer, still-in-progress statement is holding onto (e.g. [`lower_conforming_loop`]'s
/// persistent mirror `ireg`, which lives in `iregs` anyway and is untouched by this pair;
/// no analogous persistent *field* register exists anywhere in this module).
pub(crate) fn lower_stmt<F: PrimeField>(cg: &mut CodeGen<'_, F>, inst: &Instruction) -> Result<()> {
    let ireg_mark = cg.iregs.mark();
    let reg_mark = cg.regs.mark();
    let result = lower_stmt_inner(cg, inst);
    cg.iregs.free_to(ireg_mark);
    cg.regs.free_to(reg_mark);
    result
}

fn lower_stmt_inner<F: PrimeField>(cg: &mut CodeGen<'_, F>, inst: &Instruction) -> Result<()> {
    match inst {
        Instruction::Store(sb) => lower_store(cg, sb),
        Instruction::Assert(ab) => lower_assert(cg, ab),
        Instruction::Log(lb) => lower_log(cg, lb),
        Instruction::Branch(bb) => lower_branch(cg, bb),
        Instruction::Loop(lb) => lower_loop(cg, lb),
        Instruction::CreateCmp(cb) => lower_create_cmp(cg, cb),
        Instruction::Call(cb) => lower_call(cg, cb),
        Instruction::Return(rb) => lower_return(cg, rb),
        other => bail!(
            "unexpected {} instruction in statement position",
            instr_kind_name(other)
        ),
    }
}

/// Lowers a [`StoreBucket`]: a scalar store lowers straight to [`Instr::Mov`]; an array
/// store lowers its source through [`expr::lower_expr`] (which materializes a
/// multi-element load into a register range — see [`crate::codegen::expr::lower_load`])
/// and copies out via [`Instr::StoreN`]. The source is lowered *before* the destination
/// address (see [`compute_dst`]), matching the old stack-based compiler's evaluation
/// order (`circom-mpc-compiler`'s `handle_store_bucket` pushes the source's opcodes
/// first, the destination-address opcodes second, only then the `Store*` opcode that
/// consumes both) — this stayed purely academic through Task 6 (no bucket lowered here
/// could yet have a side effect for the order to matter), but Task 7's `CallBucket`
/// lowering means a source expression could in principle hide a side-effecting call;
/// see [`lower_call`]'s doc comment for why that particular risk doesn't actually
/// materialize (a call can never appear nested inside a `StoreBucket`'s `src`, or inside
/// an index sub-tree, under this crate's supported IR shapes) — this ordering is kept
/// matching old regardless, since it costs nothing and removes the question entirely
/// rather than resting on that argument.
///
/// Also updates [`CodeGen::last_const_store`] (see [`track_const_store`]) — every store
/// passes through here, top-level or nested inside a loop body, so this is the single
/// place that tracking needs to live.
fn lower_store<F: PrimeField>(cg: &mut CodeGen<'_, F>, sb: &StoreBucket) -> Result<()> {
    let size = get_size_from_size_option(&sb.context.size);
    let src = expr::lower_expr(cg, &sb.src)?;
    if let AddressType::SubcmpSignal {
        cmp_address,
        is_output,
        ..
    } = &sb.dest_address_type
    {
        debug_assert!(
            !is_output,
            "a store's destination must never be a subcomponent *output* signal"
        );
        return lower_store_subcmp(cg, cmp_address, &sb.dest, src, size);
    }
    let dst = compute_dst(cg, &sb.dest, &sb.dest_address_type)?;
    track_const_store(cg, &sb.dest_address_type, &dst, &sb.src);
    if size == 1 {
        cg.instrs.push(Instr::Mov { dst, src });
    } else {
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

/// Lowers a store to a subcomponent's input signal (`AddressType::SubcmpSignal`, old
/// `emit_store_opcodes`'s `SubcmpSignal` arm, old :276-285): unlike `Signal`/`Var`, there's
/// no `Dst` addressing mode for this — [`Instr::InputSub`] always writes from a plain
/// register, so a `src` that isn't already one (e.g. a bare constant, or a size-1 signal/var
/// read that never allocated a register) is materialized into a fresh one first; a
/// multi-element `src` is always already `Src::Reg` (materialized by [`expr::lower_expr`]'s
/// own array-load path), same as the ordinary `StoreN` case above.
///
/// `n` is `size` here, not `context_size` under some other name — this crate's `StoreBucket`
/// only ever has the one `context.size` (the value this function's caller already computed),
/// matching what `Instr::InputSub`'s docs call `n`.
fn lower_store_subcmp<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    cmp_address: &Instruction,
    dest: &LocationRule,
    src: Src,
    size: usize,
) -> Result<()> {
    let (addr, mapped) = index::eval_subcmp_location(cg, dest)?;
    let cmp = index::eval_index(cg, cmp_address)?.to_isrc(cg)?;
    let src = materialize_reg(cg, src)?;
    cg.instrs.push(Instr::InputSub {
        cmp,
        addr,
        mapped,
        src,
        n: u32::try_from(size)?,
    });
    Ok(())
}

/// Materializes `src` into a plain field register if it isn't already one — used wherever
/// the ISA wants a bare `u16` register (not the richer [`Src`] enum), such as
/// [`Instr::InputSub`]'s `src` field.
fn materialize_reg<F: PrimeField>(cg: &mut CodeGen<'_, F>, src: Src) -> Result<u16> {
    match src {
        Src::Reg(r) => Ok(r),
        other => {
            let dst = cg.alloc_freg()?;
            cg.instrs.push(Instr::Mov {
                dst: Dst::Reg(dst),
                src: other,
            });
            Ok(dst)
        }
    }
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

/// Lowers a [`LogBucket`] (old `handle_log_bucket`, `circom-mpc-compiler/src/lib.rs:
/// 596-611`): dropped outright when `debug` is off, exactly like [`lower_assert`] — old's
/// own `handle_log_bucket` never even reaches its `for` loop over `argsprint` in that case,
/// so this crate mirrors that by returning early rather than lowering (and then discarding)
/// every argument. When `debug` is on, each [`LogBucketArg`] lowers independently — a
/// `LogExp` as an ordinary expression, immediately followed by [`Instr::Log`] to append its
/// value to the runtime log buffer; a `LogStr` needs no expression lowering at all, just
/// [`Instr::LogStr`] with its string-table index straight through (the table itself is
/// already threaded into [`circom_mpc_vm2::program::CompiledProgram::strings`] by
/// `codegen::mod`'s `c_producer.get_string_table()` — see that module) — before a single
/// trailing [`Instr::LogFlush`] flushes the accumulated buffer, tagged with the bucket's
/// source line.
fn lower_log<F: PrimeField>(cg: &mut CodeGen<'_, F>, lb: &LogBucket) -> Result<()> {
    if !cg.config.debug {
        return Ok(());
    }
    for arg in &lb.argsprint {
        match arg {
            LogBucketArg::LogExp(exp) => {
                let src = expr::lower_expr(cg, exp)?;
                cg.instrs.push(Instr::Log { src });
            }
            LogBucketArg::LogStr(idx) => {
                cg.instrs.push(Instr::LogStr {
                    id: u32::try_from(*idx)?,
                });
            }
        }
    }
    cg.instrs.push(Instr::LogFlush {
        line: u32::try_from(lb.line)?,
    });
    Ok(())
}

/// Lowers a [`ReturnBucket`] (old `handle_return_bucket`, `circom-mpc-compiler/src/lib.rs:
/// 476-503`) to [`Instr::Ret`]: this is only ever reached inside a function body (a
/// template's `body` never contains one — circom's front end only emits `Return`
/// buckets, [`Instruction::Return`], for functions, matching the old compiler's own
/// `Return`/`ReturnFun` split), so no template-vs-function check is needed here — the
/// target ISA's own `Ret`/`Return` split is enforced at *runtime* by `circom_mpc_vm2::
/// exec::Machine::step`'s `StepCtx` instead.
///
/// `with_size == 1`: the value is lowered as an ordinary expression; if that already
/// resolves to a var-slot address ([`Src::Var`], a bare variable load with no
/// computation), the address passes straight through as [`RetSrc::Var`] with no extra
/// instruction (functions never see [`Src::Signal`] — they cannot read circuit signals
/// at all); anything else (a computed [`Src::Reg`], or a literal [`Src::Const`], which
/// gets one `Mov` to materialize it into a register first) becomes [`RetSrc::Reg`].
///
/// `with_size > 1`: the value is always a `Load` of a variable array (old's own
/// `panic!("Another way for multiple return vals???")` on anything else, old :494-500,
/// confirms the front end never produces another shape) — this crate evaluates its
/// address through the ordinary symbolic evaluator ([`index::eval_index`]) instead of
/// the old compiler's panicky match-and-unwrap chain (old :482-491), which additionally
/// means a computed (`Dynamic`) return-array address is supported here, not just a
/// literal slot.
fn lower_return<F: PrimeField>(cg: &mut CodeGen<'_, F>, rb: &ReturnBucket) -> Result<()> {
    if rb.with_size == 1 {
        let src = expr::lower_expr(cg, &rb.value)?;
        let ret_src = match src {
            Src::Var(addr) => RetSrc::Var(addr),
            Src::Reg(r) => RetSrc::Reg(r),
            Src::Const(_) => {
                let dst = cg.alloc_freg()?;
                cg.instrs.push(Instr::Mov {
                    dst: Dst::Reg(dst),
                    src,
                });
                RetSrc::Reg(dst)
            }
            Src::Signal(_) => {
                bail!("function return of a signal value (functions cannot read signals)")
            }
        };
        cg.instrs.push(Instr::Ret { src: ret_src, n: 1 });
        return Ok(());
    }

    let Instruction::Load(load_bucket) = rb.value.as_ref() else {
        bail!(
            "multi-value return (with_size={}) expects a Load, got {}",
            rb.with_size,
            instr_kind_name(&rb.value)
        );
    };
    if !matches!(load_bucket.address_type, AddressType::Variable) {
        bail!("multi-value return expects a Variable load, got a non-Variable load");
    }
    let LocationRule::Indexed { location, .. } = &load_bucket.src else {
        bail!("multi-value return expects an Indexed location, got Mapped");
    };
    let addr = index::eval_index(cg, location)?.to_addr();
    cg.instrs.push(Instr::Ret {
        src: RetSrc::Var(addr),
        n: u32::try_from(rb.with_size)?,
    });
    Ok(())
}

/// Lowers a [`CallBucket`] (old `handle_call_bucket`, `circom-mpc-compiler/src/lib.rs:
/// 505-594`): every argument is evaluated into a fresh, consecutive register block
/// (`args_start..args_start+args_n`, reserved atomically via
/// [`CodeGen::alloc_freg_n`]) — see [`lower_call_arg`] for how each argument (scalar or
/// array) lands in its slot; this contiguous-block-up-front approach is what replaces
/// the old compiler's last-opcode-patching hack (old :514-535), which instead lowered
/// each argument generically and then rewrote whichever single-element load opcode that
/// had just emitted into its multi-element counterpart in place.
///
/// `Instr::CallFn` follows, then the results are stored: a `SubcmpSignal` destination goes
/// through `Instr::InputSub` (mirroring [`lower_store_subcmp`] — `ret`, already a plain
/// register block, is used directly as `InputSub`'s `src`, no extra materialization
/// needed); anything else uses the ordinary [`compute_dst`]/`Instr::Mov`/`Instr::StoreN`
/// path — exactly like [`lower_store`], just fed from the call's freshly allocated `ret`
/// register block instead of an arbitrary expression.
///
/// `ReturnType::Intermediate` (a call used as an operand *inside* another expression,
/// e.g. `f(a) + 1`) is old's own `todo!()` (`circom-mpc-compiler/src/lib.rs:537`) — this
/// crate keeps that parity and bails with a clear message instead of panicking. This is
/// also what makes [`lower_store`]'s src-before-dst evaluation-order question moot for
/// now: with `Intermediate` unsupported, a `Call` can never appear nested inside
/// another bucket's expression tree at all — [`expr::lower_expr`] and
/// [`index::eval_index`] both have no `Call` match arm (see their trailing `bail!`s), so
/// any attempt to embed one would already fail to lower, rather than silently lowering
/// in the wrong order. A `Call` is therefore always its own top-level statement, args
/// and destination store fully self-contained within this one function.
fn lower_call<F: PrimeField>(cg: &mut CodeGen<'_, F>, cb: &CallBucket) -> Result<()> {
    let fn_id = *cg
        .fn_ids
        .get(&cb.symbol)
        .ok_or_else(|| eyre!("call to unknown function {:?}", cb.symbol))?;

    let sizes: Vec<usize> = cb
        .argument_types
        .iter()
        .map(|t| get_size_from_size_option(&t.size))
        .collect();
    let args_n: usize = sizes.iter().sum();
    let args_n_u32 = u32::try_from(args_n)?;
    let args_start = cg.alloc_freg_n(args_n_u32)?;

    let mut offset: u32 = 0;
    for (arg_inst, &size) in cb.arguments.iter().zip(sizes.iter()) {
        let dst_reg = u16::try_from(u32::from(args_start) + offset)?;
        lower_call_arg(cg, arg_inst, size, dst_reg)?;
        offset += u32::try_from(size)?;
    }

    let final_data = match &cb.return_info {
        ReturnType::Intermediate { .. } => bail!(
            "not yet lowered: function call used as an intermediate expression value \
             (old compiler parity: this is a todo!() there too)"
        ),
        ReturnType::Final(final_data) => final_data,
    };
    let ret_n = get_size_from_size_option(&final_data.context.size);
    let ret_n_u32 = u32::try_from(ret_n)?;
    let ret = cg.alloc_freg_n(ret_n_u32)?;

    cg.instrs.push(Instr::CallFn {
        fn_id,
        args_start,
        args_n: args_n_u32,
        ret,
        ret_n: ret_n_u32,
    });

    if let AddressType::SubcmpSignal {
        cmp_address,
        is_output,
        ..
    } = &final_data.dest_address_type
    {
        debug_assert!(
            !is_output,
            "a call's destination must never be a subcomponent *output* signal"
        );
        let (addr, mapped) = index::eval_subcmp_location(cg, &final_data.dest)?;
        let cmp = index::eval_index(cg, cmp_address)?.to_isrc(cg)?;
        cg.instrs.push(Instr::InputSub {
            cmp,
            addr,
            mapped,
            src: ret,
            n: ret_n_u32,
        });
        return Ok(());
    }

    let dst = compute_dst(cg, &final_data.dest, &final_data.dest_address_type)?;
    if ret_n == 1 {
        cg.instrs.push(Instr::Mov {
            dst,
            src: Src::Reg(ret),
        });
    } else {
        cg.instrs.push(Instr::StoreN {
            dst,
            src: ret,
            n: ret_n_u32,
        });
    }
    Ok(())
}

/// Lowers one [`CallBucket`] argument into `dst_reg` (a slot in the contiguous
/// `args_start..args_start+args_n` block — see [`lower_call`]): a scalar (`size == 1`)
/// argument lowers through the ordinary expression path and one `Mov` (this already
/// handles a subcomponent-signal argument correctly — [`expr::lower_expr`]'s `Load` path
/// materializes it via `Instr::OutputSub` like any other consumer, so no special case is
/// needed here for `size == 1`); a `size > 1` argument is always an array `Load` in
/// circom's IR (there is no array-valued arithmetic to produce anything else), so its
/// address is read directly via `Instr::LoadN` straight into the block — no intermediate
/// register range, unlike the generic [`expr::lower_load`]'s `materialize` — except for a
/// subcomponent signal, which has no addressing mode `LoadN` could use at all and instead
/// reads straight into `dst_reg` via `Instr::OutputSub` (mirroring [`expr::
/// lower_load_subcmp`], just writing directly into the caller-supplied register instead of
/// a freshly allocated one).
fn lower_call_arg<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    inst: &Instruction,
    size: usize,
    dst_reg: u16,
) -> Result<()> {
    if size == 1 {
        let src = expr::lower_expr(cg, inst)?;
        cg.instrs.push(Instr::Mov {
            dst: Dst::Reg(dst_reg),
            src,
        });
        return Ok(());
    }
    let Instruction::Load(lb) = inst else {
        bail!(
            "call argument of size {size} expects an array Load, got {}",
            instr_kind_name(inst)
        );
    };
    if let AddressType::SubcmpSignal { cmp_address, .. } = &lb.address_type {
        let (addr, mapped) = index::eval_subcmp_location(cg, &lb.src)?;
        let cmp = index::eval_index(cg, cmp_address)?.to_isrc(cg)?;
        cg.instrs.push(Instr::OutputSub {
            cmp,
            addr,
            mapped,
            dst: dst_reg,
            n: u32::try_from(size)?,
        });
        return Ok(());
    }
    let addr = expr::addr_from_location_rule(cg, &lb.src)?;
    let src = match lb.address_type {
        AddressType::Signal => Src::Signal(addr),
        AddressType::Variable => Src::Var(addr),
        AddressType::SubcmpSignal { .. } => unreachable!("handled above"),
    };
    cg.instrs.push(Instr::LoadN {
        dst: dst_reg,
        src,
        n: u32::try_from(size)?,
    });
    Ok(())
}

/// Lowers a [`CreateCmpBucket`] (old `handle_create_cmp_bucket`, old :431-438) to
/// [`Instr::CreateCmp`]: every field is already a compile-time constant in the bucket
/// itself (`symbol`/`number_of_cmp`/`signal_offset`/`signal_offset_jump`), matching old's
/// own `PushIndex`-of-constants emission — no address evaluation needed here at all, unlike
/// `Load`/`Store`'s `SubcmpSignal` handling. `templ` resolves through [`CodeGen::templ_ids`],
/// keyed by the bucket's own `symbol` (its monomorphized template header), exactly like a
/// `CallBucket`'s `symbol` resolves through [`CodeGen::fn_ids`] (see [`lower_call`]).
fn lower_create_cmp<F: PrimeField>(cg: &mut CodeGen<'_, F>, cb: &CreateCmpBucket) -> Result<()> {
    let templ = *cg
        .templ_ids
        .get(&cb.symbol)
        .ok_or_else(|| eyre!("CreateCmp references unknown template {:?}", cb.symbol))?;
    cg.instrs.push(Instr::CreateCmp {
        templ,
        count: u32::try_from(cb.number_of_cmp)?,
        base: u32::try_from(cb.signal_offset)?,
        jump: u32::try_from(cb.signal_offset_jump)?,
    });
    Ok(())
}

/// Lowers a [`BranchBucket`] (an `if`/`else if`/`else` chain — circom's front end
/// desugars an `else if` into a nested `Branch` inside the outer one's `else_branch`, so
/// no special handling for chains is needed here): the layout mirrors the old
/// stack-based compiler's `handle_branch_bucket` (`circom-mpc-compiler/src/lib.rs:
/// 451-466`) at the *source*-semantics level, but the target ISA does the runtime
/// public-vs-shared dispatch itself (see `circom_mpc_vm2::isa::Instr`'s
/// `SharedIf`/`SharedElse`/`SharedEnd` docs), so this lowering only needs to emit one of
/// the two layouts below and backpatch their targets (see [`CodeGen::patch`]) — no
/// separate "is this condition shared" check at codegen time.
///
/// With an else branch:
/// ```text
///    <cond>  → r
///    SharedIf  { r, else_target: E }
///    <truthy>
///    SharedElse { end_target: X }
/// E: <falsy>
/// X: SharedEnd
/// ```
///
/// Without an else branch — **no `SharedElse` is emitted at all** (`branch_bucket.
/// else_branch` is simply an empty `InstructionList`, not a synthesized empty block — a
/// direct read of circom's own IR): `else_target` points straight at `SharedEnd`,
/// eliding the whole `SharedElse` instruction. This is a Plan-1 obligation, not a
/// cosmetic shortcut: a shared condition otherwise costs one extra Rep3 communication
/// round toggling predication to run a no-op falsy arm.
/// ```text
///    <cond> → r
///    SharedIf { r, else_target: X }
///    <truthy>
/// X: SharedEnd
/// ```
///
/// Also a control-flow join for [`CodeGen::last_const_store`], mirroring [`lower_loop`]'s
/// own before/after clears (see its doc comment): whichever arm actually runs at runtime
/// is unknowable at compile time, so (1) tracking accumulated while lowering the truthy
/// arm must not leak into the falsy arm's lowering — reset to the pre-branch snapshot
/// before lowering it — and (2) nothing tracked by *either* arm can be trusted once both
/// are done, so the map is cleared unconditionally on exit regardless of whether there
/// even was a falsy arm (the truthy arm alone might not have run either).
fn lower_branch<F: PrimeField>(cg: &mut CodeGen<'_, F>, bb: &BranchBucket) -> Result<()> {
    let cond_mark = cg.regs.mark();
    let cond = expr::lower_expr(cg, &bb.cond)?;
    let if_idx = cg.instrs.len();
    let branch = if expr::is_known_bit(&bb.cond) {
        Instr::SharedIfBit {
            cond,
            else_target: u32::MAX,
        }
    } else {
        Instr::SharedIf {
            cond,
            else_target: u32::MAX,
        }
    };
    cg.instrs.push(branch);
    cg.regs.free_to(cond_mark);

    let pre_branch_const_store = cg.last_const_store.clone();
    lower_branch_arm(cg, &bb.if_branch)?;

    if bb.else_branch.is_empty() {
        // Else-less elision (see the doc comment above): `else_target` points straight at
        // `SharedEnd` — no `SharedElse` in the instruction stream at all.
        let end_target = u32::try_from(cg.instrs.len())?;
        cg.patch(if_idx, end_target);
        cg.instrs.push(Instr::SharedEnd);
    } else {
        let else_idx = cg.instrs.len();
        cg.instrs.push(Instr::SharedElse {
            end_target: u32::MAX,
        });
        let else_target = u32::try_from(cg.instrs.len())?;
        cg.patch(if_idx, else_target);

        // Control-flow join, part 1: the falsy arm must start lowering from the same
        // tracking state the truthy arm did, not from whatever the truthy arm's own
        // stores left behind.
        cg.last_const_store = pre_branch_const_store;
        lower_branch_arm(cg, &bb.else_branch)?;

        let end_target = u32::try_from(cg.instrs.len())?;
        cg.patch(else_idx, end_target);
        cg.instrs.push(Instr::SharedEnd);
    }

    // Control-flow join, part 2: neither arm is guaranteed to have run, so nothing either
    // one tracked can be trusted afterwards.
    cg.last_const_store.clear();
    Ok(())
}

fn lower_branch_arm<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    arm: &[Box<Instruction>],
) -> Result<()> {
    cg.branch_depth += 1;
    let result = arm.iter().try_for_each(|inst| lower_stmt(cg, inst));
    cg.branch_depth -= 1;
    result
}

/// Resolves a [`StoreBucket`]'s (or a [`CallBucket`]'s result's) destination to a [`Dst`],
/// symbolically evaluating a computed index via [`expr::addr_from_location_rule`]. Both
/// callers ([`lower_store`]/[`lower_call`]) intercept a `SubcmpSignal` destination before
/// ever reaching here — [`Instr::InputSub`] has no `Dst`-shaped addressing mode at all (see
/// [`lower_store_subcmp`]) — so the `SubcmpSignal` arm is unreachable in practice.
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
            unreachable!("callers intercept a SubcmpSignal destination before compute_dst")
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
    /// The constant step magnitude applied to the variable each iteration.
    step: u32,
    /// Whether the counter increases toward the bound or decreases toward it.
    direction: LoopDirection,
    /// Whether equality with the bound still executes one iteration (`<=`/`>=`).
    inclusive: bool,
    /// The loop's constant bound — the comparison's rhs — when its concrete value fits
    /// `u32`. Used only by [`trip_count`] to decide whether to unroll;
    /// conformance itself (mirror-`ireg` promotion, [`lower_conforming_loop`]) only needs
    /// the rhs to *be* a constant, not its value, so `None` here still takes the
    /// rolled/mirror path, just never the unrolled one.
    bound: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoopDirection {
    Ascending,
    Descending,
}

/// Detects whether `lb` matches the conservative statically-counted loop pattern (see
/// [`lower_loop`]'s module docs for the full rationale); returns `None` for anything else.
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
    let (direction, inclusive) = match cond_cb.op {
        OperatorType::Lesser => (LoopDirection::Ascending, false),
        OperatorType::LesserEq => (LoopDirection::Ascending, true),
        OperatorType::Greater => (LoopDirection::Descending, false),
        OperatorType::GreaterEq => (LoopDirection::Descending, true),
        _ => return None,
    };
    if cond_cb.stack.len() != 2 {
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
    let expected_step_op = match direction {
        LoopDirection::Ascending => OperatorType::Add,
        LoopDirection::Descending => OperatorType::Sub,
    };
    if inc_cb.op != expected_step_op || inc_cb.stack.len() != 2 {
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

    // `slot` must be written nowhere else in the body (recursing into nested loop bodies
    // *and* both arms of any nested `Branch` — see `instruction_writes_slot`: a loop whose
    // body conditionally re-stores its own induction variable inside an `if`/`else` is
    // non-conforming, exactly like an unconditional extra store would be, since which arm
    // runs — and hence whether the extra store happens — isn't known until runtime).
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
        direction,
        inclusive,
        bound,
    })
}

/// Returns whether `inst` writes to variable slot `slot`, recursing into nested loop
/// bodies (still executed within the outer loop's iteration) and into *both* arms of a
/// nested `Branch` (a store to `slot` inside either arm is a potential write to it —
/// conservatively "writes" regardless of which arm actually runs at runtime, since that's
/// unknowable at compile time) but not into `Call`/`CreateCmp` (any loop body containing
/// one of those fails to lower regardless — see [`lower_stmt_inner`] — so it's moot
/// whether conformance is judged correctly for a dead-end case).
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
        Instruction::Branch(bb) => {
            bb.if_branch
                .iter()
                .any(|inst| instruction_writes_slot(inst, slot))
                || bb
                    .else_branch
                    .iter()
                    .any(|inst| instruction_writes_slot(inst, slot))
        }
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
        None if cg.branch_depth > 0 => bail!(
            "loop inside a potentially shared branch must be a statically counted ascending or descending loop"
        ),
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
    let must_have_fixed_schedule = cg.branch_depth > 0;
    if try_unroll_loop(cg, lb, &info, must_have_fixed_schedule)? {
        return Ok(());
    }
    if must_have_fixed_schedule {
        bail!(
            "loop inside a potentially shared branch must have a statically known finite trip count"
        );
    }
    if info.direction == LoopDirection::Descending {
        return lower_fallback_loop(cg, lb);
    }
    lower_conforming_loop(cg, lb, info)
}

/// The finite trip count of a conforming ascending/descending loop (see
/// [`detect_conforming`]): `None` when the bound isn't statically known, or when
/// `step == 0` and the loop actually runs.
///
/// Strict and inclusive comparisons are handled separately so `<`/`>` use ceiling
/// division while `<=`/`>=` include the iteration exactly on the bound.
fn trip_count(info: &ConformingLoop) -> Option<usize> {
    let bound = info.bound?;
    if info.step == 0 {
        let executes = match info.direction {
            LoopDirection::Ascending => info.init < bound || (info.inclusive && info.init == bound),
            LoopDirection::Descending => {
                info.init > bound || (info.inclusive && info.init == bound)
            }
        };
        return if executes { None } else { Some(0) };
    }
    let step = info.step as usize;
    match info.direction {
        LoopDirection::Ascending => {
            if info.init > bound || (!info.inclusive && info.init == bound) {
                return Some(0);
            }
            let diff = (bound - info.init) as usize;
            Some(if info.inclusive {
                diff / step + 1
            } else {
                diff.div_ceil(step)
            })
        }
        LoopDirection::Descending => {
            if info.init < bound || (!info.inclusive && info.init == bound) {
                return Some(0);
            }
            let diff = (info.init - bound) as usize;
            Some(if info.inclusive {
                diff / step + 1
            } else {
                diff.div_ceil(step)
            })
        }
    }
}

// Test-only instrumentation for `estimate_unrolled_body`: counts every *actual* call
// (i.e. every cache miss against `CodeGen::unroll_estimate_cache`), so a test can assert
// the memoization is actually being hit rather than merely trusting that it is — see
// `tests::nested_unroll_estimation_is_memoized_per_lexical_loop` below.
#[cfg(test)]
thread_local! {
    static ESTIMATE_UNROLLED_BODY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_estimate_unrolled_body_call() {
    ESTIMATE_UNROLLED_BODY_CALLS.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
fn reset_estimate_unrolled_body_calls() {
    ESTIMATE_UNROLLED_BODY_CALLS.with(|c| c.set(0));
}

#[cfg(test)]
fn estimate_unrolled_body_calls() -> usize {
    ESTIMATE_UNROLLED_BODY_CALLS.with(|c| c.get())
}

/// Estimates how many instructions one iteration of `lb`'s body — excluding its trailing
/// increment statement, which unrolling never lowers (see [`try_unroll_loop`]) — lowers to
/// when the induction variable at `slot` is bound to [`Binding::ConstUsize`], by lowering
/// it once into a scratch instruction buffer and counting.
///
/// A single representative iteration (`sample`) is enough to estimate every iteration:
/// [`lower_branch`] always lowers a `Branch`'s condition check plus *both* its arms (bar
/// elision of `SharedElse` itself when there's no else arm — see its doc comment)
/// unconditionally into the instruction stream, regardless of the condition's compile-time
/// or runtime value — the target ISA (`circom_mpc_vm2::isa::Instr`'s
/// `SharedIf`/`SharedElse`/`SharedEnd`) defers the public-vs-shared dispatch to the VM at
/// *runtime*, so no lowered instruction is ever compile-time control-flow-conditional on
/// the induction variable's concrete value. Every iteration therefore lowers to the same
/// instruction *count* no matter what a nested `Branch`'s condition folds to, only the
/// embedded constant operands differ.
///
/// Side effects of the estimation lowering are undone before returning:
/// [`CodeGen::instrs`] is swapped out for an empty scratch buffer and restored;
/// [`CodeGen::regs`]/[`CodeGen::iregs`] (whose allocation high-water marks would otherwise
/// be inflated by register traffic that's about to be discarded, bloating the real frame
/// size) and [`CodeGen::last_const_store`] are cloned and restored; the `slot` binding is
/// restored via the usual [`Env::bind`]/[`Env::restore`] pair (mirroring
/// [`try_unroll_loop`]'s own per-iteration discipline).
///
/// Interning into [`CodeGen::names`]/[`CodeGen::constants`] (the latter via
/// [`CodeGen::const_id`]) is deliberately *not* rolled back. When the estimate leads to a
/// committed unroll, this is genuinely redundant: the real per-iteration lowering that
/// follows looks up the very same values and gets back the same ids via
/// [`CodeGen::const_ids`]. But when the estimate is instead *rejected* (`estimate * T >
/// threshold`, so the caller falls back to [`lower_conforming_loop`] instead), nothing
/// looks those values up again — the constants interned during this throwaway pass are
/// left behind as unreferenced entries in [`CodeGen::constants`] for the rest of
/// compilation. This is harmless (no emitted instruction ever indexes an entry that
/// nothing ever interned a reference to) but is a real, permanent side effect of a
/// rejected estimate, not merely a redundant no-op; rolling it back would need
/// `Self::names`/`Self::constants`/`Self::const_ids` cloned and restored exactly like
/// `regs`/`iregs` above, which this deliberately skips as not worth the extra clone for a
/// handful of dead table entries.
///
/// Cached at most once per *lexical* loop per compilation whenever it runs at nesting `0`
/// — see [`CodeGen::unroll_estimate_cache`]/[`CodeGen::unroll_estimate_nesting`], which
/// together memoize this function's result so a nested loop's enclosing loop(s) iterating
/// (for real) doesn't re-run it from scratch every time; a call nested inside an
/// ancestor's *own* estimation pass (nesting `> 0`) is never cached and always recomputed,
/// since that's precisely the context whose binding kinds might not match what the
/// ancestor(s) really, finally commit to. `#[cfg(test)]` builds additionally count every
/// call (cached or not) via [`estimate_unrolled_body_calls`], so a test can observe the
/// cache actually being hit.
fn estimate_unrolled_body<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    lb: &LoopBucket,
    slot: usize,
    sample: usize,
) -> Result<usize> {
    #[cfg(test)]
    record_estimate_unrolled_body_call();

    cg.unroll_estimate_nesting += 1;

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
    cg.unroll_estimate_nesting -= 1;

    result?;
    Ok(estimate)
}

/// Attempts to unroll a conforming loop per the size heuristic: `threshold == 0` always
/// defers to the rolled/mirror-promoted path, skipping the estimation lowering entirely
/// (per the brief). Otherwise, if `T`, the loop's trip count ([`trip_count`]), can't be
/// determined, also defers. Otherwise, estimates one iteration's instruction count
/// ([`estimate_unrolled_body`], via [`CodeGen::unroll_estimate_cache`]/[`CodeGen::
/// unroll_estimate_nesting`] — see there for why memoizing it per lexical loop, gated on
/// nesting, is sound) and unrolls — re-lowering the
/// body `T` times with `slot` bound to [`Binding::ConstUsize`] for that iteration's
/// concrete value, skipping the trailing increment statement and emitting no
/// condition/jump at all — only if `estimate * T <= threshold`.
///
/// A single trailing `Mov` re-synchronizes the induction variable's actual field slot to
/// its final value (`init +/- T * step` — exactly what the rolled loop would leave behind:
/// the first value that fails the condition) once unrolling completes with `T > 0`, so any
/// code after the loop that reads the variable's real runtime value (as opposed to an
/// index-position fold, which only ever happens *inside* the loop body while `slot` is
/// bound) still sees the right answer — unrolling must be invisible to anything outside
/// the loop, not just to the values the loop body itself computes.
fn try_unroll_loop<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    lb: &LoopBucket,
    info: &ConformingLoop,
    force: bool,
) -> Result<bool> {
    if cg.config.unroll.threshold == 0 && !force {
        return Ok(false);
    }
    let Some(trip_count) = trip_count(info) else {
        return Ok(false);
    };

    let mut require_full_vectorization = false;
    if trip_count > 0 && !force {
        // Memoized per lexical loop, keyed by `lb`'s own address — *not* `lb.message_id`,
        // which is per-*template*, not per-loop (see `CodeGen::unroll_estimate_cache`'s
        // doc comment for how that was confirmed and why the address is sound instead): a
        // loop nested inside another one that iterates `N` times would otherwise redo
        // this (a full lowering-and-discard pass, itself recursing into any loops nested
        // inside *this* one) on every single one of those `N` re-lowerings, even though
        // it always produces the same number *as long as* every enclosing loop's binding
        // kind (`ConstUsize` vs `IReg`) is the same as it'll be in the real, committed
        // lowering — which is exactly what `CodeGen::unroll_estimate_nesting` gates (see
        // its doc comment): only read from / written to while nesting is `0`.
        let estimate = if cg.unroll_estimate_nesting == 0 {
            let loop_id = std::ptr::from_ref(lb) as usize;
            match cg.unroll_estimate_cache.get(&loop_id) {
                Some(&cached) => cached,
                None => {
                    let estimate = estimate_unrolled_body(cg, lb, info.slot, info.init as usize)?;
                    cg.unroll_estimate_cache.insert(loop_id, estimate);
                    estimate
                }
            }
        } else {
            estimate_unrolled_body(cg, lb, info.slot, info.init as usize)?
        };
        let total = estimate.checked_mul(trip_count);
        let fits = total.is_some_and(|total| total <= cg.config.unroll.threshold);
        if !fits {
            // A dependency-free elementwise body lowers to one `(Bin, Mov)` pair per
            // iteration. It is worth expanding beyond the ordinary bytecode budget if
            // (and only if) the complete region then compacts to vector instructions.
            // The configurable trip-count cap bounds both this speculative work and the
            // contiguous register block needed by `BinN`; the ISA's u16 register-file
            // width is an additional hard ceiling.
            let available_regs = (u16::MAX as usize).saturating_sub(cg.regs.mark() as usize);
            let can_try_vectorization = estimate == 2
                && trip_count >= MIN_FUSABLE_RUN
                && trip_count <= cg.config.unroll.max_vectorized_loop_size
                && trip_count <= available_regs;
            if !can_try_vectorization {
                return Ok(false);
            }
            require_full_vectorization = true;
        }
    }

    let last_idx = lb.body.len() - 1;
    let unrolled_start = cg.instrs.len();
    let rollback = require_full_vectorization.then(|| {
        (
            cg.regs.clone(),
            cg.iregs.clone(),
            cg.last_const_store.clone(),
        )
    });
    for i in 0..trip_count {
        let value = match info.direction {
            LoopDirection::Ascending => info.init as usize + i * info.step as usize,
            LoopDirection::Descending => info.init as usize - i * info.step as usize,
        };
        let previous_binding = cg.env.bind(info.slot, Binding::ConstUsize(value));
        for inst in &lb.body[..last_idx] {
            lower_stmt(cg, inst)?;
        }
        cg.env.restore(info.slot, previous_binding);
    }

    fuse_unrolled_binn(cg, unrolled_start)?;

    if require_full_vectorization && !is_fully_vectorized(&cg.instrs[unrolled_start..]) {
        cg.instrs.truncate(unrolled_start);
        let (regs, iregs, last_const_store) =
            rollback.expect("vectorization rollback state was captured");
        cg.regs = regs;
        cg.iregs = iregs;
        cg.last_const_store = last_const_store;
        return Ok(false);
    }

    if trip_count > 0 {
        // Load-bearing: without this, any post-loop *value-position* read of the
        // induction variable (e.g. `final_i <== i;` after the loop) would see whatever
        // `ConstUsize` binding the last unrolled iteration happened to leave in `Env` —
        // which only ever affects lowering, never the variable's real field slot — so
        // reading the slot directly, as ordinary code after the loop does, would
        // otherwise still hold its pre-loop value. This is the highest-risk unrolling
        // scenario end to end. The regression test that actually exercises this is
        // `tests::try_unroll_loop_resyncs_slot_to_final_value_for_post_loop_reads` (below,
        // white-box/hand-built-IR — see its own doc comment for why: circom's front end
        // always folds a real `.circom` source's post-loop induction-variable read into a
        // literal before this crate's codegen ever sees it, so no `.circom` fixture can
        // reach this code path). `loop_final_value_post_loop_read_both_thresholds`
        // (`tests/kat_progression.rs`, circuit `tests/circuits/loop_final_value.circom`)
        // is still a real end-to-end correctness check of the same source-level scenario —
        // it just wouldn't fail if this `Mov` were deleted.
        let delta = i64::try_from(trip_count * info.step as usize)?;
        let final_value = match info.direction {
            LoopDirection::Ascending => i64::from(info.init) + delta,
            LoopDirection::Descending => i64::from(info.init) - delta,
        };
        let final_value = if final_value >= 0 {
            F::from(final_value as u64)
        } else {
            -F::from(final_value.unsigned_abs())
        };
        let const_id = cg.const_id(final_value)?;
        cg.instrs.push(Instr::Mov {
            dst: Dst::Var(Addr::Const(u32::try_from(info.slot)?)),
            src: Src::Const(const_id),
        });
    }

    Ok(true)
}

// ## BinN fusion
//
// A single-statement unrolled iteration like `out[i] <== a[i] * b[i]` lowers to exactly
// two instructions (`Instr::Bin` computing the product into a scratch register,
// immediately followed by `Instr::Mov` storing it) — *not* a run of consecutive `Bin`s,
// because `RegAlloc`'s stack discipline (`CodeGen::regs`, freed back to its per-statement
// mark by every `lower_stmt` call) hands every iteration's `Bin` the exact same scratch
// register. What *does* repeat, verbatim except for the operands' addresses advancing by
// one element per iteration, is the two-instruction `(Bin, Mov)` pair itself. Fusion
// therefore matches runs of these pairs — not bare `Bin`s — and folds a qualifying run of
// `n >= 4` into one `Instr::BinN` (writing into a freshly allocated `n`-register block,
// since the vectorized result needs somewhere to live all at once, unlike the reused
// scalar register) followed by one `Instr::StoreN`.
//
// Matching is conservative and purely mechanical: every `Bin` in the run must share the
// same op and reuse the very same scratch register (exactly what the unmodified
// per-iteration lowering already produces); every `Mov` must forward that exact register;
// and each of the `Bin`'s two source operands plus the `Mov`'s destination must advance by
// *exactly one* address unit per step, matching `circom_mpc_vm2::exec`'s `read_n`/
// `resolve_at` (`BinN`/`StoreN` only ever address `base..base+n`, unit stride — see
// `exec.rs`). Only `Addr::Const` addressing is recognized (an unrolled iteration's own
// array indices always fold there; `Affine`/`Dynamic` addressing, if seen, simply fails to
// match rather than being fused incorrectly). Any non-matching element ends the run in
// place; nothing about a non-fused instruction changes.
//
// Fusion runs once, after every iteration of the unrolled body has been emitted (so it
// sees the *whole* range at once, not just one candidate window) and before the trailing
// resync `Mov` (which isn't part of the range and must never be touched). It is skipped
// entirely (option (1) from the task brief, chosen for simplicity and safety over
// remapping targets) whenever the emitted range contains *any* target-carrying instruction
// (`Jmp`/`JmpIfZero`/`SharedIf`/`SharedElse`) — compaction shrinks the instruction stream,
// which would invalidate an absolute target landing inside the compacted range (a nested
// rolled loop's own back-edge, or a nested `Branch`'s `SharedIf`/`SharedElse` targets, for
// instance). Forward references from *outside* the range are unaffected either way: they
// are all patched lazily, using `CodeGen::instrs.len()` read *after* this function returns
// (see `CodeGen::patch`/`finish_loop`), so they automatically see the post-fusion length.
// Elementwise arithmetic loops — the whole payoff case — essentially never contain
// branches, so this conservative skip costs nothing in practice.

/// Runs the BinN-fusion peephole (see the module docs above) over
/// `cg.instrs[unrolled_start..]` — the instructions [`try_unroll_loop`] just emitted for
/// one loop's unrolled body, and *only* those (the caller must not have appended anything
/// else yet).
fn fuse_unrolled_binn<F: PrimeField>(cg: &mut CodeGen<'_, F>, unrolled_start: usize) -> Result<()> {
    if cg.instrs[unrolled_start..].iter().any(|i| {
        matches!(
            i,
            Instr::Jmp { .. }
                | Instr::JmpIfZero { .. }
                | Instr::SharedIf { .. }
                | Instr::SharedIfBit { .. }
                | Instr::SharedElse { .. }
        )
    }) {
        return Ok(());
    }

    let body: Vec<Instr> = cg.instrs.drain(unrolled_start..).collect();
    let fused = fuse_binn_pass(cg, body)?;
    cg.instrs.extend(fused);
    Ok(())
}

/// A key identifying one operand's address space plus its offset within that space, used
/// to check whether a sequence of operands advances by exactly one unit per step (the
/// only stride `BinN`/`StoreN` support — see the module docs above). Two operands compare
/// equal only if both the space *and* the offset match; comparing keys from different
/// address spaces is always `false`, never a false match.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OperandKey {
    Reg(i64),
    Const(i64),
    Var(i64),
    Signal(i64),
}

impl OperandKey {
    /// The key one unit past `self` in the same address space (what the *next* element's
    /// operand must equal for the run to keep advancing).
    fn next(self) -> Self {
        match self {
            OperandKey::Reg(v) => OperandKey::Reg(v + 1),
            OperandKey::Const(v) => OperandKey::Const(v + 1),
            OperandKey::Var(v) => OperandKey::Var(v + 1),
            OperandKey::Signal(v) => OperandKey::Signal(v + 1),
        }
    }
}

/// The [`OperandKey`] of a [`Src`] read operand, or `None` for addressing modes fusion
/// doesn't recognize (`Affine`/`Dynamic` — see the module docs above).
fn src_operand_key(src: &Src) -> Option<OperandKey> {
    match src {
        Src::Reg(r) => Some(OperandKey::Reg(*r as i64)),
        Src::Const(c) => Some(OperandKey::Const(*c as i64)),
        Src::Var(Addr::Const(c)) => Some(OperandKey::Var(*c as i64)),
        Src::Signal(Addr::Const(c)) => Some(OperandKey::Signal(*c as i64)),
        Src::Var(_) | Src::Signal(_) => None,
    }
}

/// The [`OperandKey`] of a [`Dst`] write operand, or `None` for addressing modes fusion
/// doesn't recognize. Deliberately shares `OperandKey`'s variants with `src_operand_key`
/// (rather than a separate enum) so a `Dst::Signal(Addr::Const(c))` and a
/// `Src::Signal(Addr::Const(c))` at the same `c` compare equal — irrelevant to fusion
/// itself (a `Bin`'s sources and a `Mov`'s destination are never compared against each
/// other), but keeping one enum for both is simpler than two structurally-identical ones.
fn dst_operand_key(dst: &Dst) -> Option<OperandKey> {
    match dst {
        Dst::Reg(r) => Some(OperandKey::Reg(*r as i64)),
        Dst::Var(Addr::Const(c)) => Some(OperandKey::Var(*c as i64)),
        Dst::Signal(Addr::Const(c)) => Some(OperandKey::Signal(*c as i64)),
        Dst::Var(_) | Dst::Signal(_) => None,
    }
}

/// One matched element of a fusable run: the position (`Bin` at `idx`, `Mov` at `idx+1`)
/// plus the three operand keys that must advance by one per step across the run.
struct FusableStep {
    a: OperandKey,
    b: OperandKey,
    store_dst: OperandKey,
}

/// If `body[idx]`/`body[idx + 1]` form one element of a fusable `(Bin, Mov)` run — a `Bin`
/// whose result is used by nothing but the immediately following `Mov` — returns its op and
/// operand keys. `None` for anything else (including a `Bin` followed by anything other
/// than a same-register `Mov`, or operands in an addressing mode fusion doesn't recognize).
fn fusable_step(body: &[Instr], idx: usize) -> Option<(BinOp, u16, FusableStep)> {
    let Instr::Bin { op, dst, a, b } = body.get(idx)? else {
        return None;
    };
    let Instr::Mov {
        dst: store_dst,
        src: Src::Reg(src_reg),
    } = body.get(idx + 1)?
    else {
        return None;
    };
    if src_reg != dst {
        return None;
    }
    let a = src_operand_key(a)?;
    let b = src_operand_key(b)?;
    let store_dst = dst_operand_key(store_dst)?;
    Some((*op, *dst, FusableStep { a, b, store_dst }))
}

/// The length (in `(Bin, Mov)` pairs) of the maximal fusable run starting at `idx`: `1` if
/// `body[idx]`/`body[idx+1]` form a valid element on their own (see [`fusable_step`]) but
/// the next pair doesn't continue it (wrong op, different scratch register, or any operand
/// key not advancing by exactly one), up to `body.len()`; `0` if `idx` isn't the start of a
/// fusable element at all.
fn fusable_run_len(body: &[Instr], idx: usize) -> usize {
    let Some((op0, reg0, first)) = fusable_step(body, idx) else {
        return 0;
    };
    let mut len = 1;
    let mut expect = FusableStep {
        a: first.a.next(),
        b: first.b.next(),
        store_dst: first.store_dst.next(),
    };
    while let Some((op, reg, step)) = fusable_step(body, idx + 2 * len) {
        if op != op0
            || reg != reg0
            || step.a != expect.a
            || step.b != expect.b
            || step.store_dst != expect.store_dst
        {
            break;
        }
        len += 1;
        expect = FusableStep {
            a: step.a.next(),
            b: step.b.next(),
            store_dst: step.store_dst.next(),
        };
    }
    // Scalar pairs execute in order, so an earlier destination write may feed a later
    // source read. `BinN` gathers the whole source range before `StoreN` writes anything,
    // which would break that loop-carried dependency. Exact in-place ranges are safe
    // (each element only reads the slot it then overwrites); conservatively reject every
    // other overlap.
    if ranges_overlap(first.a, first.store_dst, len)
        || ranges_overlap(first.b, first.store_dst, len)
    {
        return 0;
    }
    len
}

fn ranges_overlap(a: OperandKey, b: OperandKey, len: usize) -> bool {
    fn split(key: OperandKey) -> (u8, i64) {
        match key {
            OperandKey::Reg(v) => (0, v),
            OperandKey::Const(v) => (1, v),
            OperandKey::Var(v) => (2, v),
            OperandKey::Signal(v) => (3, v),
        }
    }

    let (a_space, a_start) = split(a);
    let (b_space, b_start) = split(b);
    if a_space != b_space || a_start == b_start {
        return false;
    }
    let len = i64::try_from(len).expect("instruction vector length fits i64");
    a_start < b_start + len && b_start < a_start + len
}

/// Minimum run length (in original scalar `Bin` instructions) worth fusing into one
/// `BinN`. Two scalar instructions would tie the vector form at `n = 1`; from `n = 2`
/// onward it is smaller bytecode and, more importantly, lets MPC drivers collapse
/// independent protocol operations into one communication round.
const MIN_FUSABLE_RUN: usize = 2;

/// Whether a speculative over-budget expansion compacted completely to vector compute/
/// store pairs. Accepting any leftover scalar/control-flow instruction here would defeat
/// the bytecode cap this bypass is meant to preserve, so partial fusion falls back to the
/// ordinary rolled loop.
fn is_fully_vectorized(instrs: &[Instr]) -> bool {
    !instrs.is_empty()
        && instrs.len().is_multiple_of(2)
        && instrs.chunks_exact(2).all(|pair| {
            matches!(pair[0], Instr::BinN { .. }) && matches!(pair[1], Instr::StoreN { .. })
        })
}

/// The actual fold: scans `body` for maximal fusable runs (see [`fusable_run_len`]) of at
/// least [`MIN_FUSABLE_RUN`] `(Bin, Mov)` pairs, replacing each with one `Instr::BinN`
/// (into a freshly allocated `n`-register block — `cg.regs` is exactly where the unrolled
/// loop's own iterations just freed their scratch register back to, so this reuses that
/// same space rather than growing the frame beyond what the un-fused body already needed)
/// followed by one `Instr::StoreN`; everything else (non-matching instructions, and runs
/// shorter than the threshold) is copied through unchanged.
fn fuse_binn_pass<F: PrimeField>(cg: &mut CodeGen<'_, F>, body: Vec<Instr>) -> Result<Vec<Instr>> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let run_len = fusable_run_len(&body, i);
        if run_len >= MIN_FUSABLE_RUN {
            let Instr::Bin { op, a, b, .. } = &body[i] else {
                unreachable!("fusable_run_len only returns > 0 when body[i] is a Bin")
            };
            let Instr::Mov { dst, .. } = &body[i + 1] else {
                unreachable!("fusable_run_len only returns > 0 when body[i + 1] is a Mov")
            };
            let n = u32::try_from(run_len)?;
            let fused_dst = cg.alloc_freg_n(n)?;
            out.push(Instr::BinN {
                op: *op,
                dst: fused_dst,
                a: *a,
                b: *b,
                n,
            });
            out.push(Instr::StoreN {
                dst: *dst,
                src: fused_dst,
                n,
            });
            i += 2 * run_len;
        } else {
            out.push(body[i].clone());
            i += 1;
        }
    }
    Ok(out)
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
    use circom_compiler::intermediate_representation::ir_interface::{
        ComputeBucket, InstrContext, LoadBucket, SizeOption,
    };

    fn cg() -> CodeGen<'static, ark_bn254::Fr> {
        let config: &'static CompilerConfig = Box::leak(Box::new(CompilerConfig::default()));
        CodeGen::new(config)
    }

    fn cg_with_threshold(threshold: usize) -> CodeGen<'static, ark_bn254::Fr> {
        let config: &'static CompilerConfig = Box::leak(Box::new(CompilerConfig {
            unroll: crate::UnrollConfig {
                threshold,
                ..Default::default()
            },
            ..CompilerConfig::default()
        }));
        CodeGen::new(config)
    }

    /// An address-domain leaf: a raw `usize` slot number (`static_const_slot`'s only
    /// recognized shape — see `codegen::index`), *not* a constant-table index.
    fn addr_slot(slot: usize) -> Instruction {
        Instruction::Value(ValueBucket {
            line: 0,
            message_id: 0,
            parse_as: ValueType::U32,
            op_aux_no: 0,
            value: slot,
        })
    }

    /// A field-constant leaf: `const_idx` indexes into `CodeGen::constants` (see
    /// `const_as_u32`) — the caller must have already populated that table.
    fn field_const(const_idx: usize) -> Instruction {
        Instruction::Value(ValueBucket {
            line: 0,
            message_id: 0,
            parse_as: ValueType::BigInt,
            op_aux_no: 0,
            value: const_idx,
        })
    }

    /// `Load(Variable, slot)` — a value-position read of variable `slot`.
    fn load_var(slot: usize) -> Instruction {
        Instruction::Load(LoadBucket {
            line: 0,
            message_id: 0,
            address_type: AddressType::Variable,
            src: LocationRule::Indexed {
                location: Box::new(addr_slot(slot)),
                template_header: None,
            },
            context: InstrContext {
                size: SizeOption::Single(1),
            },
        })
    }

    /// `Store(Variable, slot) <- src` — a plain scalar variable store.
    fn store_var(slot: usize, src: Instruction) -> Instruction {
        Instruction::Store(StoreBucket {
            line: 0,
            message_id: 0,
            context: InstrContext {
                size: SizeOption::Single(1),
            },
            src_context: InstrContext {
                size: SizeOption::Single(1),
            },
            dest_is_output: false,
            dest_address_type: AddressType::Variable,
            src_address_type: None,
            dest: LocationRule::Indexed {
                location: Box::new(addr_slot(slot)),
                template_header: None,
            },
            src: Box::new(src),
        })
    }

    /// A hand-built [`LoopBucket`] matching [`detect_conforming`]'s exact shape: `slot <
    /// bound_const_idx` (a `Lesser` condition), body ending in `slot = slot + step_const_idx`.
    /// The brief-mandated increment is the body's *only* statement — this test is about
    /// [`try_unroll_loop`]'s own resync `Mov`, not about the non-increment body work
    /// [`estimate_unrolled_body`] already covers elsewhere.
    fn synthetic_loop(slot: usize, bound_const_idx: usize, step_const_idx: usize) -> LoopBucket {
        LoopBucket {
            line: 0,
            message_id: 0,
            continue_condition: Box::new(Instruction::Compute(ComputeBucket {
                line: 0,
                message_id: 0,
                op: OperatorType::Lesser,
                op_aux_no: 0,
                stack: vec![
                    Box::new(load_var(slot)),
                    Box::new(field_const(bound_const_idx)),
                ],
            })),
            body: vec![Box::new(store_var(
                slot,
                Instruction::Compute(ComputeBucket {
                    line: 0,
                    message_id: 0,
                    op: OperatorType::Add,
                    op_aux_no: 0,
                    stack: vec![
                        Box::new(load_var(slot)),
                        Box::new(field_const(step_const_idx)),
                    ],
                }),
            ))],
        }
    }

    /// A hand-built [`Instruction::Branch`] (an `if`/`else` — or else-less, when
    /// `else_branch` is empty): `cond`'s actual content is irrelevant to every test that
    /// uses this helper (none of them ever lower it), so callers pass a trivial
    /// placeholder value.
    fn branch(
        cond: Instruction,
        if_branch: Vec<Instruction>,
        else_branch: Vec<Instruction>,
    ) -> Instruction {
        Instruction::Branch(BranchBucket {
            line: 0,
            message_id: 0,
            cond: Box::new(cond),
            if_branch: if_branch.into_iter().map(Box::new).collect(),
            else_branch: else_branch.into_iter().map(Box::new).collect(),
        })
    }

    /// The Task 6 carried-over regression test (from the Task 4 review): a loop whose body
    /// conditionally re-stores its own induction variable inside a `Branch` arm must be
    /// judged non-conforming, exactly as if the store were unconditional — before this
    /// task, [`instruction_writes_slot`] didn't recurse into `Branch` bodies at all (safe
    /// only because `Branch` lowering used to bail outright), so this exact shape would
    /// have been silently misjudged conforming.
    #[test]
    fn loop_with_conditional_induction_store_in_branch_is_non_conforming() {
        let mut cg = cg();
        // constants[0] = step (1), constants[1] = bound (5), constants[2] = an arbitrary
        // value stored to `slot` from inside the branch's `if` arm.
        cg.constants = vec![
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(5u64),
            ark_bn254::Fr::from(99u64),
        ];
        let slot = 0;
        cg.last_const_store.insert(slot, 0);

        let mut lb = synthetic_loop(slot, 1, 0);
        let conditional_store = branch(
            field_const(2), // placeholder cond, never lowered by this test
            vec![store_var(slot, field_const(2))],
            vec![],
        );
        lb.body.insert(0, Box::new(conditional_store));

        assert!(
            detect_conforming(&cg, &lb).is_none(),
            "a Branch arm that stores to the induction variable must make the loop \
             non-conforming, exactly like an unconditional extra store would"
        );
    }

    /// The Task 6 carried-over regression test (from the Task 4 review): a constant store
    /// made *inside* a `Branch` arm must not be trusted by [`detect_conforming`] as the
    /// definite pre-loop value of a following loop's induction variable — which arm
    /// actually ran at runtime is unknowable at compile time, so [`lower_branch`]'s
    /// control-flow join must invalidate [`CodeGen::last_const_store`] rather than let the
    /// arm's tracked constant leak out as if it were unconditionally established.
    #[test]
    fn branch_arm_const_store_does_not_feed_following_loop_conformance() {
        let mut cg = cg();
        // constants[0] = step (1), constants[1] = bound (5), constants[2] = the value the
        // branch's `if` arm stores into `slot`.
        cg.constants = vec![
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(5u64),
            ark_bn254::Fr::from(7u64),
        ];
        let slot = 0;
        // Simulates an earlier, real `slot = 0` initialization before the branch.
        cg.last_const_store.insert(slot, 0);

        let branch_inst = branch(
            field_const(2), // placeholder cond, never lowered by this test
            vec![store_var(slot, field_const(2))],
            vec![],
        );
        lower_stmt(&mut cg, &branch_inst).unwrap();

        assert!(
            !cg.last_const_store.contains_key(&slot),
            "a constant store inside a Branch arm must not remain trusted after the \
             branch — the control-flow join must invalidate it"
        );

        let lb = synthetic_loop(slot, 1, 0);
        assert!(
            detect_conforming(&cg, &lb).is_none(),
            "detect_conforming must not use a Branch arm's constant store as `init` for a \
             loop following the branch, since the arm may not have run at runtime"
        );
    }

    /// Pins [`lower_branch`]'s control-flow join, part 1 — `cg.last_const_store =
    /// pre_branch_const_store;`, restoring the pre-branch snapshot *before* lowering the
    /// falsy arm — which the test above doesn't exercise: that one only has a truthy arm,
    /// so its own `.clear()` on exit (part 2) is what actually protects it, and deleting
    /// part 1 alone still leaves it passing.
    ///
    /// Here the truthy arm const-stores an unrelated value into `slot` (simulating a slot
    /// reused by some other, non-overlapping-scope variable — completely ordinary for
    /// circom-assigned var slots), and the falsy arm's *first* statement is a
    /// conforming-shaped loop over that same `slot`, with `slot` never having been given a
    /// tracked value before the branch at all. Correct behavior: the falsy arm starts from
    /// the pre-branch snapshot (no entry for `slot`), so the loop's own `detect_conforming`
    /// finds no `init`; because a potentially shared branch may only contain fixed-schedule
    /// loops, lowering then rejects it. Without part 1,
    /// the falsy arm would instead see the truthy arm's leftover `slot -> 42` entry still
    /// sitting in `last_const_store`, wrongly detect the loop as conforming with that value
    /// as `init` and silently treat it as a statically counted loop.
    #[test]
    fn branch_falsy_arm_does_not_inherit_truthy_arm_const_store_for_its_own_loop() {
        // `threshold: 0` forces the rolled/mirror-promoted path whenever the loop is
        // detected as conforming (see `lower_conforming_or_unrolled`/`try_unroll_loop`),
        // so `Instr::ISet` unconditionally marks "detected conforming" here — no trip-count
        // arithmetic (e.g. a large inherited `init` making `bound <= init` true and trivially
        // "unrolling" to zero iterations without ever touching `ISet`) can mask the bug.
        let mut cg = cg_with_threshold(0);
        // constants[0] = step (1), constants[1] = bound (5), constants[2] = the value the
        // truthy arm stores into `slot` (unrelated to the falsy arm's loop), constants[3] =
        // placeholder cond value.
        cg.constants = vec![
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(5u64),
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(0u64),
        ];
        let slot = 0;
        // Deliberately *no* `cg.last_const_store.insert(..)` here: `slot` has no tracked
        // pre-branch value, matching a falsy-arm loop variable whose slot is only ever
        // initialized inside that same (not-yet-lowered) arm.

        let loop_in_else = synthetic_loop(slot, 1, 0);
        let branch_inst = branch(
            field_const(3),                        // placeholder cond, never lowered by this test
            vec![store_var(slot, field_const(2))], // truthy arm: unrelated store to `slot`
            vec![Instruction::Loop(loop_in_else)],
        );

        let error = lower_stmt(&mut cg, &branch_inst).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("loop inside a potentially shared branch"),
            "the falsy arm's loop must not inherit the truthy arm's const store to the \
             same slot and be wrongly accepted as a fixed-schedule loop: {error:?}"
        );
    }

    /// The regression test for the trailing resync `Mov` in [`try_unroll_loop`] — the
    /// "highest-risk unrolling scenario": a post-loop *value-position* read of the
    /// induction variable, after the loop has unrolled.
    ///
    /// This is a white-box, hand-built-IR test rather than an end-to-end `.circom`
    /// fixture, because circom's own front end always resolves a conforming loop's
    /// induction variable to a literal compile-time constant at any point after the loop
    /// where its value is provably known — which, for a plain ascending counter with a
    /// literal bound, is *always* true, regardless of what the loop body does with
    /// signals, regardless of `SimplificationLevel`, and regardless of this crate's own
    /// `unroll.threshold`. Confirmed empirically: `tests/circuits/loop_final_value.circom`
    /// (see `loop_final_value_post_loop_read_both_thresholds`,
    /// `tests/kat_progression.rs`) compiles `final_i <== i;` straight to `Mov { dst:
    /// Signal(..), src: Const(..) }` — a literal, not a `Load` of the variable — at *both*
    /// `threshold: 0` and `threshold: usize::MAX` alike, so that test alone would still
    /// pass even if this crate's resync `Mov` were deleted entirely (it does not exercise
    /// this code path). This test drives [`try_unroll_loop`] directly with a synthetic
    /// `LoopBucket`, bypassing circom's front end, so it actually observes the `Mov`.
    #[test]
    fn try_unroll_loop_resyncs_slot_to_final_value_for_post_loop_reads() {
        let mut cg = cg_with_threshold(usize::MAX);
        // constants[0] = step (1), constants[1] = bound (5); `init` is tracked separately
        // via `last_const_store` (a plain `u32`, not constant-table-indexed).
        cg.constants = vec![ark_bn254::Fr::from(1u64), ark_bn254::Fr::from(5u64)];
        let slot = 0;
        cg.last_const_store.insert(slot, 0);

        let lb = synthetic_loop(slot, 1, 0);
        let info = detect_conforming(&cg, &lb).expect("synthetic loop must be conforming");
        assert_eq!(info.init, 0);
        assert_eq!(info.step, 1);
        assert_eq!(info.bound, Some(5));

        let unrolled = try_unroll_loop(&mut cg, &lb, &info, false).unwrap();
        assert!(
            unrolled,
            "a trivial, small loop must unroll at threshold: usize::MAX"
        );

        // trip_count = ceil((5 - 0) / 1) = 5; final_value = init + trip_count * step = 5 —
        // exactly what a post-loop read of the induction variable (e.g. `final_i <== i;`)
        // must see.
        let Some(Instr::Mov {
            dst: Dst::Var(Addr::Const(dst_slot)),
            src: Src::Const(const_id),
        }) = cg.instrs.last()
        else {
            panic!(
                "expected a trailing resync Mov as the last emitted instruction, got: \
                 {:?}",
                cg.instrs
            );
        };
        assert_eq!(*dst_slot as usize, slot);
        assert_eq!(
            cg.constants[*const_id as usize],
            ark_bn254::Fr::from(5u64),
            "the resync Mov must write the loop's real post-loop value (5), not the last \
             ConstUsize binding the unrolled iterations happened to use (4)"
        );
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
            direction: LoopDirection::Ascending,
            inclusive: false,
            bound,
        }
    }

    fn descending(init: u32, bound: Option<u32>, step: u32, inclusive: bool) -> ConformingLoop {
        ConformingLoop {
            slot: 0,
            init,
            step,
            direction: LoopDirection::Descending,
            inclusive,
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

    #[test]
    fn trip_count_descending_strict_and_inclusive() {
        assert_eq!(trip_count(&descending(4, Some(0), 1, false)), Some(4));
        assert_eq!(trip_count(&descending(4, Some(0), 1, true)), Some(5));
        assert_eq!(trip_count(&descending(0, Some(0), 1, false)), Some(0));
        assert_eq!(trip_count(&descending(0, Some(0), 1, true)), Some(1));
    }

    /// Compiles a 3-deep-nested-loop fixture with `threshold: usize::MAX` (forcing every
    /// level to unroll wherever its own size fits) and returns how many times
    /// [`estimate_unrolled_body`] actually ran (see [`estimate_unrolled_body_calls`]).
    fn count_estimate_calls_for(path: &str) -> usize {
        reset_estimate_unrolled_body_calls();
        let config = CompilerConfig {
            simplification: crate::SimplificationLevel::O2(usize::MAX),
            unroll: crate::UnrollConfig {
                threshold: usize::MAX,
                ..Default::default()
            },
            ..CompilerConfig::default()
        };
        crate::CoCircomCompiler::<ark_bn254::Bn254>::parse(path, config).unwrap();
        estimate_unrolled_body_calls()
    }

    /// The regression test for `CodeGen::unroll_estimate_cache`/
    /// `CodeGen::unroll_estimate_nesting`: the reported bug was that each *outer*-loop
    /// iteration redid a nested loop's full size estimation from scratch, an overhead that
    /// grows with the *outer* loop's own trip count (and compounds with nesting depth).
    /// `tests/circuits/loop_triple_nested.circom` (outer trip count 2) and
    /// `tests/circuits/loop_triple_nested_wide_outer.circom` (identical middle/inner
    /// loops, outer trip count 6) isolate exactly that variable: if the outer loop's own
    /// trip count still mattered, the wide-outer fixture would trigger more
    /// [`estimate_unrolled_body`] calls than the narrow one. Asserting they're *equal*
    /// (not just "both small") directly demonstrates the fix, rather than trusting a
    /// single magic number tied to this specific circuit shape.
    #[test]
    fn nested_unroll_estimation_does_not_scale_with_outer_trip_count() {
        let narrow = count_estimate_calls_for("tests/circuits/loop_triple_nested.circom");
        let wide = count_estimate_calls_for("tests/circuits/loop_triple_nested_wide_outer.circom");

        assert_eq!(
            narrow, wide,
            "estimate_unrolled_body call count must not depend on the outer loop's own \
             trip count (narrow outer trip count 2: {narrow} calls; wide outer trip count \
             6: {wide} calls) — a difference means CodeGen::unroll_estimate_cache isn't \
             being hit across the outer loop's real iterations"
        );
        // Loose sanity bound: bounded by the middle/inner loops' own (small, fixed) trip
        // counts, not by anything that could grow unboundedly with nesting depth.
        assert!(
            narrow <= 10,
            "expected a small, bounded number of estimation passes for a 3-deep nest with \
             trip counts 2/2/2, got {narrow}"
        );
    }
}
