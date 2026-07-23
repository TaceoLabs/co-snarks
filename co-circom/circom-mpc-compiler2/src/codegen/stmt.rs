//! Statement lowering: the IR buckets that appear at the top level of a template or
//! function body (as opposed to nested inside an expression — see
//! [`crate::codegen::expr`]).
//!
//! This task implements [`StoreBucket`] and [`AssertBucket`]; every other statement kind
//! is a `bail!` stub filled in by its own task (see the module-level docs of
//! `circom-mpc-compiler2` for the task breakdown). `Assert` is included here — ahead of
//! its own task — because it's the *only* IR shape that can carry an `Eq` operator of
//! size > 1: circom's front end lowers every `a === b` (`ConstraintEquality`) straight to
//! `AssertBucket { evaluate: ComputeBucket { op: Eq(length), .. } }` regardless of array
//! size (see the `circom` compiler's `translate_constraint_equality`), so without this,
//! this task's `EqN` lowering (see [`crate::codegen::expr`]) would be unreachable by any
//! real circuit. The lowering itself is a direct port of the old stack-based compiler's
//! `handle_assert_bucket` (`circom-mpc-compiler/src/lib.rs:468-474`): dropped outright
//! when `debug` is off, otherwise its condition is lowered like any other expression and
//! checked at runtime.
use super::{CodeGen, expr, instr_kind_name};
use crate::frontend::get_size_from_size_option;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, AssertBucket, Instruction, LocationRule, StoreBucket,
};
use circom_mpc_vm2::isa::{Dst, Instr, Src};
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
        Instruction::Loop(_) => bail!("not yet lowered: Loop"),
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
fn lower_store<F: PrimeField>(cg: &mut CodeGen<'_, F>, sb: &StoreBucket) -> Result<()> {
    let size = get_size_from_size_option(&sb.context.size);
    let dst = compute_dst(cg, &sb.dest, &sb.dest_address_type)?;
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
