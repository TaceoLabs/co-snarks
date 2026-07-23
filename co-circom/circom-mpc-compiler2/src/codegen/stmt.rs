//! Statement lowering: the IR buckets that appear at the top level of a template or
//! function body (as opposed to nested inside an expression — see
//! [`crate::codegen::expr`]).
//!
//! This task only implements [`StoreBucket`] at a constant address; every other
//! statement kind is a `bail!` stub filled in by its own task (see the module-level
//! docs of `circom-mpc-compiler2` for the task breakdown).
use super::{CodeGen, expr, instr_kind_name};
use crate::frontend::get_size_from_size_option;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, Instruction, LocationRule, StoreBucket,
};
use circom_mpc_vm2::isa::{Addr, Dst, Instr, Src};
use eyre::{Result, bail};

/// Lowers one top-level body instruction, appending to [`CodeGen::instrs`].
pub(crate) fn lower_stmt<F: PrimeField>(cg: &mut CodeGen<'_, F>, inst: &Instruction) -> Result<()> {
    match inst {
        Instruction::Store(sb) => lower_store(cg, sb),
        // Mirrors the old compiler: with debug instructions disabled, asserts/logs are
        // dropped outright rather than lowered (`circom-mpc-compiler/src/lib.rs:468-474,
        // 596-611`) — so only bail when they'd actually need to produce code.
        Instruction::Assert(_) if !cg.config.debug => Ok(()),
        Instruction::Log(_) if !cg.config.debug => Ok(()),
        Instruction::Assert(_) => bail!("not yet lowered: Assert"),
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

/// Lowers a [`StoreBucket`] at a constant address: a scalar store lowers straight to
/// [`Instr::Mov`]; an array store lowers its source through [`expr::lower_expr`] (which
/// materializes a multi-element load into a register range — see
/// [`crate::codegen::expr::lower_load`]) and copies out via [`Instr::StoreN`].
fn lower_store<F: PrimeField>(cg: &mut CodeGen<'_, F>, sb: &StoreBucket) -> Result<()> {
    let size = get_size_from_size_option(&sb.context.size);
    let dst = compute_dst(&sb.dest, &sb.dest_address_type)?;
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

/// Resolves a [`StoreBucket`]'s destination to a constant-address [`Dst`].
fn compute_dst(dest: &LocationRule, addr_ty: &AddressType) -> Result<Dst> {
    let idx = expr::const_index_from_location_rule(dest)?;
    match addr_ty {
        AddressType::Variable => Ok(Dst::Var(Addr::Const(idx))),
        AddressType::Signal => Ok(Dst::Signal(Addr::Const(idx))),
        AddressType::SubcmpSignal { .. } => {
            bail!("not yet lowered: subcomponent signal store (Task 8)")
        }
    }
}
