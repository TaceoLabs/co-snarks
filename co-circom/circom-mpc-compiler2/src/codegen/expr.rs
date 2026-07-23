//! Expression lowering: turns an IR expression sub-tree into a [`Src`] operand.
//!
//! This is the recursive core the rest of codegen builds on. An "expression" here is any
//! [`Instruction`] that can appear in *value* position — as an operand of a
//! [`ComputeBucket`], or as the right-hand side of a [`StoreBucket`]
//! ([`crate::codegen::stmt`] handles the statement-level buckets that consume these
//! values).
use super::{CodeGen, instr_kind_name};
use crate::frontend::get_size_from_size_option;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, ComputeBucket, Instruction, LoadBucket, LocationRule, OperatorType, ValueBucket,
    ValueType,
};
use circom_mpc_vm2::isa::{Addr, BinOp, Instr, Src};
use eyre::{Result, bail};

/// Lowers an IR expression, returning the operand that holds its value.
///
/// This does **not** necessarily materialize a register: a constant lowers straight to
/// [`Src::Const`] and a single-element load lowers straight to a [`Src::Signal`]/
/// [`Src::Var`] addressing mode — both are read directly by whichever instruction
/// consumes them, with no `Mov`/`LoadN` in between. Only a [`ComputeBucket`] (an actual
/// operation) or a multi-element [`LoadBucket`] allocates a register.
pub(crate) fn lower_expr<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    inst: &Instruction,
) -> Result<Src> {
    match inst {
        Instruction::Value(vb) => lower_value(vb),
        Instruction::Compute(cb) => lower_compute(cg, cb),
        Instruction::Load(lb) => lower_load(cg, lb),
        other => bail!(
            "not yet lowered: {} used in expression position",
            instr_kind_name(other)
        ),
    }
}

/// Lowers a [`ValueBucket`]: either a field constant (the common case) or a raw index
/// value. Index values only ever occur inside address sub-trees, which this task does
/// not evaluate yet (Task 3 adds dynamic addressing).
fn lower_value(vb: &ValueBucket) -> Result<Src> {
    match vb.parse_as {
        ValueType::BigInt => Ok(Src::Const(u32::try_from(vb.value)?)),
        ValueType::U32 => bail!(
            "not yet lowered: index value used in expression position \
             (dynamic addressing lands in Task 3)"
        ),
    }
}

/// Resolves a [`LocationRule`] to a constant, component-relative address.
///
/// Only the "already a constant" case is handled this task: a
/// [`LocationRule::Indexed`] whose `location` is itself a constant [`ValueBucket`]
/// (`parse_as == U32`) — the same numbers the old stack-based compiler pushed directly
/// as `PushIndex`. Anything else (a computed index, or a `Mapped` location used for
/// subcomponent signal access) is out of scope until Task 3 / Task 8 respectively.
pub(super) fn const_index_from_location_rule(loc: &LocationRule) -> Result<u32> {
    match loc {
        LocationRule::Indexed { location, .. } => match location.as_ref() {
            Instruction::Value(vb) if vb.parse_as == ValueType::U32 => Ok(u32::try_from(vb.value)?),
            other => bail!(
                "not yet lowered: dynamic address expression ({}), Task 3",
                instr_kind_name(other)
            ),
        },
        LocationRule::Mapped { .. } => {
            bail!("not yet lowered: Mapped location (subcomponent signal access, Task 8)")
        }
    }
}

/// Lowers a [`LoadBucket`] at a constant address. A single-element load is a pure
/// addressing mode (no instruction emitted); a multi-element load materializes into a
/// fresh register range via [`Instr::LoadN`].
fn lower_load<F: PrimeField>(cg: &mut CodeGen<'_, F>, lb: &LoadBucket) -> Result<Src> {
    let size = get_size_from_size_option(&lb.context.size);
    let idx = const_index_from_location_rule(&lb.src)?;
    match &lb.address_type {
        AddressType::Signal => materialize(cg, Src::Signal(Addr::Const(idx)), size),
        AddressType::Variable => materialize(cg, Src::Var(Addr::Const(idx)), size),
        AddressType::SubcmpSignal { .. } => {
            bail!("not yet lowered: subcomponent signal load (Task 8)")
        }
    }
}

/// A `size == 1` addressing mode passes through untouched; `size > 1` is materialized
/// into consecutive fresh registers via [`Instr::LoadN`], returning the base register.
fn materialize<F: PrimeField>(cg: &mut CodeGen<'_, F>, addr_src: Src, size: usize) -> Result<Src> {
    if size == 1 {
        return Ok(addr_src);
    }
    let n = u32::try_from(size)?;
    // `LoadN` writes `n` consecutive registers at runtime, so the whole block must be
    // reserved as one unit (`alloc_freg_n`), not a single register (`alloc_freg`) — see
    // `RegAlloc::alloc_n`.
    let dst = cg.alloc_freg_n(n)?;
    cg.instrs.push(Instr::LoadN {
        dst,
        src: addr_src,
        n,
    });
    Ok(Src::Reg(dst))
}

/// Lowers a [`ComputeBucket`]: an arithmetic/logic/comparison operator applied to its
/// (already-lowered) operand sub-trees.
fn lower_compute<F: PrimeField>(cg: &mut CodeGen<'_, F>, cb: &ComputeBucket) -> Result<Src> {
    use OperatorType::*;
    match &cb.op {
        Eq(size_option) => {
            let size = get_size_from_size_option(size_option);
            if size == 1 {
                lower_binary(cg, BinOp::Eq, cb)
            } else {
                // EqN operates directly on addressing modes rather than materialized
                // registers, so it deliberately isn't wired up through this generic
                // path yet — left for the task that actually needs array equality.
                bail!("not yet lowered: EqN (array equality of size {size}, Task 3)")
            }
        }
        PrefixSub => lower_unary_neg(cg, cb),
        BoolNot => bail!("not yet lowered: BoolNot"),
        Complement => bail!("not yet lowered: Complement"),
        ToAddress | MulAddress | AddAddress => bail!(
            "not yet lowered: {} (index evaluation, Task 3)",
            cb.op.to_string()
        ),
        op => lower_binary(cg, map_binop(op)?, cb),
    }
}

/// Maps the (non-`Eq`, non-`PrefixSub`, non-`BoolNot`/`Complement`, non-address)
/// [`OperatorType`] variants 1:1 onto [`BinOp`] — the same table the old stack-based
/// compiler used (`circom-mpc-compiler/src/lib.rs:339-376`).
fn map_binop(op: &OperatorType) -> Result<BinOp> {
    use OperatorType::*;
    Ok(match op {
        Add => BinOp::Add,
        Sub => BinOp::Sub,
        Mul => BinOp::Mul,
        Div => BinOp::Div,
        Pow => BinOp::Pow,
        IntDiv => BinOp::IntDiv,
        Mod => BinOp::Mod,
        ShiftL => BinOp::ShiftL,
        ShiftR => BinOp::ShiftR,
        LesserEq => BinOp::Le,
        GreaterEq => BinOp::Ge,
        Lesser => BinOp::Lt,
        Greater => BinOp::Gt,
        NotEq => BinOp::Neq,
        BoolOr => BinOp::BoolOr,
        BoolAnd => BinOp::BoolAnd,
        BitOr => BinOp::BitOr,
        BitAnd => BinOp::BitAnd,
        BitXor => BinOp::BitXor,
        // Handled by the caller before reaching `map_binop`.
        Eq(_) | PrefixSub | BoolNot | Complement | ToAddress | MulAddress | AddAddress => {
            bail!(
                "unreachable: {} handled by lower_compute directly",
                op.to_string()
            )
        }
    })
}

/// Lowers a binary [`ComputeBucket`]: both operands, then the operator itself.
///
/// Register discipline: operand temporaries are freed back to the pre-operand `mark`
/// before allocating the destination register, so the result can reuse an operand's
/// register slot (the operand values have already been read into `a`/`b` by then — see
/// [`Src`] — so no aliasing hazard). This is what keeps expression frames small instead
/// of growing with tree depth.
fn lower_binary<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    op: BinOp,
    cb: &ComputeBucket,
) -> Result<Src> {
    if cb.stack.len() != 2 {
        bail!("{op:?} expects 2 operands, found {}", cb.stack.len());
    }
    let mark = cg.regs.mark();
    let a = lower_expr(cg, &cb.stack[0])?;
    let b = lower_expr(cg, &cb.stack[1])?;
    cg.regs.free_to(mark);
    let dst = cg.alloc_freg()?;
    cg.instrs.push(Instr::Bin { op, dst, a, b });
    Ok(Src::Reg(dst))
}

/// Lowers a unary `PrefixSub` [`ComputeBucket`] to [`Instr::Neg`] (see [`lower_binary`]
/// for the register-freeing discipline).
fn lower_unary_neg<F: PrimeField>(cg: &mut CodeGen<'_, F>, cb: &ComputeBucket) -> Result<Src> {
    if cb.stack.len() != 1 {
        bail!("PrefixSub expects 1 operand, found {}", cb.stack.len());
    }
    let mark = cg.regs.mark();
    let a = lower_expr(cg, &cb.stack[0])?;
    cg.regs.free_to(mark);
    let dst = cg.alloc_freg()?;
    cg.instrs.push(Instr::Neg { dst, a });
    Ok(Src::Reg(dst))
}
