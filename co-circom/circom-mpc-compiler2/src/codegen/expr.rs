//! Expression lowering: turns an IR expression sub-tree into a [`Src`] operand.
//!
//! This is the recursive core the rest of codegen builds on. An "expression" here is any
//! [`Instruction`] that can appear in *value* position — as an operand of a
//! [`ComputeBucket`], or as the right-hand side of a [`StoreBucket`]
//! ([`crate::codegen::stmt`] handles the statement-level buckets that consume these
//! values).
use super::env::Binding;
use super::{CodeGen, index, instr_kind_name};
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

/// Lowers a [`ValueBucket`]: a field constant is the only shape valid in expression
/// position. A raw index value (`parse_as == U32`) here would mean the front end handed
/// us an address sub-tree where a value sub-tree was expected — those are only ever
/// evaluated by [`index::eval_index`], never lowered through here.
fn lower_value(vb: &ValueBucket) -> Result<Src> {
    match vb.parse_as {
        ValueType::BigInt => Ok(Src::Const(u32::try_from(vb.value)?)),
        ValueType::U32 => bail!(
            "unexpected raw index value (U32-parsed ValueBucket) in expression position, \
             expected a field constant (BigInt-parsed)"
        ),
    }
}

/// Resolves a [`LocationRule`] to a component-relative [`Addr`], symbolically evaluating
/// a computed `Indexed` location via [`index::eval_index`].
///
/// `Mapped` locations are used for subcomponent IO ([`AddressType::SubcmpSignal`]) only —
/// they cannot occur for a plain `Signal`/`Var` load or store, so this errors if one shows
/// up here (matches the old stack-based compiler's paths). Real `Mapped` handling is
/// [`index::eval_subcmp_location`], used directly by the `SubcmpSignal` paths in
/// [`lower_load_subcmp`]/`codegen::stmt`'s store/call lowering instead of through here.
pub(super) fn addr_from_location_rule<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    loc: &LocationRule,
) -> Result<Addr> {
    match loc {
        LocationRule::Indexed { location, .. } => Ok(index::eval_index(cg, location)?.to_addr()),
        LocationRule::Mapped { .. } => {
            bail!(
                "unexpected Mapped location outside subcomponent signal access (see \
                 index::eval_subcmp_location)"
            )
        }
    }
}

/// Lowers a [`LoadBucket`]. A single-element load is a pure addressing mode (no
/// instruction emitted); a multi-element load materializes into a fresh register range
/// via [`Instr::LoadN`].
///
/// A scalar variable load whose slot is currently bound to
/// [`Binding::ConstUsize`](crate::codegen::env::Binding::ConstUsize) — an unrolled
/// iteration's induction variable (see [`crate::codegen::stmt::lower_loop`]'s unrolling
/// path) — is a value-position read, so (unlike the mirrored-`ireg` rolled-loop case,
/// which only folds *index*-position reads — see [`index::folded_index_binding`]) it folds
/// straight to a field constant here, skipping the address computation and any load
/// instruction entirely.
fn lower_load<F: PrimeField>(cg: &mut CodeGen<'_, F>, lb: &LoadBucket) -> Result<Src> {
    let size = get_size_from_size_option(&lb.context.size);
    if size == 1
        && matches!(lb.address_type, AddressType::Variable)
        && let Some(v) = const_value_binding(cg, &lb.src)
    {
        let id = cg.const_id(F::from(v as u64))?;
        return Ok(Src::Const(id));
    }
    if let AddressType::SubcmpSignal { cmp_address, .. } = &lb.address_type {
        return lower_load_subcmp(cg, cmp_address, &lb.src, size);
    }
    let addr = addr_from_location_rule(cg, &lb.src)?;
    match &lb.address_type {
        AddressType::Signal => materialize(cg, Src::Signal(addr), size),
        AddressType::Variable => materialize(cg, Src::Var(addr), size),
        AddressType::SubcmpSignal { .. } => unreachable!("handled above"),
    }
}

/// Lowers a subcomponent-output read (`AddressType::SubcmpSignal`, old `handle_load_bucket`'s
/// `SubcmpSignal` arm, old :419-428): unlike `Signal`/`Var`, there is no addressing mode a
/// consuming instruction can read directly — the subcomponent's signal RAM lives at an
/// offset only known once [`Instr::CreateCmp`] has run, reached only through the dedicated
/// [`Instr::OutputSub`] — so this always materializes into a fresh `n`-register block, even
/// for `size == 1` (no `Src::Signal`-style zero-cost addressing mode is possible here).
///
/// Evaluation order mirrors old: the location/mapping (`loc`) is resolved before
/// `cmp_address`, matching old's `handle_instruction(location)` (or the `indexes`/`PushIndex`
/// handling) preceding `handle_instruction(cmp_address)` in `handle_load_bucket`.
fn lower_load_subcmp<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    cmp_address: &Instruction,
    loc: &LocationRule,
    size: usize,
) -> Result<Src> {
    let (addr, mapped) = index::eval_subcmp_location(cg, loc)?;
    let cmp = index::eval_index(cg, cmp_address)?.to_isrc(cg)?;
    let n = u32::try_from(size)?;
    let dst = cg.alloc_freg_n(n)?;
    cg.instrs.push(Instr::OutputSub {
        cmp,
        addr,
        mapped,
        dst,
        n,
    });
    Ok(Src::Reg(dst))
}

/// Resolves whether `loc` is a plain scalar variable load whose slot is currently bound to
/// [`Binding::ConstUsize`]: if so, its value is already known at compile time. Only a bare
/// `Value(U32)` address (via [`index::static_const_slot`]) counts — an array element's
/// address is never a single constant slot, so this can't misfire on `a[k]` for some
/// unrelated bound variable `k`.
fn const_value_binding<F: PrimeField>(cg: &CodeGen<'_, F>, loc: &LocationRule) -> Option<usize> {
    let LocationRule::Indexed { location, .. } = loc else {
        return None;
    };
    let slot = index::static_const_slot(location)?;
    match cg.env.get(slot) {
        Some(Binding::ConstUsize(v)) => Some(v),
        _ => None,
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
                lower_eqn(cg, size, cb)
            }
        }
        PrefixSub => lower_unary_neg(cg, cb),
        BoolNot => bail!("not yet lowered: BoolNot"),
        Complement => bail!("not yet lowered: Complement"),
        // Address-domain-only operators: they only ever appear inside an address
        // sub-tree, evaluated by `codegen::index::eval_index`, never here.
        ToAddress | MulAddress | AddAddress => bail!(
            "unexpected {} in expression position, expected an address sub-tree \
             (see codegen::index)",
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

/// Lowers an `Eq(size > 1)` [`ComputeBucket`] (array equality, `a === b`/`a == b` on
/// arrays) to [`Instr::EqN`], which reads `n` consecutive slots from each operand's
/// starting address directly — see [`lower_eqn_operand`] for how each operand resolves to
/// that starting address (see [`lower_binary`] for the register-freeing discipline).
fn lower_eqn<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    size: usize,
    cb: &ComputeBucket,
) -> Result<Src> {
    if cb.stack.len() != 2 {
        bail!("EqN expects 2 operands, found {}", cb.stack.len());
    }
    let n = u32::try_from(size)?;
    let mark = cg.regs.mark();
    let a = lower_eqn_operand(cg, &cb.stack[0], size)?;
    let b = lower_eqn_operand(cg, &cb.stack[1], size)?;
    cg.regs.free_to(mark);
    let dst = cg.alloc_freg()?;
    cg.instrs.push(Instr::EqN { dst, a, b, n });
    Ok(Src::Reg(dst))
}

/// Resolves one `EqN` operand to the addressing mode its `n` consecutive elements start
/// at. A plain array `Load` of the expected size resolves straight to its address (no
/// register copy — `EqN` itself walks `n` slots from there); anything else falls back to
/// [`lower_expr`], which materializes a multi-element result into a contiguous register
/// block via [`Instr::LoadN`] (still `n` consecutive slots, just register-backed).
///
/// A subcomponent-signal `Load` has no such zero-cost addressing mode at all (see
/// [`lower_load_subcmp`]), so it's deliberately excluded from the shortcut and falls
/// through to [`lower_expr`]/[`lower_load`] instead, which materializes it via
/// [`Instr::OutputSub`] like any other consumer of a subcomponent signal.
fn lower_eqn_operand<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    inst: &Instruction,
    size: usize,
) -> Result<Src> {
    if let Instruction::Load(lb) = inst {
        let load_size = get_size_from_size_option(&lb.context.size);
        let is_subcmp = matches!(lb.address_type, AddressType::SubcmpSignal { .. });
        if load_size == size && !is_subcmp {
            let addr = addr_from_location_rule(cg, &lb.src)?;
            return Ok(match &lb.address_type {
                AddressType::Signal => Src::Signal(addr),
                AddressType::Variable => Src::Var(addr),
                AddressType::SubcmpSignal { .. } => unreachable!("excluded above"),
            });
        }
    }
    lower_expr(cg, inst)
}
