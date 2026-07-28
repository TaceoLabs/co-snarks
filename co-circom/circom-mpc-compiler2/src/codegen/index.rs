//! Symbolic evaluation of address sub-trees.
//!
//! Every `Load`/`StoreBucket`'s `LocationRule::Indexed` location, and every
//! `AddressType::SubcmpSignal`'s `cmp_address`, is itself a small IR sub-tree living in a
//! separate "address domain" from ordinary field expressions ([`crate::codegen::expr`]):
//! its leaves are [`ValueBucket`]s carrying raw `usize` indices (`parse_as == U32`), and
//! its internal nodes are [`ComputeBucket`]s with `op` one of `AddAddress`/`MulAddress`
//! (combining two already-evaluated sub-indices) or `ToAddress` (converting a *field*
//! expression, e.g. a signal-valued array index, into an index).
//!
//! [`eval_index`] walks this sub-tree and folds it as far as possible at compile time,
//! producing an [`IndexExpr`]: fully constant (either a literal or an unrolled loop
//! iteration's induction variable — see [`folded_index_binding`]), affine in a single
//! integer register (a promoted rolled-loop variable — also [`folded_index_binding`]), or
//! fully dynamic (computed at runtime into a fresh integer register).
//! [`IndexExpr::to_addr`] converts the result to the [`Addr`] the ISA understands.
use super::env::Binding;
use super::{CodeGen, expr};
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AccessType, AddressType, ComputeBucket, Instruction, LoadBucket, LocationRule, OperatorType,
    ValueBucket, ValueType,
};
use circom_mpc_vm2::isa::{Addr, ISrc, Instr};
use eyre::{Result, bail, eyre};

/// A symbolically-evaluated address expression — the result of [`eval_index`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexExpr {
    /// Fully known at compile time.
    Const(usize),
    /// `iregs[ireg] * stride + offset` — affine in a single integer register. Produced
    /// directly by [`eval_to_address`] when the operand is a promoted rolled-loop
    /// variable (see [`folded_index_binding`]), or by folding two already-affine/const
    /// results together (see [`try_fold_const`]).
    Affine {
        /// Integer register holding the (loop) variable's value.
        ireg: u8,
        /// Stride multiplier.
        stride: usize,
        /// Base offset.
        offset: usize,
    },
    /// Value had to be computed at runtime; it lives in this integer register.
    Dynamic(u8),
}

impl IndexExpr {
    /// Converts to the runtime [`Addr`] the VM ISA understands.
    ///
    /// Infallible: every field folded into an `IndexExpr` originated from a `u32`-ranged
    /// `ValueBucket` (`parse_as == U32`, itself parsed from a `usize` that circom's own
    /// front end already treats as an index — see [`eval_value`]), so `stride`/`offset`
    /// staying within `u32` range is an invariant of the address domain, not something
    /// that needs re-checking here.
    pub(crate) fn to_addr(self) -> Addr {
        match self {
            IndexExpr::Const(c) => Addr::Const(as_u32(c)),
            IndexExpr::Affine {
                ireg,
                stride,
                offset,
            } => Addr::Affine {
                ireg,
                stride: as_u32(stride),
                offset: as_u32(offset),
            },
            IndexExpr::Dynamic(ireg) => Addr::Dynamic(ireg),
        }
    }

    /// Materializes to an [`ISrc`] — the operand shape `CreateCmp`/`InputSub`/`OutputSub`'s
    /// `cmp` field needs (see `codegen::stmt`'s subcomponent lowering): a `Const` is an
    /// immediate (no register needed); `Dynamic`/`Affine` materialize into an integer
    /// register via [`to_isrc`] (`IAdd`/`IMul` as needed for the affine case — see there).
    pub(crate) fn to_isrc<F: PrimeField>(self, cg: &mut CodeGen<'_, F>) -> Result<ISrc> {
        to_isrc(cg, self)
    }
}

/// Converts an address-domain `usize` to `u32`, matching the range `Addr`'s fields use.
fn as_u32(v: usize) -> u32 {
    u32::try_from(v).expect("address-domain value exceeds u32 range (see IndexExpr::to_addr)")
}

/// Evaluates an address sub-tree (the location of a `Load`/`Store`, or a `cmp_address`),
/// folding as much of it as possible at compile time. See the module docs for the node
/// types this handles.
pub(crate) fn eval_index<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    inst: &Instruction,
) -> Result<IndexExpr> {
    match inst {
        Instruction::Value(vb) => eval_value(vb),
        Instruction::Compute(cb) => eval_compute(cg, cb),
        other => bail!(
            "unexpected {} in address position (expected an index value or AddAddress/\
             MulAddress/ToAddress)",
            super::instr_kind_name(other)
        ),
    }
}

/// Evaluates a [`ValueBucket`] leaf: only `parse_as == U32` (a raw index) is valid in
/// address position — a field constant (`BigInt`) here would mean the front end handed us
/// a value sub-tree where an index sub-tree was expected.
fn eval_value(vb: &ValueBucket) -> Result<IndexExpr> {
    match vb.parse_as {
        ValueType::U32 => Ok(IndexExpr::Const(vb.value)),
        ValueType::BigInt => bail!(
            "field constant (BigInt-parsed ValueBucket) used in address position, \
             expected a raw index (U32-parsed)"
        ),
    }
}

/// Evaluates a [`ComputeBucket`] node: `AddAddress`/`MulAddress` fold two already-evaluated
/// sub-indices; `ToAddress` converts a field expression into an index.
fn eval_compute<F: PrimeField>(cg: &mut CodeGen<'_, F>, cb: &ComputeBucket) -> Result<IndexExpr> {
    match cb.op {
        OperatorType::AddAddress => {
            let (a, b) = eval_operands(cg, cb)?;
            fold(cg, FoldOp::Add, a, b)
        }
        OperatorType::MulAddress => {
            let (a, b) = eval_operands(cg, cb)?;
            fold(cg, FoldOp::Mul, a, b)
        }
        OperatorType::ToAddress => eval_to_address(cg, cb),
        ref other => bail!(
            "unexpected {} in address position (expected AddAddress/MulAddress/ToAddress)",
            other.to_string()
        ),
    }
}

/// Evaluates both operands of a binary `AddAddress`/`MulAddress` node.
fn eval_operands<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    cb: &ComputeBucket,
) -> Result<(IndexExpr, IndexExpr)> {
    if cb.stack.len() != 2 {
        bail!(
            "{} expects 2 operands, found {}",
            cb.op.to_string(),
            cb.stack.len()
        );
    }
    let a = eval_index(cg, &cb.stack[0])?;
    let b = eval_index(cg, &cb.stack[1])?;
    Ok((a, b))
}

/// Evaluates a `ToAddress` node: converts its single field-valued operand into an index.
///
/// If the operand is a linear field expression over at most one bound variable —
/// [`eval_field_linear`]; a bare `Load` of a mirrored/unrolled loop variable is the
/// simplest case — the result is the folded form (`Affine`/`Const`) with no runtime
/// conversion. Otherwise the operand is lowered as an ordinary field expression
/// and converted at runtime via [`Instr::ToIndex`] into a fresh integer register (the same
/// `mark`/`free_to` discipline as any other field-register temporary — only the *field*
/// register used to feed `ToIndex` is freed here; the *integer* register receiving the
/// result is scoped to the enclosing statement, see [`crate::codegen::stmt::lower_stmt`]).
fn eval_to_address<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    cb: &ComputeBucket,
) -> Result<IndexExpr> {
    if cb.stack.len() != 1 {
        bail!("ToAddress expects 1 operand, found {}", cb.stack.len());
    }
    let operand = cb.stack[0].as_ref();
    if let Some(idx) = eval_field_linear(cg, operand).and_then(LinearForm::into_index_expr) {
        return Ok(idx);
    }
    let freg_mark = cg.regs.mark();
    let src = expr::lower_expr(cg, operand)?;
    cg.regs.free_to(freg_mark);
    let dst = cg.alloc_ireg()?;
    cg.instrs.push(Instr::ToIndex { dst, src });
    Ok(IndexExpr::Dynamic(dst))
}

/// A partially evaluated *field-domain* index expression, linear in at most one bound
/// loop variable: `var * stride + offset`, with exact signed intermediates.
///
/// This is what lets a compound index like `a[t*16 + 41 - k]` in a rolled conforming
/// loop (with `t` mirror-bound and `k` unrolled to a constant) collapse to a single
/// [`IndexExpr::Affine`] addressing mode instead of re-evaluating field arithmetic plus
/// a runtime `ToIndex` on every iteration: circom's O2 pipeline flattens
/// multi-dimensional accesses into one field expression under a single `ToAddress`, so
/// the address-domain folding ([`try_fold_const`]) never sees the linear structure.
///
/// Soundness: every leaf is either a `u32`-checked field literal or a bound variable
/// whose integer mirror equals its field value (the invariant [`folded_index_binding`]
/// already relies on), and `Add`/`Sub`/`Mul` are evaluated over ℤ in checked `i128`, so
/// the tracked `(stride, offset)` satisfy `field value ≡ stride·m + offset (mod p)` for
/// the mirror value `m`. [`Self::into_index_expr`] only folds when `stride` and `offset`
/// are non-negative `u32`s: then `stride·m + offset < 2^65 ≤ p` for any `u32`-ranged
/// `m`, so no reduction ever applies and the affine integer form is *exactly* the value
/// the runtime `ToIndex` would have produced — signed intermediates that cancel (field
/// wraps) fold, while a form that stays negative (e.g. `t*32 - 33`, in range only for
/// large-enough `t`) conservatively keeps the runtime conversion and its error behavior.
#[derive(Debug, Clone, Copy)]
struct LinearForm {
    /// The single mirrored loop-variable register the form ranges over, if any.
    /// `None` implies `stride == 0`.
    ireg: Option<u8>,
    /// Coefficient of the variable, exact over ℤ.
    stride: i128,
    /// Constant term, exact over ℤ.
    offset: i128,
}

impl LinearForm {
    fn constant(value: u32) -> Self {
        LinearForm {
            ireg: None,
            stride: 0,
            offset: i128::from(value),
        }
    }

    /// Combines the variable of two forms: at most one distinct register may appear.
    fn merge_ireg(a: Option<u8>, b: Option<u8>) -> Option<Option<u8>> {
        match (a, b) {
            (Some(a), Some(b)) if a != b => None,
            (Some(a), _) => Some(Some(a)),
            (None, b) => Some(b),
        }
    }

    fn add(self, other: Self) -> Option<Self> {
        Some(LinearForm {
            ireg: Self::merge_ireg(self.ireg, other.ireg)?,
            stride: self.stride.checked_add(other.stride)?,
            offset: self.offset.checked_add(other.offset)?,
        })
    }

    fn sub(self, other: Self) -> Option<Self> {
        Some(LinearForm {
            ireg: Self::merge_ireg(self.ireg, other.ireg)?,
            stride: self.stride.checked_sub(other.stride)?,
            offset: self.offset.checked_sub(other.offset)?,
        })
    }

    /// `(s₁·x + o₁)(s₂·x + o₂)` stays linear only when at least one side is constant
    /// (`s == 0`); a product of two variable-carrying forms is quadratic and gives up.
    fn mul(self, other: Self) -> Option<Self> {
        if self.ireg.is_some() && other.ireg.is_some() {
            return None;
        }
        Some(LinearForm {
            ireg: Self::merge_ireg(self.ireg, other.ireg)?,
            stride: self
                .stride
                .checked_mul(other.offset)?
                .checked_add(other.stride.checked_mul(self.offset)?)?,
            offset: self.offset.checked_mul(other.offset)?,
        })
    }

    /// Converts to a fold-able [`IndexExpr`] when the final coefficients are
    /// representable (see the type docs for why non-negativity is also what makes the
    /// fold exact). A form whose variable cancelled (`stride == 0`) is a constant.
    fn into_index_expr(self) -> Option<IndexExpr> {
        let offset = u32::try_from(self.offset).ok()?;
        let stride = u32::try_from(self.stride).ok()?;
        Some(match self.ireg {
            Some(ireg) if stride != 0 => IndexExpr::Affine {
                ireg,
                stride: stride as usize,
                offset: offset as usize,
            },
            _ => IndexExpr::Const(offset as usize),
        })
    }
}

/// Symbolically evaluates a field expression in address position ([`eval_to_address`]'s
/// operand) into a [`LinearForm`], without emitting any instruction or allocating any
/// register. `None` means the expression is not provably linear over a single bound
/// variable with representable coefficients — the caller falls back to the runtime
/// `ToIndex` path, so this is purely an optimization gate, never a semantics change.
fn eval_field_linear<F: PrimeField>(cg: &CodeGen<'_, F>, inst: &Instruction) -> Option<LinearForm> {
    // The exactness argument (see `LinearForm`) needs `stride·m + offset < p` for any
    // `u32`-ranged mirror value `m`, i.e. a modulus of more than 65 bits. Both supported
    // curves are ~254-bit; this guard keeps the fold sound should that ever change.
    if F::MODULUS_BIT_SIZE <= 65 {
        return None;
    }
    match inst {
        Instruction::Value(vb) => Some(LinearForm::constant(super::stmt::const_as_u32(cg, vb)?)),
        Instruction::Load(lb) => match folded_index_binding(cg, lb)? {
            IndexExpr::Affine {
                ireg,
                stride: 1,
                offset: 0,
            } => Some(LinearForm {
                ireg: Some(ireg),
                stride: 1,
                offset: 0,
            }),
            IndexExpr::Const(value) => Some(LinearForm::constant(u32::try_from(value).ok()?)),
            _ => None,
        },
        Instruction::Compute(cb) if cb.stack.len() == 2 => {
            let a = eval_field_linear(cg, &cb.stack[0])?;
            let b = eval_field_linear(cg, &cb.stack[1])?;
            match cb.op {
                OperatorType::Add => a.add(b),
                OperatorType::Sub => a.sub(b),
                OperatorType::Mul => a.mul(b),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolves whether `lb` (the operand of a `ToAddress`) is a `Load` of a variable already
/// bound to something index position can fold directly, without any runtime conversion:
/// its address must resolve (via [`static_const_slot`]) to a statically-known variable
/// slot, and that slot must currently carry either
/// [`Binding::IReg`](crate::codegen::env::Binding::IReg) — the mirror a conforming loop's
/// induction variable maintains (see [`crate::codegen::stmt::lower_loop`]) — which folds
/// to `Affine`, or [`Binding::ConstUsize`](crate::codegen::env::Binding::ConstUsize) — an
/// unrolled iteration's induction variable — which folds to `Const`.
fn folded_index_binding<F: PrimeField>(cg: &CodeGen<'_, F>, lb: &LoadBucket) -> Option<IndexExpr> {
    if !matches!(lb.address_type, AddressType::Variable) {
        return None;
    }
    let LocationRule::Indexed { location, .. } = &lb.src else {
        return None;
    };
    let slot = static_const_slot(location)?;
    match cg.env.get(slot) {
        Some(Binding::IReg { ireg }) => Some(IndexExpr::Affine {
            ireg,
            stride: 1,
            offset: 0,
        }),
        Some(Binding::ConstUsize(v)) => Some(IndexExpr::Const(v)),
        _ => None,
    }
}

/// Resolves an address sub-tree to a statically-known variable slot *without* evaluating
/// it through [`eval_index`] (which may emit code for the non-trivial cases): only a bare
/// `Value(U32)` leaf — the shape a plain scalar variable's own address always takes —
/// counts; anything else (an `AddAddress`/`MulAddress`/`ToAddress` node, always present
/// for genuine array element addressing, since arrays occupy their own disjoint slot
/// range) returns `None`. Shared by loop conformance detection
/// ([`crate::codegen::stmt::lower_loop`]) and [`folded_index_binding`], both of which need
/// this *before* any code is emitted for the instruction being inspected.
pub(super) fn static_const_slot(loc: &Instruction) -> Option<usize> {
    match loc {
        Instruction::Value(vb) if vb.parse_as == ValueType::U32 => Some(vb.value),
        _ => None,
    }
}

/// Resolves a [`LocationRule`] used for subcomponent signal access
/// (`AddressType::SubcmpSignal`'s own `src`/`dest`) to `(addr, mapped)` — the pair
/// [`Instr::InputSub`]/[`Instr::OutputSub`] need. `Indexed` is the ordinary case (`mapped:
/// None`); `Mapped` resolves its `indexes` via [`eval_mapped_indexes`] and carries
/// `signal_code` through as `mapped: Some(_)` (old :401-406/:263-266's `PushIndex`/
/// `(true, signal_code)` split).
pub(super) fn eval_subcmp_location<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    loc: &LocationRule,
) -> Result<(Addr, Option<u32>)> {
    match loc {
        LocationRule::Indexed { location, .. } => Ok((eval_index(cg, location)?.to_addr(), None)),
        LocationRule::Mapped {
            signal_code,
            indexes,
        } => {
            let addr = eval_mapped_indexes(cg, indexes)?.to_addr();
            Ok((addr, Some(u32::try_from(*signal_code)?)))
        }
    }
}

/// Resolves a `Mapped` location's `indexes` (old `handle_access_type`, old :289-301) to a
/// single [`IndexExpr`]: empty is a plain (non-array) mapped signal — `Const(0)` (old
/// :401-406's `PushIndex(0)` special case) — and exactly one [`AccessType::Indexed`] with
/// exactly one inner instruction is an array-element mapped signal with a single flattened
/// offset expression (the only two shapes any real circuit in this crate's KAT corpus
/// produces — confirmed empirically). Anything else (an [`AccessType::Qualified`] bus-field
/// selector, or more than one entry/inner instruction) is circom's *bus* feature, which old
/// itself never correctly supported either (`handle_access_type` just pushes every entry
/// without ever combining them, so old's own stack-based VM would silently miscompute —
/// not merely bail — on that IR shape): rather than reproduce that latent bug, this bails
/// clearly.
fn eval_mapped_indexes<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    indexes: &[AccessType],
) -> Result<IndexExpr> {
    match indexes {
        [] => Ok(IndexExpr::Const(0)),
        [AccessType::Indexed(info)] => match info.indexes.as_slice() {
            [] => Ok(IndexExpr::Const(0)),
            [single] => eval_index(cg, single),
            _ => bail!(
                "Mapped subcomponent signal access with a multi-dimensional index (bus \
                 type?) is not supported"
            ),
        },
        _ => bail!(
            "Mapped subcomponent signal access with {} index entries (bus type?) is not \
             supported",
            indexes.len()
        ),
    }
}

/// The two address-domain binary operators [`fold`] handles.
#[derive(Debug, Clone, Copy)]
enum FoldOp {
    /// `AddAddress`.
    Add,
    /// `MulAddress`.
    Mul,
}

impl FoldOp {
    /// Applies the operator to two compile-time-known `usize` operands.
    fn apply_const(self, a: usize, b: usize) -> usize {
        match self {
            FoldOp::Add => a + b,
            FoldOp::Mul => a * b,
        }
    }

    /// Applies the operator to an [`IndexExpr::Affine`]'s `(stride, offset)` and a
    /// constant `c`: `Add` only shifts the offset; `Mul` scales both.
    fn apply_affine_const(self, stride: usize, offset: usize, c: usize) -> (usize, usize) {
        match self {
            FoldOp::Add => (stride, offset + c),
            FoldOp::Mul => (stride * c, offset * c),
        }
    }

    /// The runtime instruction constructor for the case that can't be folded away.
    fn emit(self, dst: u8, a: ISrc, b: ISrc) -> Instr {
        match self {
            FoldOp::Add => Instr::IAdd { dst, a, b },
            FoldOp::Mul => Instr::IMul { dst, a, b },
        }
    }
}

/// Purely-symbolic folding for `AddAddress`/`MulAddress`: `Const∘Const` folds outright;
/// `Affine∘Const`/`Const∘Affine` adjusts the affine's `stride`/`offset` in place with no
/// runtime cost. Returns `None` when neither applies (both operands are non-constant —
/// `Affine∘Affine`, `Affine∘Dynamic`, `Dynamic∘Dynamic`, ...), in which case the caller
/// must materialize both operands into integer registers and emit the runtime op.
fn try_fold_const(op: FoldOp, a: IndexExpr, b: IndexExpr) -> Option<IndexExpr> {
    use IndexExpr::*;
    match (a, b) {
        (Const(x), Const(y)) => Some(Const(op.apply_const(x, y))),
        (
            Affine {
                ireg,
                stride,
                offset,
            },
            Const(c),
        )
        | (
            Const(c),
            Affine {
                ireg,
                stride,
                offset,
            },
        ) => {
            let (stride, offset) = op.apply_affine_const(stride, offset, c);
            Some(Affine {
                ireg,
                stride,
                offset,
            })
        }
        _ => None,
    }
}

/// Folds `a op b`, materializing both operands into integer registers and emitting the
/// runtime instruction when [`try_fold_const`] can't fold them away symbolically.
fn fold<F: PrimeField>(
    cg: &mut CodeGen<'_, F>,
    op: FoldOp,
    a: IndexExpr,
    b: IndexExpr,
) -> Result<IndexExpr> {
    if let Some(folded) = try_fold_const(op, a, b) {
        return Ok(folded);
    }
    let a = to_isrc(cg, a)?;
    let b = to_isrc(cg, b)?;
    let dst = cg.alloc_ireg()?;
    cg.instrs.push(op.emit(dst, a, b));
    Ok(IndexExpr::Dynamic(dst))
}

/// Materializes an [`IndexExpr`] into an [`ISrc`] readable by `IAdd`/`IMul`: a `Const`
/// needs no register at all (it's an immediate); a `Dynamic` is already a register; an
/// `Affine` is computed into a fresh register via `IMul` (skipped when `stride == 1`)
/// followed by `IAdd` (skipped when `offset == 0`).
fn to_isrc<F: PrimeField>(cg: &mut CodeGen<'_, F>, e: IndexExpr) -> Result<ISrc> {
    Ok(match e {
        IndexExpr::Const(c) => ISrc::Const(as_u32_checked(c)?),
        IndexExpr::Dynamic(ireg) => ISrc::Reg(ireg),
        IndexExpr::Affine {
            ireg,
            stride,
            offset,
        } => {
            let base = if stride == 1 {
                ireg
            } else {
                let dst = cg.alloc_ireg()?;
                cg.instrs.push(Instr::IMul {
                    dst,
                    a: ISrc::Reg(ireg),
                    b: ISrc::Const(as_u32_checked(stride)?),
                });
                dst
            };
            if offset == 0 {
                ISrc::Reg(base)
            } else {
                let dst = cg.alloc_ireg()?;
                cg.instrs.push(Instr::IAdd {
                    dst,
                    a: ISrc::Reg(base),
                    b: ISrc::Const(as_u32_checked(offset)?),
                });
                ISrc::Reg(dst)
            }
        }
    })
}

/// Fallible `usize -> u32` conversion for values that end up as an `ISrc::Const`
/// immediate (as opposed to [`as_u32`], used only once an `IndexExpr` is fully folded and
/// about to become an `Addr`).
fn as_u32_checked(v: usize) -> Result<u32> {
    u32::try_from(v).map_err(|_| eyre!("index constant {v} exceeds u32 range"))
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
    fn const_add_const_folds() {
        let r = try_fold_const(FoldOp::Add, IndexExpr::Const(2), IndexExpr::Const(3));
        assert_eq!(r, Some(IndexExpr::Const(5)));
    }

    #[test]
    fn const_mul_const_folds() {
        let r = try_fold_const(FoldOp::Mul, IndexExpr::Const(2), IndexExpr::Const(3));
        assert_eq!(r, Some(IndexExpr::Const(6)));
    }

    #[test]
    fn affine_add_const_shifts_offset_only() {
        let affine = IndexExpr::Affine {
            ireg: 4,
            stride: 3,
            offset: 10,
        };
        let r = try_fold_const(FoldOp::Add, affine, IndexExpr::Const(5));
        assert_eq!(
            r,
            Some(IndexExpr::Affine {
                ireg: 4,
                stride: 3,
                offset: 15,
            })
        );
    }

    #[test]
    fn const_add_affine_is_commutative() {
        let affine = IndexExpr::Affine {
            ireg: 4,
            stride: 3,
            offset: 10,
        };
        let r = try_fold_const(FoldOp::Add, IndexExpr::Const(5), affine);
        assert_eq!(
            r,
            Some(IndexExpr::Affine {
                ireg: 4,
                stride: 3,
                offset: 15,
            })
        );
    }

    #[test]
    fn affine_mul_const_scales_stride_and_offset() {
        let affine = IndexExpr::Affine {
            ireg: 1,
            stride: 3,
            offset: 10,
        };
        let r = try_fold_const(FoldOp::Mul, affine, IndexExpr::Const(4));
        assert_eq!(
            r,
            Some(IndexExpr::Affine {
                ireg: 1,
                stride: 12,
                offset: 40,
            })
        );
    }

    #[test]
    fn const_mul_affine_scales_stride_and_offset() {
        let affine = IndexExpr::Affine {
            ireg: 1,
            stride: 3,
            offset: 10,
        };
        let r = try_fold_const(FoldOp::Mul, IndexExpr::Const(4), affine);
        assert_eq!(
            r,
            Some(IndexExpr::Affine {
                ireg: 1,
                stride: 12,
                offset: 40,
            })
        );
    }

    #[test]
    fn affine_op_affine_does_not_fold_symbolically() {
        let a = IndexExpr::Affine {
            ireg: 1,
            stride: 1,
            offset: 0,
        };
        let b = IndexExpr::Affine {
            ireg: 2,
            stride: 1,
            offset: 0,
        };
        assert_eq!(try_fold_const(FoldOp::Add, a, b), None);
        assert_eq!(try_fold_const(FoldOp::Mul, a, b), None);
    }

    #[test]
    fn fold_affine_add_affine_materializes_both_and_emits_iadd() {
        let mut cg = cg();
        let a = IndexExpr::Affine {
            ireg: 1,
            stride: 2,
            offset: 3,
        };
        let b = IndexExpr::Affine {
            ireg: 5,
            stride: 1,
            offset: 0,
        };
        let r = fold(&mut cg, FoldOp::Add, a, b).unwrap();
        // `a` needs IMul (stride != 1) then IAdd (offset != 0) to materialize; `b` is
        // already unit-stride/zero-offset so it's used directly as ir5; then one more
        // IAdd combines both into the final Dynamic result.
        assert!(matches!(r, IndexExpr::Dynamic(_)));
        let iadd_count = cg
            .instrs
            .iter()
            .filter(|i| matches!(i, Instr::IAdd { .. }))
            .count();
        let imul_count = cg
            .instrs
            .iter()
            .filter(|i| matches!(i, Instr::IMul { .. }))
            .count();
        assert_eq!(imul_count, 1, "only `a`'s stride multiply is needed");
        assert_eq!(
            iadd_count, 2,
            "`a`'s offset add, plus the final combining add"
        );
    }

    #[test]
    fn fold_affine_mul_affine_materializes_both_and_emits_imul() {
        let mut cg = cg();
        let a = IndexExpr::Affine {
            ireg: 1,
            stride: 1,
            offset: 0,
        };
        let b = IndexExpr::Affine {
            ireg: 2,
            stride: 1,
            offset: 0,
        };
        let r = fold(&mut cg, FoldOp::Mul, a, b).unwrap();
        assert!(matches!(r, IndexExpr::Dynamic(_)));
        assert_eq!(
            cg.instrs,
            vec![Instr::IMul {
                dst: 0,
                a: ISrc::Reg(1),
                b: ISrc::Reg(2),
            }],
            "both operands are already unit-stride/zero-offset registers, so folding \
             is a single IMul with no materialization instructions"
        );
    }

    fn var(ireg: u8) -> LinearForm {
        LinearForm {
            ireg: Some(ireg),
            stride: 1,
            offset: 0,
        }
    }

    #[test]
    fn linear_form_folds_scale_and_shift() {
        // t*16 + 41 - 5 → Affine { stride: 16, offset: 36 }
        let form = var(0)
            .mul(LinearForm::constant(16))
            .unwrap()
            .add(LinearForm::constant(41))
            .unwrap()
            .sub(LinearForm::constant(5))
            .unwrap();
        assert_eq!(
            form.into_index_expr(),
            Some(IndexExpr::Affine {
                ireg: 0,
                stride: 16,
                offset: 36,
            })
        );
    }

    #[test]
    fn linear_form_negative_intermediates_cancel_exactly() {
        // 41 - t + 2*t → t + 41: the intermediate negative stride is exact over ℤ.
        let form = LinearForm::constant(41)
            .sub(var(3))
            .unwrap()
            .add(var(3).mul(LinearForm::constant(2)).unwrap())
            .unwrap();
        assert_eq!(
            form.into_index_expr(),
            Some(IndexExpr::Affine {
                ireg: 3,
                stride: 1,
                offset: 41,
            })
        );
    }

    #[test]
    fn linear_form_rejects_unrepresentable_final_coefficients() {
        // t*32 - 33: in range only for large enough t — must keep the runtime ToIndex
        // (and its range-error behavior), so the fold refuses the negative offset.
        let negative_offset = var(0)
            .mul(LinearForm::constant(32))
            .unwrap()
            .sub(LinearForm::constant(33))
            .unwrap();
        assert_eq!(negative_offset.into_index_expr(), None);

        // 33 - t: negative stride is not an Affine.
        let negative_stride = LinearForm::constant(33).sub(var(0)).unwrap();
        assert_eq!(negative_stride.into_index_expr(), None);
    }

    #[test]
    fn linear_form_cancelled_variable_is_a_constant() {
        let form = var(2)
            .add(LinearForm::constant(7))
            .unwrap()
            .sub(var(2))
            .unwrap();
        assert_eq!(form.into_index_expr(), Some(IndexExpr::Const(7)));
    }

    #[test]
    fn linear_form_rejects_two_variables_and_quadratics() {
        assert!(var(0).add(var(1)).is_none(), "two distinct registers");
        assert!(var(0).mul(var(0)).is_none(), "quadratic in one register");
        assert_eq!(
            var(0).add(var(0)).unwrap().into_index_expr(),
            Some(IndexExpr::Affine {
                ireg: 0,
                stride: 2,
                offset: 0,
            }),
            "the same register may appear on both sides"
        );
    }

    #[test]
    fn to_addr_converts_each_variant() {
        assert_eq!(IndexExpr::Const(7).to_addr(), Addr::Const(7));
        assert_eq!(
            IndexExpr::Affine {
                ireg: 2,
                stride: 3,
                offset: 4,
            }
            .to_addr(),
            Addr::Affine {
                ireg: 2,
                stride: 3,
                offset: 4,
            }
        );
        assert_eq!(IndexExpr::Dynamic(9).to_addr(), Addr::Dynamic(9));
    }
}
