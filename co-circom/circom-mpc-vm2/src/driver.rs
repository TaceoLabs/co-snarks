//! The driver trait connecting the VM to an MPC protocol (or plain execution).
use crate::isa::BinOp;
use crate::program::VMConfig;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eyre::Result;
use std::fmt;

/// Protocol driver for the register VM. All scalar operations take operands by
/// reference; only results are moved. `_many` methods have scalar-loop defaults and
/// exist so protocol drivers can batch network communication (one round per call).
pub trait VmDriver<F: PrimeField>: Sized {
    /// The public value type.
    type Public: CanonicalSerialize + CanonicalDeserialize + Clone + Default;
    /// The arithmetic share type.
    type ArithmeticShare: CanonicalSerialize + CanonicalDeserialize + Clone + Default;
    /// The VM value type (public or shared).
    type VmType: Clone + fmt::Debug + Default;

    /// c = a + b
    fn add(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a - b
    fn sub(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a * b
    fn mul(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a / b (field inverse)
    fn div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a \ b (integer division)
    fn int_div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a ^ b
    fn pow(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a % b
    fn modulo(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = -a
    fn neg(&mut self, a: &Self::VmType) -> Result<Self::VmType>;
    /// c = a < b (1/0)
    fn lt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a <= b (1/0)
    fn le(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a > b (1/0)
    fn gt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a >= b (1/0)
    fn ge(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a == b (1/0)
    fn eq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a != b (1/0)
    fn neq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a >> b
    fn shift_r(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a << b
    fn shift_l(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = !a (a ∈ {0,1})
    fn bool_not(&mut self, a: &Self::VmType) -> Result<Self::VmType>;
    /// c = a && b (a, b ∈ {0,1})
    fn bool_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a || b (a, b ∈ {0,1})
    fn bool_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a ^ b (bitwise)
    fn bit_xor(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a | b (bitwise)
    fn bit_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = a & b (bitwise)
    fn bit_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType>;
    /// c = cond ? truthy : falsy (cond ∈ {0,1}, may be shared)
    fn cmux(
        &mut self,
        cond: &Self::VmType,
        truthy: &Self::VmType,
        falsy: &Self::VmType,
    ) -> Result<Self::VmType>;

    /// Whether a is zero, **as a plain bool**. If a is shared: errors unless
    /// `allow_secret_inputs`, in which case the value is opened.
    fn is_zero(&mut self, a: &Self::VmType, allow_secret_inputs: bool) -> Result<bool>;
    /// Whether a is a shared value.
    fn is_shared(&self, a: &Self::VmType) -> Result<bool>;
    /// Public field element → usize (errors on shared or out-of-range values).
    fn to_index(&mut self, a: &Self::VmType) -> Result<usize>;
    /// Open (reconstruct) a value.
    fn open(&mut self, a: &Self::VmType) -> Result<Self::Public>;
    /// Convert to an arithmetic share (promoting publics).
    fn to_share(&mut self, a: &Self::VmType) -> Result<Self::ArithmeticShare>;
    /// Public 1.
    fn public_one(&self) -> Self::VmType;
    /// Public 0.
    fn public_zero(&self) -> Self::VmType;
    /// Public value from a field element (constant-table injection).
    fn public_from(&self, f: F) -> Self::VmType;
    /// Cross-party VM-config consistency check (no-op for local drivers).
    fn compare_vm_config(&mut self, config: &VMConfig) -> Result<()>;
    /// String form for logging; secret values render as "secret" unless allowed.
    fn log(&mut self, a: &Self::VmType, allow_leaky_logs: bool) -> Result<String>;
    /// c = sqrt(a) (used by the sqrt function accelerator; Plan 3).
    fn sqrt(&mut self, a: &Self::VmType) -> Result<Self::VmType>;

    /// Vectorized binary op — the batching hook. Default: scalar loop.
    /// Protocol drivers override this per op-kind to use one communication round.
    fn bin_many(
        &mut self,
        op: BinOp,
        a: &[Self::VmType],
        b: &[Self::VmType],
    ) -> Result<Vec<Self::VmType>> {
        debug_assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b)
            .map(|(x, y)| apply_bin(self, op, x, y))
            .collect()
    }

    /// Vectorized cmux with a single condition. Default: scalar loop.
    fn cmux_many(
        &mut self,
        cond: &Self::VmType,
        truthy: &[Self::VmType],
        falsy: &[Self::VmType],
    ) -> Result<Vec<Self::VmType>> {
        debug_assert_eq!(truthy.len(), falsy.len());
        truthy
            .iter()
            .zip(falsy)
            .map(|(t, f)| self.cmux(cond, t, f))
            .collect()
    }
}

/// Dispatch a [`BinOp`] to the matching scalar driver method.
pub fn apply_bin<F: PrimeField, C: VmDriver<F>>(
    driver: &mut C,
    op: BinOp,
    a: &C::VmType,
    b: &C::VmType,
) -> Result<C::VmType> {
    match op {
        BinOp::Add => driver.add(a, b),
        BinOp::Sub => driver.sub(a, b),
        BinOp::Mul => driver.mul(a, b),
        BinOp::Div => driver.div(a, b),
        BinOp::IntDiv => driver.int_div(a, b),
        BinOp::Pow => driver.pow(a, b),
        BinOp::Mod => driver.modulo(a, b),
        BinOp::Lt => driver.lt(a, b),
        BinOp::Le => driver.le(a, b),
        BinOp::Gt => driver.gt(a, b),
        BinOp::Ge => driver.ge(a, b),
        BinOp::Eq => driver.eq(a, b),
        BinOp::Neq => driver.neq(a, b),
        BinOp::BoolOr => driver.bool_or(a, b),
        BinOp::BoolAnd => driver.bool_and(a, b),
        BinOp::BitOr => driver.bit_or(a, b),
        BinOp::BitAnd => driver.bit_and(a, b),
        BinOp::BitXor => driver.bit_xor(a, b),
        BinOp::ShiftR => driver.shift_r(a, b),
        BinOp::ShiftL => driver.shift_l(a, b),
    }
}
