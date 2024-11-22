use std::fmt;

use ark_ff::PrimeField;

mod plain;
mod rep3;
mod shamir;
use brillig::{BitSize, IntegerBitSize};
pub use plain::PlainBrilligDriver;
pub use rep3::Rep3BrilligDriver;
pub use shamir::ShamirBrilligDriver;

pub use plain::PlainBrilligType;
pub use rep3::Rep3BrilligType;
pub use shamir::ShamirBrilligType;

pub(super) mod acir_field_utils {
    use ark_ff::PrimeField;

    pub(super) fn to_u128<F: PrimeField>(val: F) -> u128 {
        let as_bigint = val.into_bigint();
        let limbs = as_bigint.as_ref();

        let mut result = limbs[0] as u128;
        if limbs.len() > 1 {
            let high_limb = limbs[1] as u128;
            result += high_limb << 64;
        }

        result
    }
}

pub trait BrilligDriver<F: PrimeField> {
    type BrilligType: Clone + Default + fmt::Debug + From<F> + PartialEq;

    fn cast(&self, src: Self::BrilligType, bit_size: BitSize) -> eyre::Result<Self::BrilligType>;

    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize>;
    fn try_into_bool(val: Self::BrilligType) -> eyre::Result<bool>;

    fn constant(val: F, bit_size: BitSize) -> Self::BrilligType;

    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    fn sub(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;
    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;
    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    fn is_zero(&mut self, val: Self::BrilligType); // -> ?

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType>;

    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    fn lt(&self, lhs: Self::BrilligType, rhs: Self::BrilligType)
        -> eyre::Result<Self::BrilligType>;

    fn le(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.gt(lhs, rhs)?;
        self.not(gt)
    }

    fn gt(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    fn ge(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    // is this simply a2b?
    fn to_radix(
        &self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>>;

    fn expect_int(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType>;

    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType>;
}
