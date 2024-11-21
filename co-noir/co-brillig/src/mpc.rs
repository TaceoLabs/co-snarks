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

    fn add_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    fn not_franco(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType>;

    fn lt_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    fn le_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.gt_franco(lhs, rhs)?;
        self.not_franco(gt)
    }

    fn gt_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt_franco(lhs, rhs)?;
        self.not_franco(gt)
    }

    fn ge_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt_franco(lhs, rhs)?;
        self.not_franco(gt)
    }

    fn expect_int_bit_size(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType>;
}
