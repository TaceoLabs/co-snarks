use std::marker::PhantomData;

use ark_ff::PrimeField;
use brillig::{BitSize, IntegerBitSize};

use super::BrilligDriver;

#[derive(Default)]
pub struct ShamirBrilligDriver<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct ShamirBrilligType<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField> From<F> for ShamirBrilligType<F> {
    fn from(value: F) -> Self {
        todo!()
    }
}

impl<F: PrimeField> BrilligDriver<F> for ShamirBrilligDriver<F> {
    type BrilligType = ShamirBrilligType<F>;

    fn cast(&self, src: Self::BrilligType, bit_size: BitSize) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize> {
        todo!()
    }

    fn try_into_bool(val: Self::BrilligType) -> eyre::Result<bool> {
        todo!()
    }

    fn constant(val: F, bit_size: BitSize) -> Self::BrilligType {
        todo!()
    }

    fn add_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn lt_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn not_franco(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn gt_franco(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn expect_int_bit_size(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn sub(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn is_zero(&mut self, val: Self::BrilligType) {
        todo!()
    }

    fn equal(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }
}
