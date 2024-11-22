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

    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
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

    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn is_zero(&mut self, val: Self::BrilligType) {
        todo!()
    }

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn lt(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

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
        todo!()
    }

    fn ge(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    fn to_radix(
        &self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        todo!()
    }

    fn expect_int(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        todo!()
    }
}
