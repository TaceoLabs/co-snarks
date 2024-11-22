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
    fn from(_value: F) -> Self {
        todo!()
    }
}

impl<F: PrimeField> BrilligDriver<F> for ShamirBrilligDriver<F> {
    type BrilligType = ShamirBrilligType<F>;

    fn cast(&self, _src: Self::BrilligType, _bit_size: BitSize) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn try_into_usize(_val: Self::BrilligType) -> eyre::Result<usize> {
        todo!()
    }

    fn try_into_bool(_val: Self::BrilligType) -> eyre::Result<bool> {
        todo!()
    }

    fn constant(_val: F, _bit_size: BitSize) -> Self::BrilligType {
        todo!()
    }

    fn add(
        &self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn sub(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn mul(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn div(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn int_div(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn is_zero(&mut self, _val: Self::BrilligType) {
        todo!()
    }

    fn not(&self, _val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn eq(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn lt(
        &self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
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
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
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
        _val: Self::BrilligType,
        _radix: Self::BrilligType,
        _output_size: usize,
        _bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        todo!()
    }

    fn expect_int(
        _val: Self::BrilligType,
        _bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn expect_field(_val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        todo!()
    }
}
