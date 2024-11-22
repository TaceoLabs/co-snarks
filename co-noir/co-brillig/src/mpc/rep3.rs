use std::marker::PhantomData;

use ark_ff::PrimeField;
use brillig::{BitSize, IntegerBitSize};
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use mpc_core::protocols::rep3_ring::{Rep3BitShare, Rep3RingShare};

use super::BrilligDriver;

#[derive(Default)]
pub struct Rep3BrilligDriver<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Rep3BrilligType<F: PrimeField> {
    Public(Public<F>),
    Shared(Shared<F>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Public<F: PrimeField> {
    Field(F),
    Int(u128),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Shared<F: PrimeField> {
    Field(Rep3PrimeFieldShare<F>),
    Ring128(Rep3RingShare<u128>),
    Ring64(Rep3RingShare<u64>),
    Ring32(Rep3RingShare<u32>),
    Ring16(Rep3RingShare<u16>),
    Ring8(Rep3RingShare<u8>),
    Ring1(Rep3BitShare),
}

impl<F: PrimeField> From<F> for Rep3BrilligType<F> {
    fn from(value: F) -> Self {
        Rep3BrilligType::Public(Public::Field(value))
    }
}

impl<F: PrimeField> Default for Rep3BrilligType<F> {
    fn default() -> Self {
        Self::from(F::default())
    }
}

impl<F: PrimeField> BrilligDriver<F> for Rep3BrilligDriver<F> {
    type BrilligType = Rep3BrilligType<F>;

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

    fn gt(
        &self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
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

    fn to_radix(
        &self,
        _val: Self::BrilligType,
        _radix: Self::BrilligType,
        _output_size: usize,
        _bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
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

    fn ge(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }
}
