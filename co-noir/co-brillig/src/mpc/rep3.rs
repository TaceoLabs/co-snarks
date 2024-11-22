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

    fn gt(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
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

    fn to_radix(
        &self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
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
