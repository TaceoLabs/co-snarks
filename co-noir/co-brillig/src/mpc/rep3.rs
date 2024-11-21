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
}
