use std::marker::PhantomData;

use ark_ff::PrimeField;

use super::BrilligDriver;

#[derive(Default)]
pub struct ShamirBrilligDriver<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct ShamirBrilligType {}

impl<F: PrimeField> From<F> for ShamirBrilligType {
    fn from(value: F) -> Self {
        todo!()
    }
}

impl<F: PrimeField> BrilligDriver<F> for ShamirBrilligDriver<F> {
    type BrilligType = ShamirBrilligType;

    fn cast_to_int(&self, src: Self::BrilligType, bit_size: brillig::IntegerBitSize) -> u128 {
        todo!()
    }
}
