use std::marker::PhantomData;

use ark_ff::PrimeField;

use super::BrilligDriver;

#[derive(Default)]
pub struct Rep3BrilligDriver<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Rep3BrilligType {}

impl<F: PrimeField> From<F> for Rep3BrilligType {
    fn from(value: F) -> Self {
        todo!()
    }
}

impl<F: PrimeField> BrilligDriver<F> for Rep3BrilligDriver<F> {
    type BrilligType = Rep3BrilligType;
}
