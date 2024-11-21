use std::marker::PhantomData;

use ark_ff::PrimeField;

use super::BrilligDriver;

#[derive(Default)]
pub struct PlainBrilligDriver<F: PrimeField> {
    phantom_data: PhantomData<F>,
}
impl<F: PrimeField> PlainBrilligDriver<F> {
    pub fn new() -> Self {
        Self {
            phantom_data: Default::default(),
        }
    }
}

impl<F: PrimeField> BrilligDriver<F> for PlainBrilligDriver<F> {
    type BrilligType = F;
}
