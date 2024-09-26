use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::marker::PhantomData;
use ultrahonk::prelude::{Polynomial, PrecomputedEntities, ProverCrs};

pub struct ProvingKey<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) crs: ProverCrs<P>,
    pub(crate) circuit_size: u32,
    pub(crate) public_inputs: Vec<P::ScalarField>,
    pub(crate) num_public_inputs: u32,
    pub(crate) pub_inputs_offset: u32,
    // pub(crate) polynomials: Polynomials<P::ScalarField>,
    pub(crate) memory_read_records: Vec<u32>,
    pub(crate) memory_write_records: Vec<u32>,
    pub(crate) phantom_data: PhantomData<T>,
}

// This is what we get from the proving key, we shift at a later point
#[derive(Default)]
pub(crate) struct Polynomials<F: PrimeField> {
    // pub(crate) witness: ProverWitnessEntities<Polynomial<F>>,
    pub(crate) precomputed: PrecomputedEntities<Polynomial<F>>,
}

impl<F: PrimeField> Polynomials<F> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }

    // pub(crate) fn iter(&self) -> impl Iterator<Item = &Polynomial<F>> {
    //     self.witness.iter().chain(self.precomputed.iter())
    // }

    // pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Polynomial<F>> {
    //     self.witness.iter_mut().chain(self.precomputed.iter_mut())
    // }
}
