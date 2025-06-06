use ark_ff::PrimeField;
use co_builder::{
    HonkProofResult,
    polynomials::polynomial_flavours::{
        PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
    },
    prelude::Serialize,
};

use crate::plain_prover_flavour::PlainProverFlavour;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: PrimeField> {
    proof: Vec<F>,
}

impl<F: PrimeField> HonkProof<F> {
    pub(crate) fn new(proof: Vec<F>) -> Self {
        Self { proof }
    }

    pub fn inner(self) -> Vec<F> {
        self.proof
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        Serialize::to_buffer(&self.proof, false)
    }

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let res = Serialize::from_buffer(buf, false)?;
        Ok(Self::new(res))
    }

    pub fn separate_proof_and_public_inputs(self, num_public_inputs: usize) -> (Self, Vec<F>) {
        let (public_inputs, proof) = self.proof.split_at(num_public_inputs);
        (Self::new(proof.to_vec()), public_inputs.to_vec())
    }

    pub fn insert_public_inputs(self, public_inputs: Vec<F>) -> Self {
        let mut proof = public_inputs;
        proof.extend(self.proof.to_owned());
        Self::new(proof)
    }
}

pub struct AllEntities<T: Default + Clone + std::marker::Sync, L: PlainProverFlavour> {
    pub(crate) witness: L::WitnessEntities<T>,
    pub(crate) precomputed: L::PrecomputedEntities<T>,
    pub(crate) shifted_witness: L::ShiftedWitnessEntities<T>,
}

impl<T: Default + Clone + std::marker::Sync, L: PlainProverFlavour> Default for AllEntities<T, L> {
    fn default() -> Self {
        Self {
            witness: L::WitnessEntities::default(),
            precomputed: L::PrecomputedEntities::default(),
            shifted_witness: L::ShiftedWitnessEntities::default(),
        }
    }
}

impl<T: Default + Clone + std::marker::Sync, L: PlainProverFlavour> AllEntities<T, L> {
    pub(crate) fn into_iter(self) -> impl Iterator<Item = T> {
        self.precomputed
            .into_iter()
            .chain(self.witness.into_iter())
            .chain(self.shifted_witness.into_iter())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_witness.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.precomputed
            .iter_mut()
            .chain(self.witness.iter_mut())
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<T: Default + Clone + std::marker::Sync, L: PlainProverFlavour> AllEntities<Vec<T>, L> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }
}
