use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

use crate::plain_prover_flavour::PlainProverFlavour;

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
