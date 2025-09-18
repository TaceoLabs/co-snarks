use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};
use std::fmt::Debug;

use crate::plain_prover_flavour::PlainProverFlavour;

pub struct AllEntities<T, L>
where
    T: Default + Debug + Clone + std::marker::Sync,
    L: PlainProverFlavour,
{
    pub witness: L::WitnessEntities<T>,
    pub precomputed: L::PrecomputedEntities<T>,
    pub shifted_witness: L::ShiftedWitnessEntities<T>,
}

impl<T, L> AllEntities<T, L>
where
    T: Default + Clone + Debug + std::marker::Sync,
    L: PlainProverFlavour,
{
    pub fn from_elements(elements: Vec<T>) -> Self {
        let mut precomputed = elements;
        let mut witness = precomputed.split_off(L::PRECOMPUTED_ENTITIES_SIZE);
        let shifted_witness = witness.split_off(L::WITNESS_ENTITIES_SIZE);

        AllEntities {
            precomputed: L::PrecomputedEntities::from_elements(precomputed),
            witness: L::WitnessEntities::from_elements(witness),
            shifted_witness: L::ShiftedWitnessEntities::from_elements(shifted_witness),
        }
    }
}

impl<F, L> AllEntities<Vec<F>, L>
where
    F: Default + Clone + Debug + std::marker::Sync,
    L: PlainProverFlavour,
{
    pub fn get_row(&self, index: usize) -> AllEntities<F, L> {
        AllEntities::from_elements(self.iter().map(|el| el[index].clone()).collect())
    }
}

impl<T: Default + Clone + Debug + std::marker::Sync, L: PlainProverFlavour> Default
    for AllEntities<T, L>
{
    fn default() -> Self {
        Self {
            witness: L::WitnessEntities::default(),
            precomputed: L::PrecomputedEntities::default(),
            shifted_witness: L::ShiftedWitnessEntities::default(),
        }
    }
}

impl<T: Default + Clone + Debug + std::marker::Sync, L: PlainProverFlavour> AllEntities<T, L> {
    pub fn into_iterator(self) -> impl Iterator<Item = T> {
        self.precomputed
            .into_iter()
            .chain(self.witness.into_iter())
            .chain(self.shifted_witness.into_iter())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_witness.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.precomputed
            .iter_mut()
            .chain(self.witness.iter_mut())
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<T: Default + Clone + Debug + std::marker::Sync, L: PlainProverFlavour> AllEntities<Vec<T>, L> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }
}
