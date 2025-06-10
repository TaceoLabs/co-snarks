use ark_ff::PrimeField;
use co_builder::prelude::PrecomputedEntities;

use crate::{
    plain_prover_flavour::PlainProverFlavour,
    types::{ShiftedWitnessEntities, WitnessEntities},
};

pub(crate) struct PolyF<'a, T: Default, F: PrimeField, L: PlainProverFlavour<F>> {
    pub(crate) precomputed: &'a PrecomputedEntities<T, F, L>,
    pub(crate) witness: &'a WitnessEntities<T, F, L>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; 5],
}

pub(crate) struct PolyGShift<'a, T: Default> {
    pub(crate) wires: &'a ShiftedWitnessEntities<T>,
}

impl<T: Default, F: PrimeField, L: PlainProverFlavour<F>> PolyF<'_, T, F, L> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }
}

impl<T: Default> PolyG<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }
}

impl<T: Default> PolyGShift<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }
}
