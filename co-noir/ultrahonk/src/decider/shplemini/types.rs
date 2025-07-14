use crate::plain_prover_flavour::PlainProverFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
pub(crate) struct PolyF<'a, T: Default + Clone + std::marker::Sync, L: PlainProverFlavour> {
    pub(crate) precomputed: &'a L::PrecomputedEntities<T>,
    pub(crate) witness: &'a L::WitnessEntities<T>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; 5],
}

pub(crate) struct PolyGShift<'a, T: Default + std::marker::Sync, L: PlainProverFlavour> {
    pub(crate) wires: &'a L::ShiftedWitnessEntities<T>,
}

impl<T: Default + Clone + std::marker::Sync, L: PlainProverFlavour> PolyF<'_, T, L> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }
}

impl<T: Default> PolyG<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }
}

impl<T: Default + std::marker::Sync, L: PlainProverFlavour> PolyGShift<'_, T, L> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }
}
