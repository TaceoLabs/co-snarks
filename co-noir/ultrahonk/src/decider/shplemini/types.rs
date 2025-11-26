use co_noir_common::polynomials::entities::{
    PrecomputedEntities, ShiftedWitnessEntities, WitnessEntities,
};

pub(crate) struct PolyF<'a, T: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<T>,
    pub(crate) witness: &'a WitnessEntities<T>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; 5],
}

pub(crate) struct PolyGShift<'a, T: Default> {
    pub(crate) wires: &'a ShiftedWitnessEntities<T>,
}

impl<T: Default> PolyF<'_, T> {
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
