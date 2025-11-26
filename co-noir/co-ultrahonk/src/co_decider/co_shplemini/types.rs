use co_noir_common::polynomials::entities::{PrecomputedEntities, WitnessEntities};

pub(crate) struct PolyF<'a, Shared: Default, Public: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<Public>,
    pub(crate) witness: &'a WitnessEntities<Shared>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; 5],
}

impl<Shared: Default> PolyG<'_, Shared> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Shared> {
        self.wires.iter()
    }
}
