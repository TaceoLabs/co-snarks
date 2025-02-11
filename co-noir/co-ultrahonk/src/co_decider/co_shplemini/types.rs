use co_builder::prelude::PrecomputedEntities;
use std::iter;
use ultrahonk::prelude::WitnessEntities;

pub(crate) struct PolyF<'a, Shared: Default, Public: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<Public>,
    pub(crate) witness: &'a WitnessEntities<Shared>,
}

pub(crate) struct PolyG<'a, Shared: Default, Public: Default> {
    pub(crate) tables: [&'a Public; 4],
    pub(crate) wires: [&'a Shared; 4],
    pub(crate) z_perm: &'a Shared,
}

impl<Shared: Default, Public: Default> PolyG<'_, Shared, Public> {
    pub(crate) fn public_iter(&self) -> impl Iterator<Item = &Public> {
        self.tables.into_iter()
    }

    pub(crate) fn shared_iter(&self) -> impl Iterator<Item = &Shared> {
        self.wires.into_iter().chain(iter::once(self.z_perm))
    }
}
