use co_builder::prelude::PrecomputedEntities;
use std::iter;
use ultrahonk::prelude::{ShiftedTableEntities, ShiftedWitnessEntities, WitnessEntities};

pub(crate) struct PolyF<'a, Shared: Default, Public: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<Public>,
    pub(crate) witness: &'a WitnessEntities<Shared>,
}

pub(crate) struct PolyG<'a, Shared: Default, Public: Default> {
    pub(crate) tables: [&'a Public; 4],
    pub(crate) wires: [&'a Shared; 4],
    pub(crate) z_perm: &'a Shared,
}

pub(crate) struct PolyGShift<'a, T: Default> {
    pub(crate) tables: &'a ShiftedTableEntities<T>,
    pub(crate) wires: &'a ShiftedWitnessEntities<T>,
}

impl<'a, Shared: Default, Public: Default> PolyG<'a, Shared, Public> {
    pub(crate) fn public_iter(&self) -> impl Iterator<Item = &Public> {
        self.tables.into_iter()
    }

    pub(crate) fn shared_iter(&self) -> impl Iterator<Item = &Shared> {
        self.wires.into_iter().chain(iter::once(self.z_perm))
    }
}

impl<'a, T: Default> PolyGShift<'a, T> {
    pub(crate) fn tables_iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter()
    }

    pub(crate) fn wires_iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }

    pub(crate) fn public_iter(&self) -> impl Iterator<Item = &T> {
        self.tables_iter()
    }

    pub(crate) fn shared_iter(&self) -> impl Iterator<Item = &T> {
        self.wires_iter()
    }
}
