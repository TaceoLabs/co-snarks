use crate::types::WitnessEntities;
use ultrahonk::prelude::{PrecomputedEntities, ShiftedTableEntities, ShiftedWitnessEntities};

pub(crate) struct PolyF<'a, Shared: Default, Public: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<Public>,
    pub(crate) witness: &'a WitnessEntities<Shared, Public>,
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
