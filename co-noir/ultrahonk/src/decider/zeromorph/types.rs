use crate::types::{
    PrecomputedEntities, ShiftedTableEntities, ShiftedWitnessEntities, WitnessEntities,
};

pub(crate) struct PolyF<'a, T: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<T>,
    pub(crate) witness: &'a WitnessEntities<T>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) tables: [&'a T; 4],
    pub(crate) wires: [&'a T; 4],
    pub(crate) z_perm: &'a T,
}

pub(crate) struct PolyGShift<'a, T: Default> {
    pub(crate) tables: &'a ShiftedTableEntities<T>,
    pub(crate) wires: &'a ShiftedWitnessEntities<T>,
}

impl<'a, T: Default> PolyF<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }
}

impl<'a, T: Default> PolyG<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables
            .into_iter()
            .chain(self.wires)
            .chain(std::iter::once(self.z_perm))
    }
}

impl<'a, T: Default> PolyGShift<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter().chain(self.wires.iter())
    }
}
