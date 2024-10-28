use crate::types::{
    PrecomputedEntities, ShiftedTableEntities, ShiftedWitnessEntities, WitnessEntities,
};

pub(crate) struct PolyF<'a, T: Default> {
    pub(crate) precomputed: &'a PrecomputedEntities<T>,
    pub(crate) witness: &'a WitnessEntities<T>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) tables: &'a [T; 4],
    pub(crate) wires: &'a [T; 5],
}

pub(crate) struct PolyGShift<'a, T: Default> {
    pub(crate) tables: &'a ShiftedTableEntities<T>,
    pub(crate) wires: &'a ShiftedWitnessEntities<T>,
}

impl<'a, T: Default> PolyF<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }

    pub(crate) fn len(&self) -> usize {
        self.precomputed.elements.len() + self.witness.elements.len()
    }
}

impl<'a, T: Default> PolyG<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter().chain(self.wires)
    }

    pub(crate) fn len(&self) -> usize {
        self.tables.len() + self.wires.len()
    }
}

impl<'a, T: Default> PolyGShift<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter().chain(self.wires.iter())
    }
}
