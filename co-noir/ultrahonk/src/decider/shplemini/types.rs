use co_builder::prelude::PrecomputedEntities;

use crate::types::{ShiftedTableEntities, ShiftedWitnessEntities, WitnessEntities};

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

impl<T: Default> PolyF<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }

    pub(crate) fn len(&self) -> usize {
        self.precomputed.elements.len() + self.witness.elements.len()
    }
}

impl<T: Default> PolyG<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter().chain(self.wires)
    }

    pub(crate) fn len(&self) -> usize {
        self.tables.len() + self.wires.len()
    }
}

impl<T: Default> PolyGShift<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter().chain(self.wires.iter())
    }
}
