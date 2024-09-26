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

#[allow(unused)]
impl<'a, T: Default> PolyF<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }
}

#[allow(unused)]
impl<'a, T: Default> PolyG<'a, T> {
    // Table Polys
    const TABLE_1: usize = 0;
    const TABLE_2: usize = 1;
    const TABLE_3: usize = 2;
    const TABLE_4: usize = 3;

    // Wire Polys
    const W_L: usize = 0;
    const W_R: usize = 1;
    const W_O: usize = 2;
    const W_4: usize = 3;

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables
            .into_iter()
            .chain(self.wires)
            .chain(std::iter::once(self.z_perm))
    }

    pub(crate) fn table_1(&self) -> &T {
        self.tables[Self::TABLE_1]
    }

    pub(crate) fn table_2(&self) -> &T {
        self.tables[Self::TABLE_2]
    }

    pub(crate) fn table_3(&self) -> &T {
        self.tables[Self::TABLE_3]
    }

    pub(crate) fn table_4(&self) -> &T {
        self.tables[Self::TABLE_4]
    }

    pub(crate) fn w_l(&self) -> &T {
        self.wires[Self::W_L]
    }

    pub(crate) fn w_r(&self) -> &T {
        self.wires[Self::W_R]
    }

    pub(crate) fn w_o(&self) -> &T {
        self.wires[Self::W_O]
    }

    pub(crate) fn w_4(&self) -> &T {
        self.wires[Self::W_4]
    }

    pub(crate) fn z_perm(&self) -> &T {
        self.z_perm
    }
}

#[allow(unused)]
impl<'a, T: Default> PolyGShift<'a, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.tables.iter().chain(self.wires.iter())
    }
}
