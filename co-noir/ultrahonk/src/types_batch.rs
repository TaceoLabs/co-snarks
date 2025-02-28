use co_builder::prelude::PrecomputedEntities;

use crate::types::{ShiftedWitnessEntities, WitnessEntities};

const WITNESS_ENTITIES_SIZE: usize = 8;
#[derive(Default)]
pub struct WitnessEntitiesBatch<T> {
    pub(crate) elements: [Vec<T>; WITNESS_ENTITIES_SIZE],
}

pub const PRECOMPUTED_ENTITIES_SIZE: usize = 27;
#[derive(Default)]
pub struct PrecomputedEntitiesBatch<T: Default> {
    pub elements: [Vec<T>; PRECOMPUTED_ENTITIES_SIZE],
}

const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
#[derive(Default)]
pub struct ShiftedWitnessEntitiesBatch<T: Default> {
    pub(crate) elements: [Vec<T>; SHIFTED_WITNESS_ENTITIES_SIZE],
}

impl<T: Default> IntoIterator for WitnessEntitiesBatch<T> {
    type Item = Vec<T>;
    type IntoIter = std::array::IntoIter<Vec<T>, WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> WitnessEntitiesBatch<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::with_capacity(capacity)),
        }
    }

    pub fn add(&mut self, witness_entity: WitnessEntities<T>) {
        for (src, dst) in witness_entity.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> PrecomputedEntitiesBatch<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::with_capacity(capacity)),
        }
    }

    pub fn add(&mut self, precomputed_entities: PrecomputedEntities<T>) {
        for (src, dst) in precomputed_entities.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> ShiftedWitnessEntitiesBatch<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::with_capacity(capacity)),
        }
    }

    pub fn add(&mut self, shifted_witness_entities: ShiftedWitnessEntities<T>) {
        for (src, dst) in shifted_witness_entities.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> IntoIterator for ShiftedWitnessEntitiesBatch<T> {
    type Item = Vec<T>;
    type IntoIter = std::array::IntoIter<Vec<T>, SHIFTED_WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> WitnessEntitiesBatch<T> {
    /// column 0
    const W_L: usize = 0;
    /// column 1
    const W_R: usize = 1;
    /// column 2
    const W_O: usize = 2;
    /// column 3 (computed by prover)
    const W_4: usize = 3;
    /// column 4 (computed by prover)
    const Z_PERM: usize = 4;
    /// column 5 (computed by prover);
    pub(crate) const LOOKUP_INVERSES: usize = 5;
    /// column 6
    pub(crate) const LOOKUP_READ_COUNTS: usize = 6;
    /// column 7
    pub(crate) const LOOKUP_READ_TAGS: usize = 7;

    pub fn iter(&self) -> impl Iterator<Item = &Vec<T>> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Vec<T>> {
        self.elements.iter_mut()
    }

    pub fn to_be_shifted_mut(&mut self) -> &mut [Vec<T>] {
        &mut self.elements[Self::W_L..=Self::Z_PERM]
    }

    pub fn w_l(&self) -> &[T] {
        &self.elements[Self::W_L]
    }

    pub fn w_r(&self) -> &[T] {
        &self.elements[Self::W_R]
    }

    pub fn w_o(&self) -> &[T] {
        &self.elements[Self::W_O]
    }

    pub fn w_4(&self) -> &[T] {
        &self.elements[Self::W_4]
    }

    pub fn z_perm(&self) -> &[T] {
        &self.elements[Self::Z_PERM]
    }

    pub fn lookup_inverses(&self) -> &[T] {
        &self.elements[Self::LOOKUP_INVERSES]
    }

    pub fn lookup_read_counts(&self) -> &[T] {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags(&self) -> &[T] {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }

    pub fn lookup_inverses_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::LOOKUP_INVERSES]
    }

    pub fn lookup_read_counts_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::LOOKUP_READ_TAGS]
    }
}

impl<T: Default> IntoIterator for PrecomputedEntitiesBatch<T> {
    type Item = Vec<T>;
    type IntoIter = std::array::IntoIter<Vec<T>, PRECOMPUTED_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> PrecomputedEntitiesBatch<T> {
    /// column 0
    pub(crate) const Q_M: usize = 0;
    /// column 1
    pub(crate) const Q_C: usize = 1;
    /// column 2
    pub(crate) const Q_L: usize = 2;
    /// column 3
    pub(crate) const Q_R: usize = 3;
    /// column 4
    pub(crate) const Q_O: usize = 4;
    /// column 5
    pub(crate) const Q_4: usize = 5;
    /// column 6
    pub(crate) const Q_LOOKUP: usize = 6;
    /// column 7
    pub(crate) const Q_ARITH: usize = 7;
    /// column 8
    pub(crate) const Q_DELTA_RANGE: usize = 8;
    /// column 9
    pub(crate) const Q_ELLIPTIC: usize = 9;
    /// column 10
    pub(crate) const Q_AUX: usize = 10;
    /// column 11
    pub(crate) const Q_POSEIDON2_EXTERNAL: usize = 11;
    /// column 12
    pub(crate) const Q_POSEIDON2_INTERNAL: usize = 12;
    /// column 13
    const SIGMA_1: usize = 13;
    /// column 14
    const SIGMA_2: usize = 14;
    /// column 15
    const SIGMA_3: usize = 15;
    /// column 16
    const SIGMA_4: usize = 16;
    /// column 17
    const ID_1: usize = 17;
    /// column 18
    const ID_2: usize = 18;
    /// column 19
    const ID_3: usize = 19;
    /// column 20
    const ID_4: usize = 20;
    /// column 21
    const TABLE_1: usize = 21;
    /// column 22
    const TABLE_2: usize = 22;
    /// column 23
    const TABLE_3: usize = 23;
    /// column 24
    const TABLE_4: usize = 24;
    /// column 25
    const LAGRANGE_FIRST: usize = 25;
    /// column 26
    const LAGRANGE_LAST: usize = 26;

    pub fn iter(&self) -> impl Iterator<Item = &Vec<T>> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Vec<T>> {
        self.elements.iter_mut()
    }

    pub fn get_table_polynomials(&self) -> &[Vec<T>] {
        &self.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    pub fn get_selectors_mut(&mut self) -> &mut [Vec<T>] {
        &mut self.elements[Self::Q_M..=Self::Q_POSEIDON2_INTERNAL]
    }

    pub fn get_sigmas_mut(&mut self) -> &mut [Vec<T>] {
        &mut self.elements[Self::SIGMA_1..=Self::SIGMA_4]
    }

    pub fn get_ids_mut(&mut self) -> &mut [Vec<T>] {
        &mut self.elements[Self::ID_1..=Self::ID_4]
    }

    pub fn get_table_polynomials_mut(&mut self) -> &mut [Vec<T>] {
        &mut self.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    pub fn q_m(&self) -> &[T] {
        &self.elements[Self::Q_M]
    }

    pub fn q_c(&self) -> &[T] {
        &self.elements[Self::Q_C]
    }

    pub fn q_l(&self) -> &[T] {
        &self.elements[Self::Q_L]
    }

    pub fn q_r(&self) -> &[T] {
        &self.elements[Self::Q_R]
    }

    pub fn q_o(&self) -> &[T] {
        &self.elements[Self::Q_O]
    }

    pub fn q_4(&self) -> &[T] {
        &self.elements[Self::Q_4]
    }

    pub fn q_arith(&self) -> &[T] {
        &self.elements[Self::Q_ARITH]
    }

    pub fn q_delta_range(&self) -> &[T] {
        &self.elements[Self::Q_DELTA_RANGE]
    }

    pub fn q_elliptic(&self) -> &[T] {
        &self.elements[Self::Q_ELLIPTIC]
    }

    pub fn q_aux(&self) -> &[T] {
        &self.elements[Self::Q_AUX]
    }

    pub fn q_lookup(&self) -> &[T] {
        &self.elements[Self::Q_LOOKUP]
    }

    pub fn q_poseidon2_external(&self) -> &[T] {
        &self.elements[Self::Q_POSEIDON2_EXTERNAL]
    }

    pub fn q_poseidon2_internal(&self) -> &[T] {
        &self.elements[Self::Q_POSEIDON2_INTERNAL]
    }

    pub fn sigma_1(&self) -> &[T] {
        &self.elements[Self::SIGMA_1]
    }

    pub fn sigma_2(&self) -> &[T] {
        &self.elements[Self::SIGMA_2]
    }

    pub fn sigma_3(&self) -> &[T] {
        &self.elements[Self::SIGMA_3]
    }

    pub fn sigma_4(&self) -> &[T] {
        &self.elements[Self::SIGMA_4]
    }

    pub fn id_1(&self) -> &[T] {
        &self.elements[Self::ID_1]
    }

    pub fn id_2(&self) -> &[T] {
        &self.elements[Self::ID_2]
    }

    pub fn id_3(&self) -> &[T] {
        &self.elements[Self::ID_3]
    }

    pub fn id_4(&self) -> &[T] {
        &self.elements[Self::ID_4]
    }

    pub fn table_1(&self) -> &[T] {
        &self.elements[Self::TABLE_1]
    }

    pub fn table_2(&self) -> &[T] {
        &self.elements[Self::TABLE_2]
    }

    pub fn table_3(&self) -> &[T] {
        &self.elements[Self::TABLE_3]
    }

    pub fn table_4(&self) -> &[T] {
        &self.elements[Self::TABLE_4]
    }

    pub fn lagrange_first(&self) -> &[T] {
        &self.elements[Self::LAGRANGE_FIRST]
    }

    pub fn lagrange_last(&self) -> &[T] {
        &self.elements[Self::LAGRANGE_LAST]
    }

    pub fn lagrange_first_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::LAGRANGE_FIRST]
    }

    pub fn lagrange_last_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::LAGRANGE_LAST]
    }
}

impl<T: Default> ShiftedWitnessEntitiesBatch<T> {
    /// column 0
    const W_L: usize = 0;
    /// column 1
    const W_R: usize = 1;
    /// column 2
    const W_O: usize = 2;
    /// column 3
    const W_4: usize = 3;
    /// column 4
    const Z_PERM: usize = 4;

    pub fn iter(&self) -> impl Iterator<Item = &Vec<T>> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Vec<T>> {
        self.elements.iter_mut()
    }

    pub fn w_l(&self) -> &[T] {
        &self.elements[Self::W_L]
    }

    pub fn w_r(&self) -> &[T] {
        &self.elements[Self::W_R]
    }

    pub fn w_o(&self) -> &[T] {
        &self.elements[Self::W_O]
    }

    pub fn w_4(&self) -> &[T] {
        &self.elements[Self::W_4]
    }

    pub fn z_perm(&self) -> &[T] {
        &self.elements[Self::Z_PERM]
    }
}
