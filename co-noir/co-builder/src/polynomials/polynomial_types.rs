use super::polynomial::Polynomial;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

// This is what we get from the proving key, we shift at a later point
#[derive(Default, Serialize, Deserialize)]
pub struct Polynomials<F: PrimeField> {
    pub witness: ProverWitnessEntities<Polynomial<F>>,
    pub precomputed: PrecomputedEntities<Polynomial<F>>,
}

impl<F: PrimeField> Polynomials<F> {
    pub fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Polynomial<F>> {
        self.witness.iter_mut().chain(self.precomputed.iter_mut())
    }
}

pub const PROVER_WITNESS_ENTITIES_SIZE: usize = 6;
#[derive(Default, Serialize, Deserialize)]
pub struct ProverWitnessEntities<T: Default> {
    pub elements: [T; PROVER_WITNESS_ENTITIES_SIZE],
}

pub const PRECOMPUTED_ENTITIES_SIZE: usize = 27;
#[derive(Default, Serialize, Deserialize)]
pub struct PrecomputedEntities<T: Default> {
    pub elements: [T; PRECOMPUTED_ENTITIES_SIZE],
}

impl<T: Default> IntoIterator for PrecomputedEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, PRECOMPUTED_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> IntoIterator for ProverWitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, PROVER_WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> ProverWitnessEntities<T> {
    /// column 0
    const W_L: usize = 0;
    /// column 1
    pub const W_R: usize = 1;
    /// column 2
    const W_O: usize = 2;
    /// column 3 (modified by prover)
    const W_4: usize = 3;
    /// column 6
    const LOOKUP_READ_COUNTS: usize = 4;
    /// column 7
    const LOOKUP_READ_TAGS: usize = 5;

    // const Z_PERM: usize = 4; // column 4 (computed by prover)
    // const LOOKUP_INVERSES: usize = 5; // column 5 (computed by prover);

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub fn into_wires(self) -> impl Iterator<Item = T> {
        self.elements
            .into_iter()
            // .skip(Self::W_L)
            .take(Self::W_4 + 1 - Self::W_L)
    }

    pub fn get_wires(&self) -> &[T] {
        &self.elements[Self::W_L..=Self::W_4]
    }

    pub fn get_wires_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::W_L..=Self::W_4]
    }

    pub fn w_l(&self) -> &T {
        &self.elements[Self::W_L]
    }

    pub fn w_r(&self) -> &T {
        &self.elements[Self::W_R]
    }

    pub fn w_o(&self) -> &T {
        &self.elements[Self::W_O]
    }

    pub fn w_4(&self) -> &T {
        &self.elements[Self::W_4]
    }

    pub fn lookup_read_counts(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }

    pub fn lookup_read_counts_and_tags(&self) -> &[T] {
        &self.elements[Self::LOOKUP_READ_COUNTS..Self::LOOKUP_READ_TAGS + 1]
    }
    pub fn lookup_read_counts_and_tags_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::LOOKUP_READ_COUNTS..Self::LOOKUP_READ_TAGS + 1]
    }
}

impl<T: Default> PrecomputedEntities<T> {
    /// column 0
    const Q_M: usize = 0;
    /// column 1
    const Q_C: usize = 1;
    /// column 2
    const Q_L: usize = 2;
    /// column 3
    const Q_R: usize = 3;
    /// column 4
    const Q_O: usize = 4;
    /// column 5
    const Q_4: usize = 5;
    /// column 6
    const Q_ARITH: usize = 6;
    /// column 7
    const Q_DELTA_RANGE: usize = 7;
    /// column 8
    const Q_ELLIPTIC: usize = 8;
    /// column 9
    const Q_AUX: usize = 9;
    /// column 10
    const Q_LOOKUP: usize = 10;
    /// column 11
    const Q_POSEIDON2_EXTERNAL: usize = 11;
    /// column 12
    const Q_POSEIDON2_INTERNAL: usize = 12;
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

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub fn get_table_polynomials(&self) -> &[T] {
        &self.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    pub fn get_selectors_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::Q_M..=Self::Q_POSEIDON2_INTERNAL]
    }

    pub fn get_sigmas_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::SIGMA_1..=Self::SIGMA_4]
    }

    pub fn get_ids_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::ID_1..=Self::ID_4]
    }

    pub fn get_table_polynomials_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    pub fn q_m(&self) -> &T {
        &self.elements[Self::Q_M]
    }

    pub fn q_c(&self) -> &T {
        &self.elements[Self::Q_C]
    }

    pub fn q_l(&self) -> &T {
        &self.elements[Self::Q_L]
    }

    pub fn q_r(&self) -> &T {
        &self.elements[Self::Q_R]
    }

    pub fn q_o(&self) -> &T {
        &self.elements[Self::Q_O]
    }

    pub fn q_4(&self) -> &T {
        &self.elements[Self::Q_4]
    }

    pub fn q_arith(&self) -> &T {
        &self.elements[Self::Q_ARITH]
    }

    pub fn q_delta_range(&self) -> &T {
        &self.elements[Self::Q_DELTA_RANGE]
    }

    pub fn q_elliptic(&self) -> &T {
        &self.elements[Self::Q_ELLIPTIC]
    }

    pub fn q_aux(&self) -> &T {
        &self.elements[Self::Q_AUX]
    }

    pub fn q_lookup(&self) -> &T {
        &self.elements[Self::Q_LOOKUP]
    }

    pub fn q_poseidon2_external(&self) -> &T {
        &self.elements[Self::Q_POSEIDON2_EXTERNAL]
    }

    pub fn q_poseidon2_internal(&self) -> &T {
        &self.elements[Self::Q_POSEIDON2_INTERNAL]
    }

    pub fn sigma_1(&self) -> &T {
        &self.elements[Self::SIGMA_1]
    }

    pub fn sigma_2(&self) -> &T {
        &self.elements[Self::SIGMA_2]
    }

    pub fn sigma_3(&self) -> &T {
        &self.elements[Self::SIGMA_3]
    }

    pub fn sigma_4(&self) -> &T {
        &self.elements[Self::SIGMA_4]
    }

    pub fn id_1(&self) -> &T {
        &self.elements[Self::ID_1]
    }

    pub fn id_2(&self) -> &T {
        &self.elements[Self::ID_2]
    }

    pub fn id_3(&self) -> &T {
        &self.elements[Self::ID_3]
    }

    pub fn id_4(&self) -> &T {
        &self.elements[Self::ID_4]
    }

    pub fn table_1(&self) -> &T {
        &self.elements[Self::TABLE_1]
    }

    pub fn table_2(&self) -> &T {
        &self.elements[Self::TABLE_2]
    }

    pub fn table_3(&self) -> &T {
        &self.elements[Self::TABLE_3]
    }

    pub fn table_4(&self) -> &T {
        &self.elements[Self::TABLE_4]
    }

    pub fn lagrange_first(&self) -> &T {
        &self.elements[Self::LAGRANGE_FIRST]
    }

    pub fn lagrange_last(&self) -> &T {
        &self.elements[Self::LAGRANGE_LAST]
    }

    pub fn lagrange_first_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LAGRANGE_FIRST]
    }

    pub fn lagrange_last_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LAGRANGE_LAST]
    }
}
