use crate::polynomials::polynomial::Polynomial;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

// This is what we get from the proving key, we shift at a later point
#[derive(Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Polynomials<Shared: Default, Public: Default>
where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    pub witness: ProverWitnessEntities<Polynomial<Shared>>,
    pub precomputed: PrecomputedEntities<Polynomial<Public>>,
}

impl<Shared: Clone + Default, Public: Clone + Default> Polynomials<Shared, Public>
where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    pub fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .witness
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        polynomials.precomputed.iter_mut().for_each(|el| {
            el.resize(circuit_size, Default::default());
        });

        polynomials
    }
}

#[derive(Default, Clone)]
pub struct AllEntities<Shared: Default, Public: Default> {
    pub witness: WitnessEntities<Shared>,
    pub precomputed: PrecomputedEntities<Public>,
    pub shifted_witness: ShiftedWitnessEntities<Shared>,
}

impl<Shared: Default + Debug, Public: Default + Debug> AllEntities<Shared, Public> {
    pub fn from_elements(mut shared_elements: Vec<Shared>, public_elements: Vec<Public>) -> Self {
        let precomputed: [Public; PRECOMPUTED_ENTITIES_SIZE] = public_elements
            .try_into()
            .expect("Incorrect number of public elements provided to AllEntities::from_elements");
        let shifted_witness: [Shared; SHIFTED_WITNESS_ENTITIES_SIZE] = shared_elements
            .split_off(WITNESS_ENTITIES_SIZE)
            .try_into()
            .expect("Incorrect number of shared elements provided to AllEntities::from_elements");
        let witness: [Shared; WITNESS_ENTITIES_SIZE] = shared_elements
            .try_into()
            .expect("Incorrect number of shared elements provided to AllEntities::from_elements");
        Self {
            witness: witness.into(),
            precomputed: precomputed.into(),
            shifted_witness: shifted_witness.into(),
        }
    }
}

impl<Shared: Default, Public: Default> AllEntities<Shared, Public> {
    pub fn public_iter(&self) -> impl Iterator<Item = &Public> {
        self.precomputed.iter()
    }

    pub fn shared_iter(&self) -> impl Iterator<Item = &Shared> {
        self.witness.iter().chain(self.shifted_witness.iter())
    }

    pub fn into_shared_iter(self) -> impl Iterator<Item = Shared> {
        self.witness.into_iter().chain(self.shifted_witness)
    }

    pub fn public_iter_mut(&mut self) -> impl Iterator<Item = &mut Public> {
        self.precomputed.iter_mut()
    }

    pub fn shared_iter_mut(&mut self) -> impl Iterator<Item = &mut Shared> {
        self.witness
            .iter_mut()
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<Shared: Default + Clone, Public: Default + Clone> AllEntities<Vec<Shared>, Vec<Public>> {
    pub fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .shared_iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        polynomials
            .public_iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }
}

impl<T: Default> AllEntities<T, T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_witness.iter())
    }
}

pub const PROVER_WITNESS_ENTITIES_SIZE: usize = 6;
pub const WITNESS_ENTITIES_SIZE: usize = PROVER_WITNESS_ENTITIES_SIZE + 2;
#[derive(Default, Serialize, Deserialize)]
pub struct ProverWitnessEntities<T: Default> {
    pub elements: [T; PROVER_WITNESS_ENTITIES_SIZE],
}

pub const PRECOMPUTED_ENTITIES_SIZE: usize = 28;
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct PrecomputedEntities<T: Default> {
    pub elements: [T; PRECOMPUTED_ENTITIES_SIZE],
}

impl<T: Default> PrecomputedEntities<Vec<T>> {
    pub fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    pub fn add(&mut self, precomputed_entities: PrecomputedEntities<T>) {
        for (src, dst) in precomputed_entities.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> From<[T; PRECOMPUTED_ENTITIES_SIZE]> for PrecomputedEntities<T> {
    fn from(elements: [T; PRECOMPUTED_ENTITIES_SIZE]) -> Self {
        Self { elements }
    }
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
    pub const W_L: usize = 0;
    /// column 1
    pub const W_R: usize = 1;
    /// column 2
    pub const W_O: usize = 2;
    /// column 3 (modified by prover)
    pub const W_4: usize = 3;
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

    pub fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_L]
    }

    pub fn w_r(&self) -> &T {
        &self.elements[Self::W_R]
    }

    pub fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_R]
    }

    pub fn w_o(&self) -> &T {
        &self.elements[Self::W_O]
    }

    pub fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_O]
    }

    pub fn w_4(&self) -> &T {
        &self.elements[Self::W_4]
    }

    pub fn lookup_read_counts(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }

    pub fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_TAGS]
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
    pub const Q_M: usize = 0;
    /// column 1
    pub const Q_C: usize = 1;
    /// column 2
    pub const Q_L: usize = 2;
    /// column 3
    pub const Q_R: usize = 3;
    /// column 4
    pub const Q_O: usize = 4;
    /// column 5
    pub const Q_4: usize = 5;
    /// column 6
    pub const Q_LOOKUP: usize = 6;
    /// column 7
    pub const Q_ARITH: usize = 7;
    /// column 8
    pub const Q_DELTA_RANGE: usize = 8;
    /// column 9
    pub const Q_ELLIPTIC: usize = 9;
    /// column 10
    pub const Q_MEMORY: usize = 10;
    /// column 11
    pub const Q_NNF: usize = 11;
    /// column 12
    pub const Q_POSEIDON2_EXTERNAL: usize = 12;
    /// column 13
    pub const Q_POSEIDON2_INTERNAL: usize = 13;
    /// column 14
    const SIGMA_1: usize = 14;
    /// column 15
    const SIGMA_2: usize = 15;
    /// column 16
    const SIGMA_3: usize = 16;
    /// column 17
    const SIGMA_4: usize = 17;
    /// column 18
    const ID_1: usize = 18;
    /// column 19
    const ID_2: usize = 19;
    /// column 20
    const ID_3: usize = 20;
    /// column 21
    const ID_4: usize = 21;
    /// column 22
    const TABLE_1: usize = 22;
    /// column 23
    const TABLE_2: usize = 23;
    /// column 24
    const TABLE_3: usize = 24;
    /// column 25
    const TABLE_4: usize = 25;
    /// column 26
    const LAGRANGE_FIRST: usize = 26;
    /// column 27
    const LAGRANGE_LAST: usize = 27;

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

    pub fn q_memory(&self) -> &T {
        &self.elements[Self::Q_MEMORY]
    }

    pub fn q_nnf(&self) -> &T {
        &self.elements[Self::Q_NNF]
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

    pub fn q_m_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_M]
    }

    pub fn q_c_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_C]
    }

    pub fn q_l_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_L]
    }

    pub fn q_r_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_R]
    }

    pub fn q_o_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_O]
    }

    pub fn q_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_4]
    }

    pub fn q_arith_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_ARITH]
    }

    pub fn q_delta_range_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_DELTA_RANGE]
    }

    pub fn q_elliptic_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_ELLIPTIC]
    }

    pub fn q_memory_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_MEMORY]
    }

    pub fn q_nnf_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_NNF]
    }

    pub fn q_lookup_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_LOOKUP]
    }

    pub fn q_poseidon2_external_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_POSEIDON2_EXTERNAL]
    }

    pub fn q_poseidon2_internal_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Q_POSEIDON2_INTERNAL]
    }

    pub fn table_1_mut(&mut self) -> &mut T {
        &mut self.elements[Self::TABLE_1]
    }

    pub fn table_2_mut(&mut self) -> &mut T {
        &mut self.elements[Self::TABLE_2]
    }

    pub fn table_3_mut(&mut self) -> &mut T {
        &mut self.elements[Self::TABLE_3]
    }

    pub fn table_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::TABLE_4]
    }

    pub fn sigma_1_mut(&mut self) -> &mut T {
        &mut self.elements[Self::SIGMA_1]
    }

    pub fn sigma_2_mut(&mut self) -> &mut T {
        &mut self.elements[Self::SIGMA_2]
    }

    pub fn sigma_3_mut(&mut self) -> &mut T {
        &mut self.elements[Self::SIGMA_3]
    }

    pub fn sigma_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::SIGMA_4]
    }

    pub fn id_1_mut(&mut self) -> &mut T {
        &mut self.elements[Self::ID_1]
    }

    pub fn id_2_mut(&mut self) -> &mut T {
        &mut self.elements[Self::ID_2]
    }

    pub fn id_3_mut(&mut self) -> &mut T {
        &mut self.elements[Self::ID_3]
    }

    pub fn id_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::ID_4]
    }
}

#[derive(Default, Clone, Debug)]
pub struct WitnessEntities<T: Default> {
    pub elements: [T; WITNESS_ENTITIES_SIZE],
}

pub const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
#[derive(Default, Clone, Debug)]
pub struct ShiftedWitnessEntities<T: Default> {
    pub elements: [T; SHIFTED_WITNESS_ENTITIES_SIZE],
}

impl<T: Default> IntoIterator for WitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> From<[T; WITNESS_ENTITIES_SIZE]> for WitnessEntities<T> {
    fn from(elements: [T; WITNESS_ENTITIES_SIZE]) -> Self {
        Self { elements }
    }
}

impl<T: Default> WitnessEntities<Vec<T>> {
    pub fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    pub fn add(&mut self, witness_entity: WitnessEntities<T>) {
        for (src, dst) in witness_entity.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> IntoIterator for ShiftedWitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, SHIFTED_WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> ShiftedWitnessEntities<Vec<T>> {
    pub fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    pub fn add(&mut self, shifted_witness_entities: ShiftedWitnessEntities<T>) {
        for (src, dst) in shifted_witness_entities.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> From<[T; SHIFTED_WITNESS_ENTITIES_SIZE]> for ShiftedWitnessEntities<T> {
    fn from(elements: [T; SHIFTED_WITNESS_ENTITIES_SIZE]) -> Self {
        Self { elements }
    }
}

impl<T: Default> WitnessEntities<T> {
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

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub fn to_be_shifted(&self) -> &[T] {
        &self.elements[Self::W_L..=Self::Z_PERM]
    }

    pub fn to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::W_L..=Self::Z_PERM]
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

    pub fn z_perm(&self) -> &T {
        &self.elements[Self::Z_PERM]
    }

    pub fn lookup_inverses(&self) -> &T {
        &self.elements[Self::LOOKUP_INVERSES]
    }

    pub fn lookup_read_counts(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }

    pub fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_L]
    }

    pub fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_R]
    }

    pub fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_O]
    }

    pub fn w_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_4]
    }

    pub fn z_perm_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Z_PERM]
    }

    pub fn lookup_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_INVERSES]
    }

    pub fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_TAGS]
    }
}

impl<T: Default> ShiftedWitnessEntities<T> {
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

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
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

    pub fn z_perm(&self) -> &T {
        &self.elements[Self::Z_PERM]
    }

    pub fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_L]
    }

    pub fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_R]
    }

    pub fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_O]
    }

    pub fn w_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_4]
    }

    pub fn z_perm_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Z_PERM]
    }
}
