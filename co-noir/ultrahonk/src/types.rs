use ark_ff::PrimeField;
use co_builder::{
    prelude::{PrecomputedEntities, Serialize, PRECOMPUTED_ENTITIES_SIZE},
    HonkProofResult,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: PrimeField> {
    proof: Vec<F>,
}

impl<F: PrimeField> HonkProof<F> {
    pub(crate) fn new(proof: Vec<F>) -> Self {
        Self { proof }
    }

    pub(crate) fn inner(self) -> Vec<F> {
        self.proof
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        Serialize::to_buffer(&self.proof, true)
    }

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let res = Serialize::from_buffer(buf, true)?;
        Ok(Self::new(res))
    }
}

pub(crate) const NUM_ALL_ENTITIES: usize = WITNESS_ENTITIES_SIZE
    + PRECOMPUTED_ENTITIES_SIZE
    + SHIFTED_TABLE_ENTITIES_SIZE
    + SHIFTED_WITNESS_ENTITIES_SIZE;
#[derive(Default)]
pub(crate) struct AllEntities<T: Default> {
    pub(crate) witness: WitnessEntities<T>,
    pub(crate) precomputed: PrecomputedEntities<T>,
    pub(crate) shifted_witness: ShiftedWitnessEntities<T>,
    pub(crate) shifted_tables: ShiftedTableEntities<T>,
}

impl<T: Default> AllEntities<T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_tables.iter())
            .chain(self.shifted_witness.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.precomputed
            .iter_mut()
            .chain(self.witness.iter_mut())
            .chain(self.shifted_tables.iter_mut())
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<T: Default + Clone> AllEntities<Vec<T>> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }
}

const WITNESS_ENTITIES_SIZE: usize = 8;
#[derive(Default)]
pub(crate) struct WitnessEntities<T: Default> {
    pub(crate) elements: [T; WITNESS_ENTITIES_SIZE],
}

const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
#[derive(Default)]
pub struct ShiftedWitnessEntities<T: Default> {
    pub(crate) elements: [T; SHIFTED_WITNESS_ENTITIES_SIZE],
}

const SHIFTED_TABLE_ENTITIES_SIZE: usize = 4;
#[derive(Default)]
pub struct ShiftedTableEntities<T: Default> {
    pub(crate) elements: [T; SHIFTED_TABLE_ENTITIES_SIZE],
}

impl<T: Default> IntoIterator for WitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> IntoIterator for ShiftedTableEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, SHIFTED_TABLE_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> IntoIterator for ShiftedWitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, SHIFTED_WITNESS_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> IntoIterator for AllEntities<T> {
    type Item = T;
    type IntoIter = std::iter::Chain<
        std::iter::Chain<
            std::iter::Chain<
                std::array::IntoIter<T, PRECOMPUTED_ENTITIES_SIZE>,
                std::array::IntoIter<T, WITNESS_ENTITIES_SIZE>,
            >,
            std::array::IntoIter<T, SHIFTED_TABLE_ENTITIES_SIZE>,
        >,
        std::array::IntoIter<T, SHIFTED_WITNESS_ENTITIES_SIZE>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.precomputed
            .into_iter()
            .chain(self.witness)
            .chain(self.shifted_tables)
            .chain(self.shifted_witness)
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

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub(crate) fn to_be_shifted(&self) -> &[T] {
        &self.elements[Self::W_L..=Self::Z_PERM]
    }

    pub(crate) fn to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::W_L..=Self::Z_PERM]
    }

    pub(crate) fn w_l(&self) -> &T {
        &self.elements[Self::W_L]
    }

    pub(crate) fn w_r(&self) -> &T {
        &self.elements[Self::W_R]
    }

    pub(crate) fn w_o(&self) -> &T {
        &self.elements[Self::W_O]
    }

    pub(crate) fn w_4(&self) -> &T {
        &self.elements[Self::W_4]
    }

    pub(crate) fn z_perm(&self) -> &T {
        &self.elements[Self::Z_PERM]
    }

    pub(crate) fn lookup_inverses(&self) -> &T {
        &self.elements[Self::LOOKUP_INVERSES]
    }

    pub(crate) fn lookup_read_counts(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub(crate) fn lookup_read_tags(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }

    pub(crate) fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_L]
    }

    pub(crate) fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_R]
    }

    pub(crate) fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_O]
    }

    pub(crate) fn w_4_mut(&mut self) -> &mut T {
        &mut self.elements[Self::W_4]
    }

    pub(crate) fn z_perm_mut(&mut self) -> &mut T {
        &mut self.elements[Self::Z_PERM]
    }

    pub(crate) fn lookup_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_INVERSES]
    }

    pub(crate) fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub(crate) fn lookup_read_tags_mut(&mut self) -> &mut T {
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
}

#[allow(dead_code)]
impl<T: Default> ShiftedTableEntities<T> {
    /// column 0
    const TABLE_1: usize = 0;
    /// column 1
    const TABLE_2: usize = 1;
    /// column 2
    const TABLE_3: usize = 2;
    /// column 3
    const TABLE_4: usize = 3;

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub(crate) fn table_1(&self) -> &T {
        &self.elements[Self::TABLE_1]
    }

    pub(crate) fn table_2(&self) -> &T {
        &self.elements[Self::TABLE_2]
    }

    pub(crate) fn table_3(&self) -> &T {
        &self.elements[Self::TABLE_3]
    }

    pub(crate) fn table_4(&self) -> &T {
        &self.elements[Self::TABLE_4]
    }
}
