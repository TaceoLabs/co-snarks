use crate::{
    decider::polynomial::Polynomial,
    prover::{HonkProofError, HonkProofResult},
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use num_bigint::BigUint;

// This is what we get from the proving key, we shift at a later point
#[derive(Default)]
pub(crate) struct Polynomials<F: PrimeField> {
    pub(crate) witness: ProverWitnessEntities<Polynomial<F>>,
    pub(crate) precomputed: PrecomputedEntities<Polynomial<F>>,
}

impl<F: PrimeField> Polynomials<F> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Polynomial<F>> {
        self.witness.iter().chain(self.precomputed.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Polynomial<F>> {
        self.witness.iter_mut().chain(self.precomputed.iter_mut())
    }
}

pub struct ProvingKey<P: Pairing> {
    pub(crate) crs: ProverCrs<P>,
    pub(crate) circuit_size: u32,
    pub(crate) public_inputs: Vec<P::ScalarField>,
    pub(crate) num_public_inputs: u32,
    pub(crate) pub_inputs_offset: u32,
    pub(crate) polynomials: Polynomials<P::ScalarField>,
    pub(crate) memory_read_records: Vec<u32>,
    pub(crate) memory_write_records: Vec<u32>,
}

pub(crate) struct Crs<P: Pairing> {
    pub(crate) monomials: Vec<P::G1Affine>,
    pub(crate) g2_x: P::G2Affine,
}

pub struct ProverCrs<P: Pairing> {
    pub(crate) monomials: Vec<P::G1Affine>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: PrimeField> {
    proof: Vec<F>,
}

impl<F: PrimeField> HonkProof<F> {
    const NUM_64_LIMBS: u32 = F::MODULUS_BIT_SIZE.div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;
    const VEC_LEN_BYTES: u32 = 4;

    pub(crate) fn new(proof: Vec<F>) -> Self {
        Self { proof }
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        self.to_buffer_internal(true)
    }

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        Self::from_buffer_internal(buf, true)
    }

    fn from_buffer_internal(buf: &[u8], size_included: bool) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;

        // Check sizes
        let num_elements = if size_included {
            let num_elements =
                (size - Self::VEC_LEN_BYTES as usize) / Self::FIELDSIZE_BYTES as usize;
            if num_elements * Self::FIELDSIZE_BYTES as usize + Self::VEC_LEN_BYTES as usize != size
            {
                return Err(HonkProofError::InvalidProofLength);
            }

            let read_num_elements = Self::read_u32(buf, &mut offset);
            if read_num_elements != num_elements as u32 {
                return Err(HonkProofError::InvalidProofLength);
            }
            num_elements
        } else {
            let num_elements = size / Self::FIELDSIZE_BYTES as usize;
            if num_elements * Self::FIELDSIZE_BYTES as usize != size {
                return Err(HonkProofError::InvalidProofLength);
            }
            num_elements
        };

        // Read data
        let mut res = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            res.push(Self::read_field_element(buf, &mut offset));
        }
        debug_assert_eq!(offset, size);
        Ok(Self { proof: res })
    }

    fn to_buffer_internal(&self, include_size: bool) -> Vec<u8> {
        let total_size = self.proof.len() as u32 * Self::FIELDSIZE_BYTES
            + if include_size { Self::VEC_LEN_BYTES } else { 0 };

        let mut res = Vec::with_capacity(total_size as usize);
        if include_size {
            Self::write_u32(&mut res, self.proof.len() as u32);
        }
        for el in self.proof.iter().cloned() {
            Self::write_field_element(&mut res, el);
        }
        debug_assert_eq!(res.len(), total_size as usize);
        res
    }

    fn read_u32(buf: &[u8], offset: &mut usize) -> u32 {
        const BYTES: usize = 4;
        let res = u32::from_be_bytes(buf[*offset..*offset + BYTES].try_into().unwrap());
        *offset += BYTES;
        res
    }

    fn read_u64(buf: &[u8], offset: &mut usize) -> u64 {
        const BYTES: usize = 8;
        let res = u64::from_be_bytes(buf[*offset..*offset + BYTES].try_into().unwrap());
        *offset += BYTES;
        res
    }

    fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend(val.to_be_bytes());
    }

    fn write_u64(buf: &mut Vec<u8>, val: u64) {
        buf.extend(val.to_be_bytes());
    }

    fn write_field_element(buf: &mut Vec<u8>, el: F) {
        let prev_len = buf.len();
        let el = el.into_bigint(); // Gets rid of montgomery form

        for data in el.as_ref().iter().rev().cloned() {
            Self::write_u64(buf, data);
        }

        debug_assert_eq!(buf.len() - prev_len, Self::FIELDSIZE_BYTES as usize);
    }

    fn read_field_element(buf: &[u8], offset: &mut usize) -> F {
        let mut bigint: BigUint = Default::default();

        for _ in 0..Self::NUM_64_LIMBS {
            let data = Self::read_u64(buf, offset);
            bigint <<= 64;
            bigint += data;
        }

        F::from(bigint)
    }
}

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

    fn into_iter(self) -> impl Iterator<Item = T> {
        self.precomputed
            .into_iter()
            .chain(self.witness)
            .chain(self.shifted_tables)
            .chain(self.shifted_witness)
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

const PROVER_WITNESS_ENTITIES_SIZE: usize = 6;
#[derive(Default)]
pub(crate) struct ProverWitnessEntities<T: Default> {
    pub(crate) elements: [T; PROVER_WITNESS_ENTITIES_SIZE],
}

const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
#[derive(Default)]
pub(crate) struct ShiftedWitnessEntities<T: Default> {
    pub(crate) elements: [T; SHIFTED_WITNESS_ENTITIES_SIZE],
}

const SHIFTED_TABLE_ENTITIES_SIZE: usize = 4;
#[derive(Default)]
pub(crate) struct ShiftedTableEntities<T: Default> {
    pub(crate) elements: [T; SHIFTED_TABLE_ENTITIES_SIZE],
}

const PRECOMPUTED_ENTITIES_SIZE: usize = 27;
#[derive(Default)]
pub(crate) struct PrecomputedEntities<T: Default> {
    pub(crate) elements: [T; PRECOMPUTED_ENTITIES_SIZE],
}

impl<T: Default> IntoIterator for PrecomputedEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, PRECOMPUTED_ENTITIES_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> IntoIterator for WitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, WITNESS_ENTITIES_SIZE>;

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

impl<T: Default> ProverWitnessEntities<T> {
    const W_L: usize = 0; // column 0
    const W_R: usize = 1; // column 1
    const W_O: usize = 2; // column 2
    const W_4: usize = 3; // column 3 (modified by prover)
    const LOOKUP_READ_COUNTS: usize = 4; // column 6
    const LOOKUP_READ_TAGS: usize = 5; // column 7

    // const Z_PERM: usize = 4; // column 4 (computed by prover)
    // const LOOKUP_INVERSES: usize = 5; // column 5 (computed by prover);

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub(crate) fn into_wires(self) -> impl Iterator<Item = T> {
        self.elements
            .into_iter()
            // .skip(Self::W_L)
            .take(Self::W_4 + 1 - Self::W_L)
    }

    pub(crate) fn get_wires_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::W_L..=Self::W_4]
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

    pub(crate) fn lookup_read_counts(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub(crate) fn lookup_read_tags(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }

    pub(crate) fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub(crate) fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LOOKUP_READ_TAGS]
    }
}

impl<T: Default> WitnessEntities<T> {
    const W_L: usize = 0; // column 0
    const W_R: usize = 1; // column 1
    const W_O: usize = 2; // column 2
    const W_4: usize = 3; // column 3 (computed by prover)
    const Z_PERM: usize = 4; // column 4 (computed by prover)
    pub(crate) const LOOKUP_INVERSES: usize = 5; // column 5 (computed by prover);
    pub(crate) const LOOKUP_READ_COUNTS: usize = 6; // column 6
    pub(crate) const LOOKUP_READ_TAGS: usize = 7; // column 7

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
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
    const W_L: usize = 0; // column 0
    const W_R: usize = 1; // column 1
    const W_O: usize = 2; // column 2
    const W_4: usize = 3; // column 3
    const Z_PERM: usize = 4; // column 4

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
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
}

impl<T: Default> ShiftedTableEntities<T> {
    const TABLE_1: usize = 0; // column 0
    const TABLE_2: usize = 1; // column 1
    const TABLE_3: usize = 2; // column 2
    const TABLE_4: usize = 3; // column 3

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
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

impl<T: Default> PrecomputedEntities<T> {
    const Q_M: usize = 0; // column 0
    const Q_C: usize = 1; // column 1
    const Q_L: usize = 2; // column 2
    const Q_R: usize = 3; // column 3
    const Q_O: usize = 4; // column 4
    const Q_4: usize = 5; // column 5
    const Q_ARITH: usize = 6; // column 6
    const Q_DELTA_RANGE: usize = 7; // column 7
    const Q_ELLIPTIC: usize = 8; // column 8
    const Q_AUX: usize = 9; // column 9
    const Q_LOOKUP: usize = 10; // column 10
    const Q_POSEIDON2_EXTERNAL: usize = 11; // column 11
    const Q_POSEIDON2_INTERNAL: usize = 12; // column 12
    const SIGMA_1: usize = 13; // column 13
    const SIGMA_2: usize = 14; // column 14
    const SIGMA_3: usize = 15; // column 15
    const SIGMA_4: usize = 16; // column 16
    const ID_1: usize = 17; // column 17
    const ID_2: usize = 18; // column 18
    const ID_3: usize = 19; // column 19
    const ID_4: usize = 20; // column 20
    const TABLE_1: usize = 21; // column 21
    const TABLE_2: usize = 22; // column 22
    const TABLE_3: usize = 23; // column 23
    const TABLE_4: usize = 24; // column 24
    const LAGRANGE_FIRST: usize = 25; // column 25
    const LAGRANGE_LAST: usize = 26; // column 26

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub(crate) fn get_table_polynomials(&self) -> &[T] {
        &self.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    pub(crate) fn get_selectors_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::Q_M..=Self::Q_POSEIDON2_INTERNAL]
    }

    pub(crate) fn get_sigmas_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::SIGMA_1..=Self::SIGMA_4]
    }

    pub(crate) fn get_ids_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::ID_1..=Self::ID_4]
    }

    pub(crate) fn get_table_polynomials_mut(&mut self) -> &mut [T] {
        &mut self.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    pub(crate) fn q_m(&self) -> &T {
        &self.elements[Self::Q_M]
    }

    pub(crate) fn q_c(&self) -> &T {
        &self.elements[Self::Q_C]
    }

    pub(crate) fn q_l(&self) -> &T {
        &self.elements[Self::Q_L]
    }

    pub(crate) fn q_r(&self) -> &T {
        &self.elements[Self::Q_R]
    }

    pub(crate) fn q_o(&self) -> &T {
        &self.elements[Self::Q_O]
    }

    pub(crate) fn q_4(&self) -> &T {
        &self.elements[Self::Q_4]
    }

    pub(crate) fn q_arith(&self) -> &T {
        &self.elements[Self::Q_ARITH]
    }

    pub(crate) fn q_delta_range(&self) -> &T {
        &self.elements[Self::Q_DELTA_RANGE]
    }

    pub(crate) fn q_elliptic(&self) -> &T {
        &self.elements[Self::Q_ELLIPTIC]
    }

    pub(crate) fn q_aux(&self) -> &T {
        &self.elements[Self::Q_AUX]
    }

    pub(crate) fn q_lookup(&self) -> &T {
        &self.elements[Self::Q_LOOKUP]
    }

    pub(crate) fn q_poseidon2_external(&self) -> &T {
        &self.elements[Self::Q_POSEIDON2_EXTERNAL]
    }

    pub(crate) fn q_poseidon2_internal(&self) -> &T {
        &self.elements[Self::Q_POSEIDON2_INTERNAL]
    }

    pub(crate) fn sigma_1(&self) -> &T {
        &self.elements[Self::SIGMA_1]
    }

    pub(crate) fn sigma_2(&self) -> &T {
        &self.elements[Self::SIGMA_2]
    }

    pub(crate) fn sigma_3(&self) -> &T {
        &self.elements[Self::SIGMA_3]
    }

    pub(crate) fn sigma_4(&self) -> &T {
        &self.elements[Self::SIGMA_4]
    }

    pub(crate) fn id_1(&self) -> &T {
        &self.elements[Self::ID_1]
    }

    pub(crate) fn id_2(&self) -> &T {
        &self.elements[Self::ID_2]
    }

    pub(crate) fn id_3(&self) -> &T {
        &self.elements[Self::ID_3]
    }

    pub(crate) fn id_4(&self) -> &T {
        &self.elements[Self::ID_4]
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

    pub(crate) fn lagrange_first(&self) -> &T {
        &self.elements[Self::LAGRANGE_FIRST]
    }

    pub(crate) fn lagrange_last(&self) -> &T {
        &self.elements[Self::LAGRANGE_LAST]
    }

    pub(crate) fn lagrange_first_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LAGRANGE_FIRST]
    }

    pub(crate) fn lagrange_last_mut(&mut self) -> &mut T {
        &mut self.elements[Self::LAGRANGE_LAST]
    }
}
