use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub type Polynomials<F> = AllEntities<Vec<F>>;

pub struct ProvingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
}

pub struct ProverCrs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
}

pub struct HonkProof<F: PrimeField> {
    pub proof: Vec<F>,
}

#[derive(Default)]
pub struct AllEntities<T: Default> {
    pub witness: WitnessEntities<T>,
    pub precomputed: PrecomputedEntities<T>,
    pub shifted_witness: ShiftedWitnessEntities<T>,
    pub shifted_tables: ShiftedTableEntities<T>,
}

impl<T: Default> AllEntities<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.witness
            .iter()
            .chain(self.precomputed.iter())
            .chain(self.shifted_witness.iter())
            .chain(self.shifted_tables.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.witness
            .iter_mut()
            .chain(self.precomputed.iter_mut())
            .chain(self.shifted_witness.iter_mut())
            .chain(self.shifted_tables.iter_mut())
    }
}

#[derive(Default)]
pub struct WitnessEntities<T: Default> {
    pub elements: [T; 5],
}

#[derive(Default)]
pub struct ShiftedWitnessEntities<T: Default> {
    pub elements: [T; 4],
}

#[derive(Default)]
pub struct ShiftedTableEntities<T: Default> {
    pub elements: [T; 4],
}

#[derive(Default)]
pub struct PrecomputedEntities<T: Default> {
    pub elements: [T; 27],
}

impl<T: Default> WitnessEntities<T> {
    const W_L: usize = 0; // column 0
    const W_R: usize = 1; // column 1
    const W_O: usize = 2; // column 2
    const LOOKUP_READ_COUNTS: usize = 3; // column 6
    const LOOKUP_READ_TAGS: usize = 4; // column 7

    // const W_4: usize  // column 3 (computed by prover)
    // const Z_PERM: usize  // column 4 (computed by prover)
    // const LOOKUP_INVERSES: usize // column 5 (computed by prover);

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

    pub fn lookup_read_counts(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_COUNTS]
    }

    pub fn lookup_read_tags(&self) -> &T {
        &self.elements[Self::LOOKUP_READ_TAGS]
    }
}

impl<T: Default> ShiftedWitnessEntities<T> {
    const W_L: usize = 0; // column 0
    const W_R: usize = 1; // column 1
    const W_O: usize = 2; // column 2
    const W_4: usize = 3; // column 3 // TODO right place? shifted by the prover? Same as z_perm_shift?

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
}

impl<T: Default> ShiftedTableEntities<T> {
    const TABLE_1: usize = 0; // column 0
    const TABLE_2: usize = 1; // column 1
    const TABLE_3: usize = 2; // column 2
    const TABLE_4: usize = 3; // column 3

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
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

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
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
}
