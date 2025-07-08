use crate::{
    polynomials::{
        polynomial_flavours::{
            PolyGFlavour, PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour,
            WitnessEntitiesFlavour,
        },
        polynomial_types::{
            PrecomputedEntities, ProverWitnessEntities, ShiftedWitnessEntities, WitnessEntities,
        },
    },
    prover_flavour::{Flavour, ProverFlavour},
};

type MegaPrecomputedEntities<T> =
    PrecomputedEntities<T, { MegaFlavour::PRECOMPUTED_ENTITIES_SIZE }>;
type MegaProverWitnessEntities<T> =
    ProverWitnessEntities<T, { MegaFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;
type MegaShiftedWitnessEntities<T> =
    ShiftedWitnessEntities<T, { MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;
type MegaWitnessEntities<T> = WitnessEntities<T, { MegaFlavour::WITNESS_ENTITIES_SIZE }>;

#[derive(Default)]
pub struct MegaFlavour {}

impl ProverFlavour for MegaFlavour {
    type ProverWitnessEntities<T: Default + std::marker::Sync> = MegaProverWitnessEntities<T>;
    type ShiftedWitnessEntities<T: Default + std::marker::Sync> = MegaShiftedWitnessEntities<T>; // This is the same for Ultra and Mega
    type WitnessEntities<T: Default + std::marker::Sync> = MegaWitnessEntities<T>;
    type PrecomputedEntities<T: Default + Clone + std::marker::Sync> = MegaPrecomputedEntities<T>;

    const FLAVOUR: Flavour = Flavour::Mega;
    const WITNESS_ENTITIES_SIZE: usize = 24;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 30;
    const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
        + Self::PRECOMPUTED_ENTITIES_SIZE
        + Self::SHIFTED_WITNESS_ENTITIES_SIZE;

    const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = Self::MAX_PARTIAL_RELATION_LENGTH + 1;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = Self::BATCHED_RELATION_PARTIAL_LENGTH + 1;

    //Precomputed Entities:
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
    const Q_BUSREAD: usize = 6;
    /// column 7
    const Q_LOOKUP: usize = 7;
    /// column 8
    const Q_ARITH: usize = 8;
    /// column 9
    const Q_DELTA_RANGE: usize = 9;
    /// column 10
    const Q_ELLIPTIC: usize = 10;
    /// column 11
    const Q_AUX: usize = 11;
    /// column 12
    const Q_POSEIDON2_EXTERNAL: usize = 12;
    /// column 13
    const Q_POSEIDON2_INTERNAL: usize = 13;
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
    /// column 28
    const LAGRANGE_ECC_OP: usize = 28;
    /// column 29
    const DATABUS_ID: usize = 29;

    // Prover Witness entities:
    /// column 0
    const W_L: usize = 0;
    /// column 1
    const W_R: usize = 1;
    /// column 2
    const W_O: usize = 2;
    /// column 3 (computed by prover)
    const W_4: usize = 3;
    /// column 4 (computed by prover)
    // const Z_PERM: usize = 4;
    // /// column 5 (computed by prover);
    // const LOOKUP_INVERSES: usize = 5;
    /// column 6
    const LOOKUP_READ_COUNTS: usize = 4;
    /// column 7
    const LOOKUP_READ_TAGS: usize = 5;
    const ECC_OP_WIRE_1: usize = 6;
    const ECC_OP_WIRE_2: usize = 7;
    const ECC_OP_WIRE_3: usize = 8;
    const ECC_OP_WIRE_4: usize = 9;
    const CALLDATA: usize = 10;
    const CALLDATA_READ_COUNTS: usize = 11;
    const CALLDATA_READ_TAGS: usize = 12;
    const CALLDATA_INVERSES: usize = 13;
    const SECONDARY_CALLDATA: usize = 14;
    const SECONDARY_CALLDATA_READ_COUNTS: usize = 15;
    const SECONDARY_CALLDATA_READ_TAGS: usize = 16;
    const SECONDARY_CALLDATA_INVERSES: usize = 17;
    const RETURN_DATA: usize = 18;
    const RETURN_DATA_READ_COUNTS: usize = 19;
    const RETURN_DATA_READ_TAGS: usize = 20;
    const RETURN_DATA_INVERSES: usize = 21;

    //  Witness entities:
    /// column 0
    const WITNESS_W_L: usize = 0;
    /// column 1
    const WITNESS_W_R: usize = 1;
    /// column 2
    const WITNESS_W_O: usize = 2;
    /// column 3 (computed by prover)
    const WITNESS_W_4: usize = 3;
    /// column 4 (computed by prover)
    const WITNESS_Z_PERM: usize = 4;
    // /// column 5 (computed by prover);
    const WITNESS_LOOKUP_INVERSES: usize = 5;
    /// column 6
    const WITNESS_LOOKUP_READ_COUNTS: usize = 6;
    /// column 7
    const WITNESS_LOOKUP_READ_TAGS: usize = 7;
    const WITNESS_ECC_OP_WIRE_1: usize = 8;
    const WITNESS_ECC_OP_WIRE_2: usize = 9;
    const WITNESS_ECC_OP_WIRE_3: usize = 10;
    const WITNESS_ECC_OP_WIRE_4: usize = 11;
    const WITNESS_CALLDATA: usize = 12;
    const WITNESS_CALLDATA_READ_COUNTS: usize = 13;
    const WITNESS_CALLDATA_READ_TAGS: usize = 14;
    const WITNESS_CALLDATA_INVERSES: usize = 15;
    const WITNESS_SECONDARY_CALLDATA: usize = 16;
    const WITNESS_SECONDARY_CALLDATA_READ_COUNTS: usize = 17;
    const WITNESS_SECONDARY_CALLDATA_READ_TAGS: usize = 18;
    const WITNESS_SECONDARY_CALLDATA_INVERSES: usize = 19;
    const WITNESS_RETURN_DATA: usize = 20;
    const WITNESS_RETURN_DATA_READ_COUNTS: usize = 21;
    const WITNESS_RETURN_DATA_READ_TAGS: usize = 22;
    const WITNESS_RETURN_DATA_INVERSES: usize = 23;

    fn prover_witness_entity_from_vec<T: Default + Sync + Clone>(
        vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::ProverWitnessEntities<crate::prelude::Polynomial<T>> {
        MegaProverWitnessEntities {
            elements: std::array::from_fn(|i| vec[i].clone()),
        }
    }

    fn precomputed_entity_from_vec<T: Default + Clone + Sync>(
        vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::PrecomputedEntities<crate::prelude::Polynomial<T>> {
        MegaPrecomputedEntities {
            elements: std::array::from_fn(|i| vec[i].clone()),
        }
    }
    type PolyG<'a, T: Default + 'a> = MegaPolyG<'a, T>;
}
pub struct MegaPolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE],
}

impl<'a, T: Default> PolyGFlavour<'a, T> for MegaPolyG<'a, T> {
    fn iter(&self) -> impl Iterator<Item = &'a T> {
        self.wires.iter()
    }

    fn from_slice(input: &'a [T]) -> Self {
        assert_eq!(
            input.len(),
            MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE,
            "Input slice length does not match the expected size for Mega flavour."
        );
        Self {
            wires: input
                .try_into()
                .unwrap_or_else(|_| panic!("Slice length mismatch")),
        }
    }
}

impl<T: Default> PrecomputedEntitiesFlavour<T> for MegaPrecomputedEntities<T> {
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        self.elements.iter()
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        self.elements.iter_mut()
    }
    fn into_iter(self) -> impl Iterator<Item = T> {
        self.elements.into_iter()
    }
    fn get_table_polynomials(&self) -> &[T] {
        &self.elements[MegaFlavour::TABLE_1..=MegaFlavour::TABLE_4]
    }
    fn get_selectors_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::Q_M..=MegaFlavour::Q_POSEIDON2_INTERNAL]
    }
    fn get_sigmas_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::SIGMA_1..=MegaFlavour::SIGMA_4]
    }
    fn get_ids_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::ID_1..=MegaFlavour::ID_4]
    }
    fn get_table_polynomials_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::TABLE_1..=MegaFlavour::TABLE_4]
    }
    fn q_m(&self) -> &T {
        &self.elements[MegaFlavour::Q_M]
    }
    fn q_c(&self) -> &T {
        &self.elements[MegaFlavour::Q_C]
    }
    fn q_l(&self) -> &T {
        &self.elements[MegaFlavour::Q_L]
    }
    fn q_r(&self) -> &T {
        &self.elements[MegaFlavour::Q_R]
    }
    fn q_o(&self) -> &T {
        &self.elements[MegaFlavour::Q_O]
    }
    fn q_4(&self) -> &T {
        &self.elements[MegaFlavour::Q_4]
    }
    fn q_busread(&self) -> &T {
        &self.elements[MegaFlavour::Q_BUSREAD]
    }
    fn q_arith(&self) -> &T {
        &self.elements[MegaFlavour::Q_ARITH]
    }
    fn q_delta_range(&self) -> &T {
        &self.elements[MegaFlavour::Q_DELTA_RANGE]
    }
    fn q_elliptic(&self) -> &T {
        &self.elements[MegaFlavour::Q_ELLIPTIC]
    }
    fn q_aux(&self) -> &T {
        &self.elements[MegaFlavour::Q_AUX]
    }
    fn q_lookup(&self) -> &T {
        &self.elements[MegaFlavour::Q_LOOKUP]
    }
    fn q_poseidon2_external(&self) -> &T {
        &self.elements[MegaFlavour::Q_POSEIDON2_EXTERNAL]
    }
    fn q_poseidon2_internal(&self) -> &T {
        &self.elements[MegaFlavour::Q_POSEIDON2_INTERNAL]
    }
    fn sigma_1(&self) -> &T {
        &self.elements[MegaFlavour::SIGMA_1]
    }
    fn sigma_2(&self) -> &T {
        &self.elements[MegaFlavour::SIGMA_2]
    }
    fn sigma_3(&self) -> &T {
        &self.elements[MegaFlavour::SIGMA_3]
    }
    fn sigma_4(&self) -> &T {
        &self.elements[MegaFlavour::SIGMA_4]
    }
    fn id_1(&self) -> &T {
        &self.elements[MegaFlavour::ID_1]
    }
    fn id_2(&self) -> &T {
        &self.elements[MegaFlavour::ID_2]
    }
    fn id_3(&self) -> &T {
        &self.elements[MegaFlavour::ID_3]
    }
    fn id_4(&self) -> &T {
        &self.elements[MegaFlavour::ID_4]
    }
    fn table_1(&self) -> &T {
        &self.elements[MegaFlavour::TABLE_1]
    }
    fn table_2(&self) -> &T {
        &self.elements[MegaFlavour::TABLE_2]
    }
    fn table_3(&self) -> &T {
        &self.elements[MegaFlavour::TABLE_3]
    }
    fn table_4(&self) -> &T {
        &self.elements[MegaFlavour::TABLE_4]
    }
    fn lagrange_first(&self) -> &T {
        &self.elements[MegaFlavour::LAGRANGE_FIRST]
    }
    fn lagrange_last(&self) -> &T {
        &self.elements[MegaFlavour::LAGRANGE_LAST]
    }
    fn lagrange_ecc_op(&self) -> &T {
        &self.elements[MegaFlavour::LAGRANGE_ECC_OP]
    }
    fn databus_id(&self) -> &T {
        &self.elements[MegaFlavour::DATABUS_ID]
    }
    fn lagrange_first_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::LAGRANGE_FIRST]
    }
    fn lagrange_last_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::LAGRANGE_LAST]
    }
    fn lagrange_ecc_op_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::LAGRANGE_ECC_OP]
    }
    fn databus_id_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::DATABUS_ID]
    }
    fn q_m_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_M]
    }
    fn q_c_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_C]
    }
    fn q_l_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_L]
    }
    fn q_r_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_R]
    }
    fn q_o_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_O]
    }
    fn q_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_4]
    }
    fn q_busread_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_BUSREAD]
    }
    fn q_arith_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_ARITH]
    }
    fn q_delta_range_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_DELTA_RANGE]
    }
    fn q_elliptic_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_ELLIPTIC]
    }
    fn q_aux_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_AUX]
    }
    fn q_lookup_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_LOOKUP]
    }
    fn q_poseidon2_external_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_POSEIDON2_EXTERNAL]
    }
    fn q_poseidon2_internal_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::Q_POSEIDON2_INTERNAL]
    }
    fn table_1_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::TABLE_1]
    }
    fn table_2_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::TABLE_2]
    }
    fn table_3_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::TABLE_3]
    }
    fn table_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::TABLE_4]
    }
    fn sigma_1_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SIGMA_1]
    }
    fn sigma_2_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SIGMA_2]
    }
    fn sigma_3_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SIGMA_3]
    }
    fn sigma_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SIGMA_4]
    }
    fn id_1_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ID_1]
    }
    fn id_2_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ID_2]
    }
    fn id_3_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ID_3]
    }
    fn id_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ID_4]
    }

    fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}

impl<T: Default> ProverWitnessEntitiesFlavour<T> for MegaProverWitnessEntities<T> {
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        self.elements.iter()
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        self.elements.iter_mut()
    }
    fn into_iter(self) -> impl Iterator<Item = T> {
        self.elements.into_iter()
    }
    fn into_wires(self) -> impl Iterator<Item = T> {
        self.elements
            .into_iter()
            // .skip(Self::W_L)
            .take(MegaFlavour::W_4 + 1 - MegaFlavour::W_L)
    }
    fn get_wires(&self) -> &[T] {
        &self.elements[MegaFlavour::W_L..=MegaFlavour::W_4]
    }
    fn get_wires_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::W_L..=MegaFlavour::W_4]
    }
    fn w_l(&self) -> &T {
        &self.elements[MegaFlavour::W_L]
    }
    fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::W_L]
    }
    fn w_r(&self) -> &T {
        &self.elements[MegaFlavour::W_R]
    }
    fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::W_R]
    }
    fn w_o(&self) -> &T {
        &self.elements[MegaFlavour::W_O]
    }
    fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::W_O]
    }
    fn w_4(&self) -> &T {
        &self.elements[MegaFlavour::W_4]
    }
    fn lookup_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::LOOKUP_READ_COUNTS]
    }
    fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::LOOKUP_READ_COUNTS]
    }
    fn lookup_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::LOOKUP_READ_TAGS]
    }
    fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::LOOKUP_READ_TAGS]
    }
    fn lookup_read_counts_and_tags(&self) -> &[T] {
        &self.elements[MegaFlavour::LOOKUP_READ_COUNTS..MegaFlavour::LOOKUP_READ_TAGS + 1]
    }
    fn lookup_read_counts_and_tags_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::LOOKUP_READ_COUNTS..MegaFlavour::LOOKUP_READ_TAGS + 1]
    }
    fn calldata(&self) -> &T {
        &self.elements[MegaFlavour::CALLDATA]
    }
    fn calldata_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::CALLDATA]
    }
    fn secondary_calldata(&self) -> &T {
        &self.elements[MegaFlavour::SECONDARY_CALLDATA]
    }
    fn secondary_calldata_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SECONDARY_CALLDATA]
    }
    fn return_data(&self) -> &T {
        &self.elements[MegaFlavour::RETURN_DATA]
    }
    fn return_data_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::RETURN_DATA]
    }
    fn ecc_op_wire_1(&self) -> &T {
        &self.elements[MegaFlavour::ECC_OP_WIRE_1]
    }
    fn ecc_op_wire_1_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ECC_OP_WIRE_1]
    }
    fn ecc_op_wire_2(&self) -> &T {
        &self.elements[MegaFlavour::ECC_OP_WIRE_2]
    }
    fn ecc_op_wire_2_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ECC_OP_WIRE_2]
    }
    fn ecc_op_wire_3(&self) -> &T {
        &self.elements[MegaFlavour::ECC_OP_WIRE_3]
    }
    fn ecc_op_wire_3_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ECC_OP_WIRE_3]
    }
    fn ecc_op_wire_4(&self) -> &T {
        &self.elements[MegaFlavour::ECC_OP_WIRE_4]
    }
    fn ecc_op_wire_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::ECC_OP_WIRE_4]
    }
    fn calldata_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::CALLDATA_READ_COUNTS]
    }
    fn calldata_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::CALLDATA_READ_COUNTS]
    }
    fn calldata_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::CALLDATA_READ_TAGS]
    }
    fn calldata_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::CALLDATA_READ_TAGS]
    }
    fn calldata_inverses(&self) -> &T {
        &self.elements[MegaFlavour::CALLDATA_INVERSES]
    }
    fn calldata_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::CALLDATA_INVERSES]
    }
    fn secondary_calldata_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::SECONDARY_CALLDATA_READ_COUNTS]
    }
    fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SECONDARY_CALLDATA_READ_COUNTS]
    }
    fn secondary_calldata_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::SECONDARY_CALLDATA_READ_TAGS]
    }
    fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SECONDARY_CALLDATA_READ_TAGS]
    }
    fn secondary_calldata_inverses(&self) -> &T {
        &self.elements[MegaFlavour::SECONDARY_CALLDATA_INVERSES]
    }
    fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::SECONDARY_CALLDATA_INVERSES]
    }
    fn return_data_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::RETURN_DATA_READ_COUNTS]
    }
    fn return_data_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::RETURN_DATA_READ_COUNTS]
    }
    fn return_data_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::RETURN_DATA_READ_TAGS]
    }
    fn return_data_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::RETURN_DATA_READ_TAGS]
    }
    fn return_data_inverses(&self) -> &T {
        &self.elements[MegaFlavour::RETURN_DATA_INVERSES]
    }
    fn return_data_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::RETURN_DATA_INVERSES]
    }
}

impl<T: Default> WitnessEntitiesFlavour<T> for MegaWitnessEntities<T> {
    fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        self.elements.iter()
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        self.elements.iter_mut()
    }
    fn into_iter(self) -> impl Iterator<Item = T> {
        self.elements.into_iter()
    }
    fn to_be_shifted(&self) -> &[T] {
        &self.elements[MegaFlavour::WITNESS_W_L..=MegaFlavour::WITNESS_Z_PERM]
    }
    fn to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[MegaFlavour::WITNESS_W_L..=MegaFlavour::WITNESS_Z_PERM]
    }
    fn w_l(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_W_L]
    }
    fn w_r(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_W_R]
    }
    fn w_o(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_W_O]
    }
    fn w_4(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_W_4]
    }
    fn z_perm(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_Z_PERM]
    }
    fn lookup_inverses(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_LOOKUP_INVERSES]
    }
    fn lookup_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_LOOKUP_READ_COUNTS]
    }
    fn lookup_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_LOOKUP_READ_TAGS]
    }
    fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_W_L]
    }
    fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_W_R]
    }
    fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_W_O]
    }
    fn w_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_W_4]
    }
    fn z_perm_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_Z_PERM]
    }
    fn lookup_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_LOOKUP_INVERSES]
    }
    fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_LOOKUP_READ_COUNTS]
    }
    fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_LOOKUP_READ_TAGS]
    }
    fn calldata(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_CALLDATA]
    }
    fn calldata_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_CALLDATA]
    }
    fn secondary_calldata(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA]
    }
    fn secondary_calldata_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA]
    }
    fn return_data(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_RETURN_DATA]
    }
    fn return_data_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_RETURN_DATA]
    }
    fn ecc_op_wire_1(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_1]
    }
    fn ecc_op_wire_1_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_1]
    }
    fn ecc_op_wire_2(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_2]
    }
    fn ecc_op_wire_2_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_2]
    }
    fn ecc_op_wire_3(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_3]
    }
    fn ecc_op_wire_3_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_3]
    }
    fn ecc_op_wire_4(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_4]
    }
    fn ecc_op_wire_4_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_ECC_OP_WIRE_4]
    }
    fn calldata_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_CALLDATA_READ_COUNTS]
    }
    fn calldata_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_CALLDATA_READ_COUNTS]
    }
    fn calldata_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_CALLDATA_READ_TAGS]
    }
    fn calldata_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_CALLDATA_READ_TAGS]
    }
    fn calldata_inverses(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_CALLDATA_INVERSES]
    }
    fn calldata_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_CALLDATA_INVERSES]
    }
    fn secondary_calldata_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA_READ_COUNTS]
    }
    fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA_READ_COUNTS]
    }
    fn secondary_calldata_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA_READ_TAGS]
    }
    fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA_READ_TAGS]
    }
    fn secondary_calldata_inverses(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA_INVERSES]
    }
    fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_SECONDARY_CALLDATA_INVERSES]
    }
    fn return_data_read_counts(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_RETURN_DATA_READ_COUNTS]
    }
    fn return_data_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_RETURN_DATA_READ_COUNTS]
    }
    fn return_data_read_tags(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_RETURN_DATA_READ_TAGS]
    }
    fn return_data_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_RETURN_DATA_READ_TAGS]
    }
    fn return_data_inverses(&self) -> &T {
        &self.elements[MegaFlavour::WITNESS_RETURN_DATA_INVERSES]
    }
    fn return_data_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[MegaFlavour::WITNESS_RETURN_DATA_INVERSES]
    }
}
