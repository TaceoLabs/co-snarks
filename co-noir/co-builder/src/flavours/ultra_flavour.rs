use crate::{
    polynomials::{
        polynomial_flavours::{
            PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour,
            ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
        },
        polynomial_types::{
            PrecomputedEntities, ProverWitnessEntities, ShiftedWitnessEntities, WitnessEntities,
        },
    },
    prover_flavour::{Flavour, ProverFlavour},
};
use std::fmt::Debug;

type UltraPrecomputedEntities<T> =
    PrecomputedEntities<T, { UltraFlavour::PRECOMPUTED_ENTITIES_SIZE }>;
type UltraProverWitnessEntities<T> =
    ProverWitnessEntities<T, { UltraFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;
type UltraShiftedWitnessEntities<T> =
    ShiftedWitnessEntities<T, { UltraFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;
type UltraWitnessEntities<T> = WitnessEntities<T, { UltraFlavour::WITNESS_ENTITIES_SIZE }>;

#[derive(Default, Clone)]
pub struct UltraFlavour {}

impl ProverFlavour for UltraFlavour {
    type ProverWitnessEntities<T: Default + std::marker::Sync> = UltraProverWitnessEntities<T>;
    type ShiftedWitnessEntities<T: Default + Debug + Clone + std::marker::Sync> =
        UltraShiftedWitnessEntities<T>; // This is the same for Ultra and Mega
    type WitnessEntities<T: Default + Debug + Clone + std::marker::Sync> = UltraWitnessEntities<T>;
    type PrecomputedEntities<T: Default + Debug + Clone + std::marker::Sync> =
        UltraPrecomputedEntities<T>;

    const FLAVOUR: Flavour = Flavour::Ultra;
    const WITNESS_ENTITIES_SIZE: usize = 8;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 27;
    const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
        + Self::PRECOMPUTED_ENTITIES_SIZE
        + Self::SHIFTED_WITNESS_ENTITIES_SIZE;
    const PROVER_WITNESS_ENTITIES_SIZE: usize = Self::WITNESS_ENTITIES_SIZE - 2;

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
    const Q_BUSREAD: Option<usize> = None; //Not used in Ultra
    /// column 6
    const Q_LOOKUP: usize = 6;
    /// column 7
    const Q_ARITH: usize = 7;
    /// column 8
    const Q_DELTA_RANGE: usize = 8;
    /// column 9
    const Q_ELLIPTIC: usize = 9;
    /// column 10
    const Q_AUX: usize = 10;
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
    const LAGRANGE_ECC_OP: Option<usize> = None; //Not used in Ultra
    const DATABUS_ID: Option<usize> = None; //Not used in Ultra

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
    const ECC_OP_WIRE_1: Option<usize> = None;
    const ECC_OP_WIRE_2: Option<usize> = None;
    const ECC_OP_WIRE_3: Option<usize> = None;
    const ECC_OP_WIRE_4: Option<usize> = None;
    const CALLDATA: Option<usize> = None;
    const CALLDATA_READ_COUNTS: Option<usize> = None;
    const CALLDATA_READ_TAGS: Option<usize> = None;
    const CALLDATA_INVERSES: Option<usize> = None;
    const SECONDARY_CALLDATA: Option<usize> = None;
    const SECONDARY_CALLDATA_READ_COUNTS: Option<usize> = None;
    const SECONDARY_CALLDATA_READ_TAGS: Option<usize> = None;
    const SECONDARY_CALLDATA_INVERSES: Option<usize> = None;
    const RETURN_DATA: Option<usize> = None;
    const RETURN_DATA_READ_COUNTS: Option<usize> = None;
    const RETURN_DATA_READ_TAGS: Option<usize> = None;
    const RETURN_DATA_INVERSES: Option<usize> = None;

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
    const WITNESS_ECC_OP_WIRE_1: Option<usize> = None;
    const WITNESS_ECC_OP_WIRE_2: Option<usize> = None;
    const WITNESS_ECC_OP_WIRE_3: Option<usize> = None;
    const WITNESS_ECC_OP_WIRE_4: Option<usize> = None;
    const WITNESS_CALLDATA: Option<usize> = None;
    const WITNESS_CALLDATA_READ_COUNTS: Option<usize> = None;
    const WITNESS_CALLDATA_READ_TAGS: Option<usize> = None;
    const WITNESS_CALLDATA_INVERSES: Option<usize> = None;
    const WITNESS_SECONDARY_CALLDATA: Option<usize> = None;
    const WITNESS_SECONDARY_CALLDATA_READ_COUNTS: Option<usize> = None;
    const WITNESS_SECONDARY_CALLDATA_READ_TAGS: Option<usize> = None;
    const WITNESS_SECONDARY_CALLDATA_INVERSES: Option<usize> = None;
    const WITNESS_RETURN_DATA: Option<usize> = None;
    const WITNESS_RETURN_DATA_READ_COUNTS: Option<usize> = None;
    const WITNESS_RETURN_DATA_READ_TAGS: Option<usize> = None;
    const WITNESS_RETURN_DATA_INVERSES: Option<usize> = None;

    fn prover_witness_entity_from_vec<T: Default + Sync + Clone>(
        vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::ProverWitnessEntities<crate::prelude::Polynomial<T>> {
        UltraProverWitnessEntities {
            elements: std::array::from_fn(|i| vec[i].clone()),
        }
    }

    fn precomputed_entity_from_vec<T: Default + Debug + Clone + Sync>(
        vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::PrecomputedEntities<crate::prelude::Polynomial<T>> {
        UltraPrecomputedEntities {
            elements: std::array::from_fn(|i| vec[i].clone()),
        }
    }
}

impl<T: Default + Debug + Clone> PrecomputedEntitiesFlavour<T> for UltraPrecomputedEntities<T> {
    fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
    fn from_elements(elements: Vec<T>) -> Self {
        Self {
            elements: elements.try_into().unwrap(),
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
    fn get_table_polynomials(&self) -> &[T] {
        &self.elements[UltraFlavour::TABLE_1..=UltraFlavour::TABLE_4]
    }
    fn get_selectors_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::Q_M..=UltraFlavour::Q_POSEIDON2_INTERNAL]
    }
    fn get_sigmas_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::SIGMA_1..=UltraFlavour::SIGMA_4]
    }
    fn get_ids_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::ID_1..=UltraFlavour::ID_4]
    }
    fn get_table_polynomials_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::TABLE_1..=UltraFlavour::TABLE_4]
    }
    fn q_m(&self) -> &T {
        &self.elements[UltraFlavour::Q_M]
    }
    fn q_c(&self) -> &T {
        &self.elements[UltraFlavour::Q_C]
    }
    fn q_l(&self) -> &T {
        &self.elements[UltraFlavour::Q_L]
    }
    fn q_r(&self) -> &T {
        &self.elements[UltraFlavour::Q_R]
    }
    fn q_o(&self) -> &T {
        &self.elements[UltraFlavour::Q_O]
    }
    fn q_4(&self) -> &T {
        &self.elements[UltraFlavour::Q_4]
    }
    fn q_busread(&self) -> &T {
        if let Some(idx) = UltraFlavour::Q_BUSREAD {
            &self.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn q_arith(&self) -> &T {
        &self.elements[UltraFlavour::Q_ARITH]
    }
    fn q_delta_range(&self) -> &T {
        &self.elements[UltraFlavour::Q_DELTA_RANGE]
    }
    fn q_elliptic(&self) -> &T {
        &self.elements[UltraFlavour::Q_ELLIPTIC]
    }
    fn q_aux(&self) -> &T {
        &self.elements[UltraFlavour::Q_AUX]
    }
    fn q_lookup(&self) -> &T {
        &self.elements[UltraFlavour::Q_LOOKUP]
    }
    fn q_poseidon2_external(&self) -> &T {
        &self.elements[UltraFlavour::Q_POSEIDON2_EXTERNAL]
    }
    fn q_poseidon2_internal(&self) -> &T {
        &self.elements[UltraFlavour::Q_POSEIDON2_INTERNAL]
    }
    fn sigma_1(&self) -> &T {
        &self.elements[UltraFlavour::SIGMA_1]
    }
    fn sigma_2(&self) -> &T {
        &self.elements[UltraFlavour::SIGMA_2]
    }
    fn sigma_3(&self) -> &T {
        &self.elements[UltraFlavour::SIGMA_3]
    }
    fn sigma_4(&self) -> &T {
        &self.elements[UltraFlavour::SIGMA_4]
    }
    fn id_1(&self) -> &T {
        &self.elements[UltraFlavour::ID_1]
    }
    fn id_2(&self) -> &T {
        &self.elements[UltraFlavour::ID_2]
    }
    fn id_3(&self) -> &T {
        &self.elements[UltraFlavour::ID_3]
    }
    fn id_4(&self) -> &T {
        &self.elements[UltraFlavour::ID_4]
    }
    fn table_1(&self) -> &T {
        &self.elements[UltraFlavour::TABLE_1]
    }
    fn table_2(&self) -> &T {
        &self.elements[UltraFlavour::TABLE_2]
    }
    fn table_3(&self) -> &T {
        &self.elements[UltraFlavour::TABLE_3]
    }
    fn table_4(&self) -> &T {
        &self.elements[UltraFlavour::TABLE_4]
    }
    fn lagrange_first(&self) -> &T {
        &self.elements[UltraFlavour::LAGRANGE_FIRST]
    }
    fn lagrange_last(&self) -> &T {
        &self.elements[UltraFlavour::LAGRANGE_LAST]
    }
    fn lagrange_first_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::LAGRANGE_FIRST]
    }
    fn lagrange_last_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::LAGRANGE_LAST]
    }
    fn q_m_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_M]
    }
    fn q_c_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_C]
    }
    fn q_l_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_L]
    }
    fn q_r_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_R]
    }
    fn q_o_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_O]
    }
    fn q_4_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_4]
    }
    fn q_arith_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_ARITH]
    }
    fn q_delta_range_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_DELTA_RANGE]
    }
    fn q_elliptic_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_ELLIPTIC]
    }
    fn q_aux_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_AUX]
    }
    fn q_lookup_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_LOOKUP]
    }
    fn q_poseidon2_external_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_POSEIDON2_EXTERNAL]
    }
    fn q_poseidon2_internal_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::Q_POSEIDON2_INTERNAL]
    }
    fn table_1_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::TABLE_1]
    }
    fn table_2_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::TABLE_2]
    }
    fn table_3_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::TABLE_3]
    }
    fn table_4_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::TABLE_4]
    }
    fn sigma_1_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::SIGMA_1]
    }
    fn sigma_2_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::SIGMA_2]
    }
    fn sigma_3_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::SIGMA_3]
    }
    fn sigma_4_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::SIGMA_4]
    }
    fn id_1_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::ID_1]
    }
    fn id_2_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::ID_2]
    }
    fn id_3_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::ID_3]
    }
    fn id_4_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::ID_4]
    }
}
impl<T: Default> ProverWitnessEntitiesFlavour<T> for UltraProverWitnessEntities<T> {
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
            .take(UltraFlavour::W_4 + 1 - UltraFlavour::W_L)
    }
    fn get_wires(&self) -> &[T] {
        &self.elements[UltraFlavour::W_L..=UltraFlavour::W_4]
    }
    fn get_wires_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::W_L..=UltraFlavour::W_4]
    }
    fn w_l(&self) -> &T {
        &self.elements[UltraFlavour::W_L]
    }
    fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::W_L]
    }
    fn w_r(&self) -> &T {
        &self.elements[UltraFlavour::W_R]
    }
    fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::W_R]
    }
    fn w_o(&self) -> &T {
        &self.elements[UltraFlavour::W_O]
    }
    fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::W_O]
    }
    fn w_4(&self) -> &T {
        &self.elements[UltraFlavour::W_4]
    }
    fn lookup_read_counts(&self) -> &T {
        &self.elements[UltraFlavour::LOOKUP_READ_COUNTS]
    }
    fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::LOOKUP_READ_COUNTS]
    }
    fn lookup_read_tags(&self) -> &T {
        &self.elements[UltraFlavour::LOOKUP_READ_TAGS]
    }
    fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::LOOKUP_READ_TAGS]
    }
    fn lookup_read_counts_and_tags(&self) -> &[T] {
        &self.elements[UltraFlavour::LOOKUP_READ_COUNTS..UltraFlavour::LOOKUP_READ_TAGS + 1]
    }
    fn lookup_read_counts_and_tags_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::LOOKUP_READ_COUNTS..UltraFlavour::LOOKUP_READ_TAGS + 1]
    }
}

impl<T: Default + Debug + Clone> WitnessEntitiesFlavour<T> for UltraWitnessEntities<T> {
    fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
    fn from_elements(elements: Vec<T>) -> Self {
        Self {
            elements: elements.try_into().unwrap(),
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
        &self.elements[UltraFlavour::WITNESS_W_L..=UltraFlavour::WITNESS_Z_PERM]
    }
    fn to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[UltraFlavour::WITNESS_W_L..=UltraFlavour::WITNESS_Z_PERM]
    }
    fn w_l(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_L]
    }
    fn w_r(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_R]
    }
    fn w_o(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_O]
    }
    fn w_4(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_4]
    }
    fn z_perm(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_Z_PERM]
    }
    fn lookup_inverses(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_LOOKUP_INVERSES]
    }
    fn lookup_read_counts(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_LOOKUP_READ_COUNTS]
    }
    fn lookup_read_tags(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_LOOKUP_READ_TAGS]
    }
    fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_L]
    }
    fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_R]
    }
    fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_O]
    }
    fn w_4_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_4]
    }
    fn z_perm_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_Z_PERM]
    }
    fn lookup_inverses_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_LOOKUP_INVERSES]
    }
    fn lookup_read_counts_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_LOOKUP_READ_COUNTS]
    }
    fn lookup_read_tags_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_LOOKUP_READ_TAGS]
    }
}

impl<T: Default + Debug + Clone> ShiftedWitnessEntitiesFlavour<T>
    for UltraShiftedWitnessEntities<T>
{
    fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
    fn from_elements(elements: Vec<T>) -> Self {
        Self {
            elements: elements.try_into().unwrap(),
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
    fn w_l(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_L]
    }
    fn w_r(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_R]
    }
    fn w_o(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_O]
    }
    fn w_4(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_W_4]
    }
    fn z_perm(&self) -> &T {
        &self.elements[UltraFlavour::WITNESS_Z_PERM]
    }
    fn w_l_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_L]
    }
    fn w_r_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_R]
    }
    fn w_o_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_O]
    }
    fn w_4_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_W_4]
    }
    fn z_perm_mut(&mut self) -> &mut T {
        &mut self.elements[UltraFlavour::WITNESS_Z_PERM]
    }
}
