use crate::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use crate::prelude::WitnessEntities;
use crate::prover_flavour::{Flavour, ProverFlavour};
use crate::{
    polynomials::polynomial_flavours::{
        PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour, WitnessEntitiesFlavour,
    },
    prelude::{PrecomputedEntities, ProverWitnessEntities, ShiftedWitnessEntities},
};
#[derive(Default)]
pub struct ECCVMFlavour {}

impl ECCVMFlavour {
    const NUM_DERIVED_WITNESS_ENTITIES_NON_SHIFTED: usize = 1;
    pub fn non_shifted_labels() -> &'static [&'static str] {
        todo!()
    }

    pub fn to_be_shifted_without_accumulators_labels() -> &'static [&'static str] {
        todo!()
    }
    pub fn to_be_shifted_accumulators_labels() -> &'static [&'static str] {
        todo!()
    }
}

impl ProverFlavour for ECCVMFlavour {
    const FLAVOUR: Flavour = Flavour::ECCVM;

    type PrecomputedEntities<T: Default + Clone + std::marker::Sync> = ECCVMPrecomputedEntities<T>;

    type WitnessEntities<T: Default + std::marker::Sync> = ECCVMWitnessEntities<T>;

    type ShiftedWitnessEntities<T: Default + std::marker::Sync> = ECCVMShiftedWitnessEntities<T>;

    type ProverWitnessEntities<T: Default + std::marker::Sync> = ECCVMProverWitnessEntities<T>;

    const WITNESS_ENTITIES_SIZE: usize = 87;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 26;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 3;
    const MAX_PARTIAL_RELATION_LENGTH: usize = 22;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = 24;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = 24; //ECCVM is always ZK
    const Q_M: usize = 0;
    const Q_C: usize = 0;
    const Q_L: usize = 0;
    const Q_R: usize = 0;
    const Q_O: usize = 0;
    const Q_4: usize = 0;
    const Q_BUSREAD: Option<usize> = None;
    const Q_LOOKUP: usize = 0;
    const Q_ARITH: usize = 0;
    const Q_DELTA_RANGE: usize = 0;
    const Q_ELLIPTIC: usize = 0;
    const Q_AUX: usize = 0;
    const Q_POSEIDON2_EXTERNAL: usize = 0;
    const Q_POSEIDON2_INTERNAL: usize = 0;
    const SIGMA_1: usize = 0;
    const SIGMA_2: usize = 0;
    const SIGMA_3: usize = 0;
    const SIGMA_4: usize = 0;
    const ID_1: usize = 0;
    const ID_2: usize = 0;
    const ID_3: usize = 0;
    const ID_4: usize = 0;
    const TABLE_1: usize = 0;
    const TABLE_2: usize = 0;
    const TABLE_3: usize = 0;
    const TABLE_4: usize = 0;
    const LAGRANGE_FIRST: usize = 0;
    const LAGRANGE_LAST: usize = 0;
    const LAGRANGE_ECC_OP: Option<usize> = None;
    const DATABUS_ID: Option<usize> = None;
    const W_L: usize = 0;
    const W_R: usize = 0;
    const W_O: usize = 0;
    const W_4: usize = 0;
    const LOOKUP_READ_COUNTS: usize = 0;
    const LOOKUP_READ_TAGS: usize = 0;
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
    const WITNESS_W_L: usize = 0;
    const WITNESS_W_R: usize = 0;
    const WITNESS_W_O: usize = 0;
    const WITNESS_W_4: usize = 0;
    const WITNESS_Z_PERM: usize = 0;
    const WITNESS_LOOKUP_INVERSES: usize = 0;
    const WITNESS_LOOKUP_READ_COUNTS: usize = 0;
    const WITNESS_LOOKUP_READ_TAGS: usize = 0;
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
        todo!()
    }

    fn precomputed_entity_from_vec<T: Default + Clone + Sync>(
        vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::PrecomputedEntities<crate::prelude::Polynomial<T>> {
        todo!()
    }
}

pub type ECCVMPrecomputedEntities<T> =
    PrecomputedEntities<T, { ECCVMFlavour::PRECOMPUTED_ENTITIES_SIZE }>;
pub type ECCVMProverWitnessEntities<T> =
    ProverWitnessEntities<T, { ECCVMFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;
pub type ECCVMShiftedWitnessEntities<T> =
    ShiftedWitnessEntities<T, { ECCVMFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;
pub type ECCVMWitnessEntities<T> = WitnessEntities<T, { ECCVMFlavour::WITNESS_ENTITIES_SIZE }>;
impl<T: Default> ProverWitnessEntitiesFlavour<T> for ECCVMProverWitnessEntities<T> {
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
    //TODO FLORIN panic or something else?
    fn into_wires(self) -> impl Iterator<Item = T> {
        std::iter::empty()
    }
}
impl<T: Default> PrecomputedEntitiesFlavour<T> for ECCVMPrecomputedEntities<T> {
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

    fn new() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default> WitnessEntitiesFlavour<T> for ECCVMWitnessEntities<T> {
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
}
impl<T: Default> ShiftedWitnessEntitiesFlavour<T> for ECCVMShiftedWitnessEntities<T> {
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
}

impl<T: Default> ECCVMProverWitnessEntities<T> {
    pub fn non_shifted(&self) -> &[T] {
        todo!()
    }

    pub fn non_shifted_mut(&mut self) -> &mut [T] {
        todo!()
    }

    pub fn to_be_shifted_without_accumulators(&self) -> &[T] {
        todo!()
    }

    pub fn to_be_shifted_without_accumulators_mut(&mut self) -> &mut [T] {
        todo!()
    }

    pub fn to_be_shifted_accumulators(&self) -> &[T] {
        todo!()
    }

    pub fn to_be_shifted_accumulators_mut(&mut self) -> &mut [T] {
        todo!()
    }

    pub fn msm_add(&self) -> &T {
        todo!()
    }
    pub fn msm_add_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_skew(&self) -> &T {
        todo!()
    }
    pub fn msm_skew_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_select(&self) -> &T {
        todo!()
    }
    pub fn precompute_select_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_round(&self) -> &T {
        todo!()
    }
    pub fn precompute_pc(&self) -> &T {
        todo!()
    }
    pub fn precompute_s1hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s1lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_s2hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s2lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_s3hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s3lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_s4hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s4lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_skew(&self) -> &T {
        todo!()
    }
    pub fn precompute_point_transition(&self) -> &T {
        todo!()
    }
    pub fn precompute_tx(&self) -> &T {
        todo!()
    }
    pub fn precompute_ty(&self) -> &T {
        todo!()
    }
    pub fn precompute_scalar_sum(&self) -> &T {
        todo!()
    }
    pub fn msm_transition_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_pc_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_accumulator_x_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_accumulator_y_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_size_of_msm(&self) -> &T {
        todo!()
    }
    pub fn precompute_round_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_pc_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s1hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s1lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s2hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s2lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s3hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s3lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s4hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s4lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_skew_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_point_transition_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_tx_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_ty_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_scalar_sum_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_transition_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_pc_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_accumulator_x_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_accumulator_y_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_size_of_msm_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_pc(&self) -> &T {
        todo!()
    }
    pub fn msm_count(&self) -> &T {
        todo!()
    }
    pub fn msm_round(&self) -> &T {
        todo!()
    }
    pub fn msm_add1(&self) -> &T {
        todo!()
    }
    pub fn msm_slice1(&self) -> &T {
        todo!()
    }
    pub fn msm_add2(&self) -> &T {
        todo!()
    }
    pub fn msm_slice2(&self) -> &T {
        todo!()
    }
    pub fn msm_add3(&self) -> &T {
        todo!()
    }
    pub fn msm_slice3(&self) -> &T {
        todo!()
    }
    pub fn msm_add4(&self) -> &T {
        todo!()
    }
    pub fn msm_slice4(&self) -> &T {
        todo!()
    }
    pub fn transcript_pc(&self) -> &T {
        todo!()
    }
    pub fn transcript_px(&self) -> &T {
        todo!()
    }
    pub fn transcript_op(&self) -> &T {
        todo!()
    }
    pub fn transcript_py(&self) -> &T {
        todo!()
    }
    pub fn transcript_z1(&self) -> &T {
        todo!()
    }
    pub fn transcript_z2(&self) -> &T {
        todo!()
    }
    pub fn transcript_z1zero(&self) -> &T {
        todo!()
    }
    pub fn transcript_z2zero(&self) -> &T {
        todo!()
    }
    pub fn transcript_base_infinity(&self) -> &T {
        todo!()
    }
    pub fn transcript_mul(&self) -> &T {
        todo!()
    }
    pub fn cube_root_of_unity(&self) -> &T {
        todo!()
    }
    pub fn transcript_pc_shift(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_x(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_y(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_transition(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_count(&self) -> &T {
        todo!()
    }
    pub fn msm_pc_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_count_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_round_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add4_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice4_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_pc_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_px_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_py_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z1zero_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z2zero_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_base_infinity_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_mul_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn cube_root_of_unity_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_pc_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_x_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_y_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_transition_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_count_mut(&mut self) -> &mut T {
        todo!()
    }

    pub fn msm_x1(&self) -> &T {
        todo!()
    }
    pub fn msm_x2(&self) -> &T {
        todo!()
    }
    pub fn msm_x3(&self) -> &T {
        todo!()
    }
    pub fn msm_x4(&self) -> &T {
        todo!()
    }
    pub fn msm_y1(&self) -> &T {
        todo!()
    }
    pub fn msm_y2(&self) -> &T {
        todo!()
    }
    pub fn msm_y3(&self) -> &T {
        todo!()
    }
    pub fn msm_y4(&self) -> &T {
        todo!()
    }
    pub fn msm_x1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_x2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_x3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_x4_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y4_mut(&mut self) -> &mut T {
        todo!()
    }
}

impl<T: Default> ECCVMWitnessEntities<T> {
    pub fn non_shifted(&self) -> &[T] {
        todo!()
    }

    pub fn non_shifted_mut(&mut self) -> &mut [T] {
        todo!()
    }

    pub fn to_be_shifted_without_accumulators(&self) -> &[T] {
        todo!()
    }

    pub fn to_be_shifted_without_accumulators_mut(&mut self) -> &mut [T] {
        todo!()
    }

    pub fn to_be_shifted_accumulators(&self) -> &[T] {
        todo!()
    }

    pub fn to_be_shifted_accumulators_mut(&mut self) -> &mut [T] {
        todo!()
    }

    pub fn msm_add(&self) -> &T {
        todo!()
    }
    pub fn msm_add_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_skew(&self) -> &T {
        todo!()
    }
    pub fn msm_skew_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_select(&self) -> &T {
        todo!()
    }
    pub fn precompute_select_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_round(&self) -> &T {
        todo!()
    }
    pub fn precompute_pc(&self) -> &T {
        todo!()
    }
    pub fn precompute_s1hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s1lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_s2hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s2lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_s3hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s3lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_s4hi(&self) -> &T {
        todo!()
    }
    pub fn precompute_s4lo(&self) -> &T {
        todo!()
    }
    pub fn precompute_skew(&self) -> &T {
        todo!()
    }
    pub fn precompute_point_transition(&self) -> &T {
        todo!()
    }
    pub fn precompute_tx(&self) -> &T {
        todo!()
    }
    pub fn precompute_ty(&self) -> &T {
        todo!()
    }
    pub fn precompute_scalar_sum(&self) -> &T {
        todo!()
    }
    pub fn msm_transition_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_pc_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_accumulator_x_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_accumulator_y_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_size_of_msm(&self) -> &T {
        todo!()
    }
    pub fn precompute_round_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_pc_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s1hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s1lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s2hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s2lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s3hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s3lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s4hi_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_s4lo_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_skew_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_point_transition_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_tx_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_ty_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn precompute_scalar_sum_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_transition_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_pc_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_accumulator_x_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_accumulator_y_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_size_of_msm_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_pc(&self) -> &T {
        todo!()
    }
    pub fn msm_count(&self) -> &T {
        todo!()
    }
    pub fn msm_round(&self) -> &T {
        todo!()
    }
    pub fn msm_add1(&self) -> &T {
        todo!()
    }
    pub fn msm_slice1(&self) -> &T {
        todo!()
    }
    pub fn msm_add2(&self) -> &T {
        todo!()
    }
    pub fn msm_slice2(&self) -> &T {
        todo!()
    }
    pub fn msm_add3(&self) -> &T {
        todo!()
    }
    pub fn msm_slice3(&self) -> &T {
        todo!()
    }
    pub fn msm_add4(&self) -> &T {
        todo!()
    }
    pub fn msm_slice4(&self) -> &T {
        todo!()
    }
    pub fn transcript_pc(&self) -> &T {
        todo!()
    }
    pub fn transcript_px(&self) -> &T {
        todo!()
    }
    pub fn transcript_op(&self) -> &T {
        todo!()
    }
    pub fn transcript_py(&self) -> &T {
        todo!()
    }
    pub fn transcript_z1(&self) -> &T {
        todo!()
    }
    pub fn transcript_z2(&self) -> &T {
        todo!()
    }
    pub fn transcript_z1zero(&self) -> &T {
        todo!()
    }
    pub fn transcript_z2zero(&self) -> &T {
        todo!()
    }
    pub fn transcript_base_infinity(&self) -> &T {
        todo!()
    }
    pub fn transcript_mul(&self) -> &T {
        todo!()
    }
    pub fn cube_root_of_unity(&self) -> &T {
        todo!()
    }
    pub fn transcript_pc_shift(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_x(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_y(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_transition(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_count(&self) -> &T {
        todo!()
    }
    pub fn msm_pc_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_count_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_round_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_add4_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_slice4_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_pc_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_px_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_py_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z1zero_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_z2zero_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_base_infinity_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_mul_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn cube_root_of_unity_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_pc_shift_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_x_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_y_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_transition_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn transcript_msm_count_mut(&mut self) -> &mut T {
        todo!()
    }

    pub fn msm_x1(&self) -> &T {
        todo!()
    }
    pub fn msm_x2(&self) -> &T {
        todo!()
    }
    pub fn msm_x3(&self) -> &T {
        todo!()
    }
    pub fn msm_x4(&self) -> &T {
        todo!()
    }
    pub fn msm_y1(&self) -> &T {
        todo!()
    }
    pub fn msm_y2(&self) -> &T {
        todo!()
    }
    pub fn msm_y3(&self) -> &T {
        todo!()
    }
    pub fn msm_y4(&self) -> &T {
        todo!()
    }
    pub fn msm_x1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_x2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_x3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_x4_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y1_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y2_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y3_mut(&mut self) -> &mut T {
        todo!()
    }
    pub fn msm_y4_mut(&mut self) -> &mut T {
        todo!()
    }

    pub fn transcript_msm_count_zero_at_transition(&self) -> &T {
        todo!()
    }
    pub fn transcript_add(&self) -> &T {
        todo!()
    }
    pub fn transcript_eq(&self) -> &T {
        todo!()
    }
    pub fn transcript_accumulator_empty(&self) -> &T {
        todo!()
    }
    pub fn transcript_reset_accumulator(&self) -> &T {
        todo!()
    }
    pub fn transcript_msm_infinity(&self) -> &T {
        todo!()
    }
    pub fn transcript_add_x_equal(&self) -> &T {
        todo!()
    }
    pub fn transcript_add_y_equal(&self) -> &T {
        todo!()
    }
    pub fn msm_transition(&self) -> &T {
        todo!()
    }
    pub fn msm_double(&self) -> &T {
        todo!()
    }
    pub fn msm_collision_x1(&self) -> &T {
        todo!()
    }
    pub fn msm_collision_x2(&self) -> &T {
        todo!()
    }
    pub fn msm_collision_x3(&self) -> &T {
        todo!()
    }
    pub fn msm_collision_x4(&self) -> &T {
        todo!()
    }
    pub fn msm_lambda1(&self) -> &T {
        todo!()
    }
    pub fn msm_lambda2(&self) -> &T {
        todo!()
    }
    pub fn msm_lambda3(&self) -> &T {
        todo!()
    }
    pub fn msm_lambda4(&self) -> &T {
        todo!()
    }
    pub fn msm_add1_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_accumulator_x(&self) -> &T {
        todo!()
    }
    pub fn msm_accumulator_y(&self) -> &T {
        todo!()
    }
    pub fn msm_round_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_add_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_skew_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_double_shift(&self) -> &T {
        todo!()
    }
    pub fn msm_count_shift(&self) -> &T {
        todo!()
    }
    pub fn lookup_read_counts_0(&self) -> &T {
        todo!()
    }
    pub fn lookup_read_counts_1(&self) -> &T {
        todo!()
    }
}

impl<T: Default> ECCVMShiftedWitnessEntities<T> {
    pub fn z_perm_shift(&self) -> &T {
        todo!()
    }
    pub fn transcript_mul_shift(&self) -> &T {
        todo!()
    } // column 0
    pub fn transcript_msm_count_shift(&self) -> &T {
        todo!()
    } // column 1
    pub fn precompute_scalar_sum_shift(&self) -> &T {
        todo!()
    } // column 2
    pub fn precompute_s1hi_shift(&self) -> &T {
        todo!()
    } // column 3
    pub fn precompute_dx_shift(&self) -> &T {
        todo!()
    } // column 4
    pub fn precompute_dy_shift(&self) -> &T {
        todo!()
    } // column 5
    pub fn precompute_tx_shift(&self) -> &T {
        todo!()
    } // column 6
    pub fn precompute_ty_shift(&self) -> &T {
        todo!()
    } // column 7
    pub fn msm_transition_shift(&self) -> &T {
        todo!()
    } // column 8
    pub fn msm_add_shift(&self) -> &T {
        todo!()
    } // column 9
    pub fn msm_double_shift(&self) -> &T {
        todo!()
    } // column 10
    pub fn msm_skew_shift(&self) -> &T {
        todo!()
    } // column 11
    pub fn msm_accumulator_x_shift(&self) -> &T {
        todo!()
    } // column 12
    pub fn msm_accumulator_y_shift(&self) -> &T {
        todo!()
    } // column 13
    pub fn msm_count_shift(&self) -> &T {
        todo!()
    } // column 14
    pub fn msm_round_shift(&self) -> &T {
        todo!()
    } // column 15
    pub fn msm_add1_shift(&self) -> &T {
        todo!()
    } // column 16
    pub fn msm_pc_shift(&self) -> &T {
        todo!()
    } // column 17
    pub fn precompute_pc_shift(&self) -> &T {
        todo!()
    } // column 18
    pub fn transcript_pc_shift(&self) -> &T {
        todo!()
    } // column 19
    pub fn precompute_round_shift(&self) -> &T {
        todo!()
    } // column 20
    pub fn precompute_select_shift(&self) -> &T {
        todo!()
    } // column 21
    pub fn transcript_accumulator_empty_shift(&self) -> &T {
        todo!()
    } // column 22
    pub fn transcript_accumulator_x_shift(&self) -> &T {
        todo!()
    } // column 23
    pub fn transcript_accumulator_y_shift(&self) -> &T {
        todo!()
    }
}
