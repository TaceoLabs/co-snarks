use crate::{
    polynomials::polynomial_flavours::{
        PolyGFlavour, PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour,
        ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
    },
    prelude::{
        PrecomputedEntities, ProverWitnessEntities, ShiftedWitnessEntities, WitnessEntities,
    },
    prover_flavour::{Flavour, ProverFlavour},
};
use std::fmt::Debug;

#[derive(Default)]
pub struct TranslatorFlavour {}
impl TranslatorFlavour {
    pub const NUM_LIMB_BITS: usize = 68;
    pub const RESULT_ROW: usize = 2;
    pub const CONST_TRANSLATOR_LOG_N: usize = 18;

    pub fn wire_to_be_shifted_labels() -> &'static [&'static str] {
        todo!()
    }
    pub fn get_ordered_range_constraints_labels() -> &'static [&'static str] {
        todo!()
    }
}

impl ProverFlavour for TranslatorFlavour {
    const FLAVOUR: Flavour = Flavour::Translator;
    type PolyG<'a, T: Default + 'a> = TranslatorPolyG<'a, T>;

    type PrecomputedEntities<T: Default + Clone + Debug + std::marker::Sync> =
        TranslatorPrecomputedEntities<T>;

    type WitnessEntities<T: Default + Debug + Clone + std::marker::Sync> =
        TranslatorWitnessEntities<T>;

    type ShiftedWitnessEntities<T: Default + Clone + Debug + std::marker::Sync> =
        TranslatorShiftedWitnessEntities<T>;

    type ProverWitnessEntities<T: Default + std::marker::Sync> = TranslatorProverWitnessEntities<T>;

    const WITNESS_ENTITIES_SIZE: usize = 91;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 86;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 9;
    const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = 9; //Translator is always ZK
    const Q_M: usize = usize::MAX;
    const Q_C: usize = usize::MAX;
    const Q_L: usize = usize::MAX;
    const Q_R: usize = usize::MAX;
    const Q_O: usize = usize::MAX;
    const Q_4: usize = usize::MAX;
    const Q_BUSREAD: usize = usize::MAX;
    const Q_LOOKUP: usize = usize::MAX;
    const Q_ARITH: usize = usize::MAX;
    const Q_DELTA_RANGE: usize = usize::MAX;
    const Q_ELLIPTIC: usize = usize::MAX;
    const Q_AUX: usize = usize::MAX;
    const Q_POSEIDON2_EXTERNAL: usize = usize::MAX;
    const Q_POSEIDON2_INTERNAL: usize = usize::MAX;
    const SIGMA_1: usize = usize::MAX;
    const SIGMA_2: usize = usize::MAX;
    const SIGMA_3: usize = usize::MAX;
    const SIGMA_4: usize = usize::MAX;
    const ID_1: usize = usize::MAX;
    const ID_2: usize = usize::MAX;
    const ID_3: usize = usize::MAX;
    const ID_4: usize = usize::MAX;
    const TABLE_1: usize = usize::MAX;
    const TABLE_2: usize = usize::MAX;
    const TABLE_3: usize = usize::MAX;
    const TABLE_4: usize = usize::MAX;
    const LAGRANGE_FIRST: usize = usize::MAX;
    const LAGRANGE_LAST: usize = usize::MAX;
    const LAGRANGE_ECC_OP: usize = usize::MAX;
    const DATABUS_ID: usize = usize::MAX;
    const W_L: usize = usize::MAX;
    const W_R: usize = usize::MAX;
    const W_O: usize = usize::MAX;
    const W_4: usize = usize::MAX;
    const LOOKUP_READ_COUNTS: usize = usize::MAX;
    const LOOKUP_READ_TAGS: usize = usize::MAX;
    const ECC_OP_WIRE_1: usize = usize::MAX;
    const ECC_OP_WIRE_2: usize = usize::MAX;
    const ECC_OP_WIRE_3: usize = usize::MAX;
    const ECC_OP_WIRE_4: usize = usize::MAX;
    const CALLDATA: usize = usize::MAX;
    const CALLDATA_READ_COUNTS: usize = usize::MAX;
    const CALLDATA_READ_TAGS: usize = usize::MAX;
    const CALLDATA_INVERSES: usize = usize::MAX;
    const SECONDARY_CALLDATA: usize = usize::MAX;
    const SECONDARY_CALLDATA_READ_COUNTS: usize = usize::MAX;
    const SECONDARY_CALLDATA_READ_TAGS: usize = usize::MAX;
    const SECONDARY_CALLDATA_INVERSES: usize = usize::MAX;
    const RETURN_DATA: usize = usize::MAX;
    const RETURN_DATA_READ_COUNTS: usize = usize::MAX;
    const RETURN_DATA_READ_TAGS: usize = usize::MAX;
    const RETURN_DATA_INVERSES: usize = usize::MAX;
    const WITNESS_W_L: usize = usize::MAX;
    const WITNESS_W_R: usize = usize::MAX;
    const WITNESS_W_O: usize = usize::MAX;
    const WITNESS_W_4: usize = usize::MAX;
    const WITNESS_Z_PERM: usize = usize::MAX;
    const WITNESS_LOOKUP_INVERSES: usize = usize::MAX;
    const WITNESS_LOOKUP_READ_COUNTS: usize = usize::MAX;
    const WITNESS_LOOKUP_READ_TAGS: usize = usize::MAX;
    const WITNESS_ECC_OP_WIRE_1: usize = usize::MAX;
    const WITNESS_ECC_OP_WIRE_2: usize = usize::MAX;
    const WITNESS_ECC_OP_WIRE_3: usize = usize::MAX;
    const WITNESS_ECC_OP_WIRE_4: usize = usize::MAX;
    const WITNESS_CALLDATA: usize = usize::MAX;
    const WITNESS_CALLDATA_READ_COUNTS: usize = usize::MAX;
    const WITNESS_CALLDATA_READ_TAGS: usize = usize::MAX;
    const WITNESS_CALLDATA_INVERSES: usize = usize::MAX;
    const WITNESS_SECONDARY_CALLDATA: usize = usize::MAX;
    const WITNESS_SECONDARY_CALLDATA_READ_COUNTS: usize = usize::MAX;
    const WITNESS_SECONDARY_CALLDATA_READ_TAGS: usize = usize::MAX;
    const WITNESS_SECONDARY_CALLDATA_INVERSES: usize = usize::MAX;
    const WITNESS_RETURN_DATA: usize = usize::MAX;
    const WITNESS_RETURN_DATA_READ_COUNTS: usize = usize::MAX;
    const WITNESS_RETURN_DATA_READ_TAGS: usize = usize::MAX;
    const WITNESS_RETURN_DATA_INVERSES: usize = usize::MAX;

    fn prover_witness_entity_from_vec<T: Default + Sync + Clone>(
        _vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::ProverWitnessEntities<crate::prelude::Polynomial<T>> {
        todo!()
    }

    fn precomputed_entity_from_vec<T: Default + Clone + Sync + Debug>(
        _vec: Vec<crate::prelude::Polynomial<T>>,
    ) -> Self::PrecomputedEntities<crate::prelude::Polynomial<T>> {
        todo!()
    }
}
pub type TranslatorPrecomputedEntities<T> =
    PrecomputedEntities<T, { TranslatorFlavour::PRECOMPUTED_ENTITIES_SIZE }>;
pub type TranslatorProverWitnessEntities<T> =
    ProverWitnessEntities<T, { TranslatorFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;
pub type TranslatorShiftedWitnessEntities<T> =
    ShiftedWitnessEntities<T, { TranslatorFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;
pub type TranslatorWitnessEntities<T> =
    WitnessEntities<T, { TranslatorFlavour::WITNESS_ENTITIES_SIZE }>;

pub struct TranslatorPolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; TranslatorFlavour::SHIFTED_WITNESS_ENTITIES_SIZE],
}
impl<'a, T: Default> PolyGFlavour<'a, T> for TranslatorPolyG<'a, T> {
    fn iter(&self) -> impl Iterator<Item = &'a T> {
        self.wires.iter()
    }
    fn from_slice(input: &'a [T]) -> Self {
        assert_eq!(
            input.len(),
            TranslatorFlavour::SHIFTED_WITNESS_ENTITIES_SIZE,
            "Input slice length does not match the expected size for Translator flavour."
        );
        Self {
            wires: input
                .try_into()
                .unwrap_or_else(|_| panic!("Slice length mismatch")),
        }
    }
}

impl<T: Default> ProverWitnessEntitiesFlavour<T> for TranslatorProverWitnessEntities<T> {
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
        std::iter::empty()
    }
}
impl<T: Default + Debug> PrecomputedEntitiesFlavour<T> for TranslatorPrecomputedEntities<T> {
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

    fn from_elements(elements: Vec<T>) -> Self {
        todo!()
    }
}
impl<T: Default + Debug> WitnessEntitiesFlavour<T> for TranslatorWitnessEntities<T> {
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

    fn from_elements(elements: Vec<T>) -> Self {
        todo!()
    }
}
impl<T: Default + Debug> ShiftedWitnessEntitiesFlavour<T> for TranslatorShiftedWitnessEntities<T> {
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

    fn from_elements(elements: Vec<T>) -> Self {
        todo!()
    }
}
impl<T: Default> TranslatorPrecomputedEntities<T> {
    pub fn ordered_extra_range_constraints_numerator(&self) -> &T {
        todo!()
    }

    pub fn lagrange_odd_in_minicircuit(&self) -> &T {
        todo!()
    }
    pub fn lagrange_even_in_minicircuit(&self) -> &T {
        todo!()
    }
    pub fn lagrange_result_row(&self) -> &T {
        todo!()
    }
    pub fn lagrange_last_in_minicircuit(&self) -> &T {
        todo!()
    }
    pub fn lagrange_masking(&self) -> &T {
        todo!()
    }
    pub fn lagrange_real_last(&self) -> &T {
        todo!()
    }
}

impl<T: Default> TranslatorProverWitnessEntities<T> {
    pub fn accumulators_binary_limbs_0(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_1(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_2(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_3(&self) -> &T {
        todo!()
    }

    pub fn wire_to_be_shifted_mut(&mut self) -> &mut [T] {
        todo!()
    }
    pub fn get_ordered_range_constraints_mut(&mut self) -> &mut [T] {
        todo!()
    }
    pub fn interleaved_range_constraints_0(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_1(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_2(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_3(&self) -> &T {
        todo!()
    }

    pub fn ordered_range_constraints_0(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_1(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_2(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_3(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_4(&self) -> &T {
        todo!()
    }
}

impl<T: Default> TranslatorWitnessEntities<T> {
    pub fn accumulators_binary_limbs_0(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_1(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_2(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_3(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_0(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_1(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_2(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_3(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_4(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_0(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_1(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_2(&self) -> &T {
        todo!()
    }
    pub fn interleaved_range_constraints_3(&self) -> &T {
        todo!()
    }
    pub fn op(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_4(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_0(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_1(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_2(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_3(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_tail(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_binary_limbs(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_binary_limbs(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs(&self) -> &T {
        todo!()
    }
    pub fn x_lo_y_hi(&self) -> &T {
        todo!()
    }
    pub fn x_hi_z_1(&self) -> &T {
        todo!()
    }
    pub fn y_lo_z_2(&self) -> &T {
        todo!()
    }
}
impl<T: Default> TranslatorShiftedWitnessEntities<T> {
    pub fn ordered_range_constraints_0_shift(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_1_shift(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_2_shift(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_3_shift(&self) -> &T {
        todo!()
    }
    pub fn ordered_range_constraints_4_shift(&self) -> &T {
        todo!()
    }
    pub fn z_perm_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_0_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_1_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_2_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulators_binary_limbs_3_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_binary_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_binary_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_0_shift(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_1_shift(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_2_shift(&self) -> &T {
        todo!()
    }
    pub fn relation_wide_limbs_range_constraint_3_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_low_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn p_x_high_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_low_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn p_y_high_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn z_low_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn z_high_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_low_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_low_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
    pub fn quotient_high_limbs_range_constraint_4_shift(&self) -> &T {
        todo!()
    }
    pub fn x_lo_y_hi_shift(&self) -> &T {
        todo!()
    }
    pub fn x_hi_z_1_shift(&self) -> &T {
        todo!()
    }
    pub fn y_lo_z_2_shift(&self) -> &T {
        todo!()
    }
    pub fn accumulator_high_limbs_range_constraint_tail_shift(&self) -> &T {
        todo!()
    }
}
