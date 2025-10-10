use co_noir_common::polynomials::polynomial::Polynomial;

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
    // Number of bits in a binary limb
    // This is not a configurable value. Relations are sepcifically designed for it to be 68
    pub const NUM_LIMB_BITS: usize = 68;
    pub const RESULT_ROW: usize = 2;
    // Log of size of interleaved_* and ordered_* polynomials
    pub const CONST_TRANSLATOR_LOG_N: usize = 18;
    // The fixed  log size of Translator circuit determining the size most polynomials (except the ones
    // involved in the interleaving subprotocol). It should be determined by the size of the EccOpQueue.
    pub const LOG_MINI_CIRCUIT_SIZE: usize = 14;
    pub const MINI_CIRCUIT_SIZE: usize = 1 << Self::LOG_MINI_CIRCUIT_SIZE;
    // How many mini_circuit_size polynomials are interleaved in one interleaved_*
    pub const INTERLEAVING_GROUP_SIZE: usize = 16;
    // The step in the DeltaRangeConstraint relation i.e. the maximum difference between two consecutive values
    pub const SORT_STEP: usize = 3;
    // The number of interleaved_* wires
    pub const NUM_INTERLEAVED_WIRES: usize = 4;

    pub fn wire_to_be_shifted_labels() -> &'static [&'static str] {
        &[
            "X_LO_Y_HI",
            "X_HI_Z_1",
            "Y_LO_Z_2",
            "P_X_LOW_LIMBS",
            "P_X_HIGH_LIMBS",
            "P_Y_LOW_LIMBS",
            "P_Y_HIGH_LIMBS",
            "Z_LOW_LIMBS",
            "Z_HIGH_LIMBS",
            "ACCUMULATORS_BINARY_LIMBS_0",
            "ACCUMULATORS_BINARY_LIMBS_1",
            "ACCUMULATORS_BINARY_LIMBS_2",
            "ACCUMULATORS_BINARY_LIMBS_3",
            "QUOTIENT_LOW_BINARY_LIMBS",
            "QUOTIENT_HIGH_BINARY_LIMBS",
            "RELATION_WIDE_LIMBS",
            "P_X_LOW_LIMBS_RANGE_CONSTRAINT_0",
            "P_X_LOW_LIMBS_RANGE_CONSTRAINT_1",
            "P_X_LOW_LIMBS_RANGE_CONSTRAINT_2",
            "P_X_LOW_LIMBS_RANGE_CONSTRAINT_3",
            "P_X_LOW_LIMBS_RANGE_CONSTRAINT_4",
            "P_X_LOW_LIMBS_RANGE_CONSTRAINT_TAIL",
            "P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0",
            "P_X_HIGH_LIMBS_RANGE_CONSTRAINT_1",
            "P_X_HIGH_LIMBS_RANGE_CONSTRAINT_2",
            "P_X_HIGH_LIMBS_RANGE_CONSTRAINT_3",
            "P_X_HIGH_LIMBS_RANGE_CONSTRAINT_4",
            "P_X_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL",
            "P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0",
            "P_Y_LOW_LIMBS_RANGE_CONSTRAINT_1",
            "P_Y_LOW_LIMBS_RANGE_CONSTRAINT_2",
            "P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3",
            "P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4",
            "P_Y_LOW_LIMBS_RANGE_CONSTRAINT_TAIL",
            "P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0",
            "P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_1",
            "P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_2",
            "P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_3",
            "P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_4",
            "P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL",
            "Z_LOW_LIMBS_RANGE_CONSTRAINT_0",
            "Z_LOW_LIMBS_RANGE_CONSTRAINT_1",
            "Z_LOW_LIMBS_RANGE_CONSTRAINT_2",
            "Z_LOW_LIMBS_RANGE_CONSTRAINT_3",
            "Z_LOW_LIMBS_RANGE_CONSTRAINT_4",
            "Z_LOW_LIMBS_RANGE_CONSTRAINT_TAIL",
            "Z_HIGH_LIMBS_RANGE_CONSTRAINT_0",
            "Z_HIGH_LIMBS_RANGE_CONSTRAINT_1",
            "Z_HIGH_LIMBS_RANGE_CONSTRAINT_2",
            "Z_HIGH_LIMBS_RANGE_CONSTRAINT_3",
            "Z_HIGH_LIMBS_RANGE_CONSTRAINT_4",
            "Z_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL",
            "ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0",
            "ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_1",
            "ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_2",
            "ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_3",
            "ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_4",
            "ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_TAIL",
            "ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0",
            "ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_1",
            "ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_2",
            "ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_3",
            "ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_4",
            "ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL",
            "QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0",
            "QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_1",
            "QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_2",
            "QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_3",
            "QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_4",
            "QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_TAIL",
            "QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0",
            "QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_1",
            "QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_2",
            "QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_3",
            "QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_4",
            "QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL",
            "RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0",
            "RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1",
            "RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2",
            "RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3",
        ]
    }
    pub fn wire_non_shifted_labels() -> &'static str {
        "OP"
    }
    pub fn get_ordered_range_constraints_labels() -> &'static [&'static str] {
        &[
            "ORDERED_RANGE_CONSTRAINTS_0",
            "ORDERED_RANGE_CONSTRAINTS_1",
            "ORDERED_RANGE_CONSTRAINTS_2",
            "ORDERED_RANGE_CONSTRAINTS_3",
            "ORDERED_RANGE_CONSTRAINTS_4",
        ]
    }
    // PRECOMPUTED ENTITIES:
    const ORDERED_EXTRA_RANGE_CONSTRAINTS_NUMERATOR: usize = 0; // column 0
    // The lagrange constants are already defined in the polynomial flavours
    // const LAGRANGE_FIRST: usize = 1; // column 1
    // const LAGRANGE_LAST: usize = 2; // column 2
    // TODO(https://github.com/AztecProtocol/barretenberg/issues/758): Check if one of these
    // can be replaced by shifts
    const LAGRANGE_ODD_IN_MINICIRCUIT: usize = 3; // column 3
    const LAGRANGE_EVEN_IN_MINICIRCUIT: usize = 4; // column 4
    const LAGRANGE_RESULT_ROW: usize = 5; // column 5
    const LAGRANGE_LAST_IN_MINICIRCUIT: usize = 6; // column 6
    const LAGRANGE_MASKING: usize = 7; // column 7
    const LAGRANGE_REAL_LAST: usize = 8; // column 8
    // WITNESS ENTITIES:
    const OP: usize = 0;
    // Here the shifted start:
    const X_LO_Y_HI: usize = 1;
    const X_HI_Z_1: usize = 2;
    const Y_LO_Z_2: usize = 3;
    const P_X_LOW_LIMBS: usize = 4;
    const P_X_HIGH_LIMBS: usize = 5;
    const P_Y_LOW_LIMBS: usize = 6;
    const P_Y_HIGH_LIMBS: usize = 7;
    const Z_LOW_LIMBS: usize = 8;
    const Z_HIGH_LIMBS: usize = 9;
    const ACCUMULATORS_BINARY_LIMBS_0: usize = 10;
    const ACCUMULATORS_BINARY_LIMBS_1: usize = 11;
    const ACCUMULATORS_BINARY_LIMBS_2: usize = 12;
    const ACCUMULATORS_BINARY_LIMBS_3: usize = 13;
    const QUOTIENT_LOW_BINARY_LIMBS: usize = 14;
    const QUOTIENT_HIGH_BINARY_LIMBS: usize = 15;
    const RELATION_WIDE_LIMBS: usize = 16;
    const P_X_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 17;
    const P_X_LOW_LIMBS_RANGE_CONSTRAINT_1: usize = 18;
    const P_X_LOW_LIMBS_RANGE_CONSTRAINT_2: usize = 19;
    const P_X_LOW_LIMBS_RANGE_CONSTRAINT_3: usize = 20;
    const P_X_LOW_LIMBS_RANGE_CONSTRAINT_4: usize = 21;
    const P_X_LOW_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 22;
    const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 23;
    const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_1: usize = 24;
    const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_2: usize = 25;
    const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_3: usize = 26;
    const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_4: usize = 27;
    const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 28;
    const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 29;
    const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_1: usize = 30;
    const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_2: usize = 31;
    const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3: usize = 32;
    const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4: usize = 33;
    const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 34;
    const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 35;
    const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_1: usize = 36;
    const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_2: usize = 37;
    const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_3: usize = 38;
    const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_4: usize = 39;
    const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 40;
    const Z_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 41;
    const Z_LOW_LIMBS_RANGE_CONSTRAINT_1: usize = 42;
    const Z_LOW_LIMBS_RANGE_CONSTRAINT_2: usize = 43;
    const Z_LOW_LIMBS_RANGE_CONSTRAINT_3: usize = 44;
    const Z_LOW_LIMBS_RANGE_CONSTRAINT_4: usize = 45;
    const Z_LOW_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 46;
    const Z_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 47;
    const Z_HIGH_LIMBS_RANGE_CONSTRAINT_1: usize = 48;
    const Z_HIGH_LIMBS_RANGE_CONSTRAINT_2: usize = 49;
    const Z_HIGH_LIMBS_RANGE_CONSTRAINT_3: usize = 50;
    const Z_HIGH_LIMBS_RANGE_CONSTRAINT_4: usize = 51;
    const Z_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 52;
    const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 53;
    const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_1: usize = 54;
    const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_2: usize = 55;
    const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_3: usize = 56;
    const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_4: usize = 57;
    const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 58;
    const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 59;
    const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_1: usize = 60;
    const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_2: usize = 61;
    const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_3: usize = 62;
    const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_4: usize = 63;
    const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 64;
    const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 65;
    const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_1: usize = 66;
    const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_2: usize = 67;
    const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_3: usize = 68;
    const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_4: usize = 69;
    const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 70;
    const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 71;
    const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_1: usize = 72;
    const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_2: usize = 73;
    const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_3: usize = 74;
    const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_4: usize = 75;
    const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL: usize = 76;
    const RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0: usize = 77;
    const RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1: usize = 78;
    const RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2: usize = 79;
    const RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3: usize = 80;
    const ORDERED_RANGE_CONSTRAINTS_0: usize = 81;
    const ORDERED_RANGE_CONSTRAINTS_1: usize = 82;
    const ORDERED_RANGE_CONSTRAINTS_2: usize = 83;
    const ORDERED_RANGE_CONSTRAINTS_3: usize = 84;
    const ORDERED_RANGE_CONSTRAINTS_4: usize = 85;
    const Z_PERM: usize = 86;
    //here the shifted end
    const INTERLEAVED_RANGE_CONSTRAINTS_0: usize = 87;
    const INTERLEAVED_RANGE_CONSTRAINTS_1: usize = 88;
    const INTERLEAVED_RANGE_CONSTRAINTS_2: usize = 89;
    const INTERLEAVED_RANGE_CONSTRAINTS_3: usize = 90;
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
    const PROVER_WITNESS_ENTITIES_SIZE: usize = 90; // Only z_perm is a derived witness entity
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
    const LAGRANGE_FIRST: usize = 1;
    const LAGRANGE_LAST: usize = 2;
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
        _vec: Vec<Polynomial<T>>,
    ) -> Self::ProverWitnessEntities<Polynomial<T>> {
        todo!("Implementation for prover_witness_entity_from_vec in TranslatorFlavour")
    }

    fn precomputed_entity_from_vec<T: Default + Clone + Sync + Debug>(
        _vec: Vec<Polynomial<T>>,
    ) -> Self::PrecomputedEntities<Polynomial<T>> {
        todo!("Implementation for precomputed_entity_from_vec in TranslatorFlavour")
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
    fn get_wires_mut(&mut self) -> &mut [T] {
        &mut self.elements
            [TranslatorFlavour::OP..=TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3]
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

    fn from_elements(_elements: Vec<T>) -> Self {
        unimplemented!(
            "PrecomputedEntitiesFlavour::from_elements is not implemented for TranslatorFlavour."
        );
    }
    fn lagrange_first_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_FIRST]
    }
    fn lagrange_last_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_LAST]
    }
    fn lagrange_last(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_LAST]
    }
    fn lagrange_first(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_FIRST]
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
        Self {
            elements: elements.try_into().unwrap(),
        }
    }
    fn to_be_shifted(&self) -> &[T] {
        &self.elements[TranslatorFlavour::X_LO_Y_HI..=TranslatorFlavour::Z_PERM]
    }
    fn to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[TranslatorFlavour::X_LO_Y_HI..=TranslatorFlavour::Z_PERM]
    }
    fn get_unshifted(&self) -> &[T] {
        &self.elements[TranslatorFlavour::OP..=TranslatorFlavour::Z_PERM]
    }
    fn z_perm(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_PERM]
    }
    fn get_interleaved(&self) -> Option<&[T]> {
        Some(
            &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_0
                ..=TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_3],
        )
    }
    fn get_groups_to_be_interleaved(&self) -> Option<[&[T]; 4]> {
        Some([
            &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_0
                ..=TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3],
            &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4
                ..=TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_1],
            &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_2
                ..=TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL],
            &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0
                ..=TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3],
        ])
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
        Self {
            elements: elements.try_into().unwrap(),
        }
    }
    fn z_perm(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_PERM - 1] // We do -1 because OP is not included in the shifted entities
    }
}
impl<T: Default> TranslatorPrecomputedEntities<T> {
    pub fn ordered_extra_range_constraints_numerator(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_EXTRA_RANGE_CONSTRAINTS_NUMERATOR]
    }
    pub fn ordered_extra_range_constraints_numerator_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::ORDERED_EXTRA_RANGE_CONSTRAINTS_NUMERATOR]
    }
    pub fn lagrange_odd_in_minicircuit(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_ODD_IN_MINICIRCUIT]
    }
    pub fn lagrange_odd_in_minicircuit_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_ODD_IN_MINICIRCUIT]
    }
    pub fn lagrange_even_in_minicircuit(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_EVEN_IN_MINICIRCUIT]
    }
    pub fn lagrange_even_in_minicircuit_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_EVEN_IN_MINICIRCUIT]
    }
    pub fn lagrange_result_row(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_RESULT_ROW]
    }
    pub fn lagrange_result_row_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_RESULT_ROW]
    }
    pub fn lagrange_last_in_minicircuit(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_LAST_IN_MINICIRCUIT]
    }
    pub fn lagrange_last_in_minicircuit_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_LAST_IN_MINICIRCUIT]
    }
    pub fn lagrange_masking(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_MASKING]
    }
    pub fn lagrange_masking_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_MASKING]
    }
    pub fn lagrange_real_last(&self) -> &T {
        &self.elements[TranslatorFlavour::LAGRANGE_REAL_LAST]
    }
    pub fn lagrange_real_last_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::LAGRANGE_REAL_LAST]
    }
}

impl<T: Default> TranslatorProverWitnessEntities<T> {
    pub fn into_shifted_without_z_perm(self) -> impl Iterator<Item = T> {
        self.elements
            .into_iter()
            .skip(1)
            .take(TranslatorFlavour::SHIFTED_WITNESS_ENTITIES_SIZE - 1) // Minus 1 because we don't include z_perm
    }
    pub fn to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[TranslatorFlavour::X_LO_Y_HI..TranslatorFlavour::Z_PERM]
    }
    pub fn accumulators_binary_limbs_0(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_0]
    }
    pub fn accumulators_binary_limbs_1(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_1]
    }
    pub fn accumulators_binary_limbs_2(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_2]
    }
    pub fn accumulators_binary_limbs_3(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_3]
    }
    pub fn wire_non_shifted_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::OP]
    }
    pub fn op(&self) -> &T {
        &self.elements[TranslatorFlavour::OP]
    }
    pub fn wire_to_be_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[TranslatorFlavour::X_LO_Y_HI
            ..=TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn get_ordered_range_constraints_mut(&mut self) -> &mut [T] {
        &mut self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_0
            ..=TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_4]
    }
    pub fn interleaved_range_constraints_0(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_0 - 1] // We do -1 here because we don't have z_perm here
    }
    pub fn interleaved_range_constraints_1(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_1 - 1] // We do -1 here because we don't have z_perm here
    }
    pub fn interleaved_range_constraints_2(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_2 - 1] // We do -1 here because we don't have z_perm here
    }
    pub fn interleaved_range_constraints_3(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_3 - 1] // We do -1 here because we don't have z_perm here
    }
    pub fn get_interleaved_range_constraints(&self) -> &[T] {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_0 - 1
            ..=TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_3 - 1]
    }
    pub fn get_interleaved_range_constraints_mut(&mut self) -> &mut [T] {
        &mut self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_0 - 1
            ..=TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_3 - 1]
    }
    pub fn ordered_range_constraints_0(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_0]
    }
    pub fn ordered_range_constraints_1(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_1]
    }
    pub fn ordered_range_constraints_2(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_2]
    }
    pub fn ordered_range_constraints_3(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_3]
    }
    pub fn ordered_range_constraints_4(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_4]
    }
    pub fn ordered_range_constraints_0_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_0]
    }
    pub fn ordered_range_constraints_1_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_1]
    }
    pub fn ordered_range_constraints_2_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_2]
    }
    pub fn ordered_range_constraints_3_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_3]
    }
    pub fn ordered_range_constraints_4_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_4]
    }
    pub fn get_groups_to_be_interleaved(&self) -> [&[T]; 4] {
        [
            &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_0
                ..=TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3],
            &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4
                ..=TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_1],
            &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_2
                ..=TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL],
            &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0
                ..=TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3],
        ]
    }
}
impl<T: Default> TranslatorWitnessEntities<T> {
    pub fn accumulators_binary_limbs_0(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_0]
    }
    pub fn accumulators_binary_limbs_1(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_1]
    }
    pub fn accumulators_binary_limbs_2(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_2]
    }
    pub fn accumulators_binary_limbs_3(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_3]
    }
    pub fn ordered_range_constraints_0(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_0]
    }
    pub fn ordered_range_constraints_1(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_1]
    }
    pub fn ordered_range_constraints_2(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_2]
    }
    pub fn ordered_range_constraints_3(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_3]
    }
    pub fn ordered_range_constraints_4(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_4]
    }
    pub fn interleaved_range_constraints_0(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_0]
    }
    pub fn interleaved_range_constraints_1(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_1]
    }
    pub fn interleaved_range_constraints_2(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_2]
    }
    pub fn interleaved_range_constraints_3(&self) -> &T {
        &self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_3]
    }
    pub fn get_interleaved_range_constraints_mut(&mut self) -> &mut [T] {
        &mut self.elements[TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_0
            ..=TranslatorFlavour::INTERLEAVED_RANGE_CONSTRAINTS_3]
    }
    pub fn op(&self) -> &T {
        &self.elements[TranslatorFlavour::OP]
    }
    pub fn op_mut(&mut self) -> &mut T {
        &mut self.elements[TranslatorFlavour::OP]
    }
    pub fn p_x_low_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn p_x_low_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn p_x_low_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn p_x_low_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn p_x_low_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn p_x_high_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn p_x_high_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn p_x_high_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn p_x_high_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn p_x_high_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn p_y_low_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn p_y_low_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn p_y_low_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn p_y_low_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn p_y_low_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn p_y_high_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn p_y_high_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn p_y_high_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn p_y_high_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn p_y_high_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn z_low_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn z_low_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn z_low_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn z_low_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn z_low_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn z_high_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn z_high_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn z_high_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn z_high_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn z_high_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn accumulator_low_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn accumulator_low_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn accumulator_low_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn accumulator_low_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn accumulator_low_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn accumulator_high_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn accumulator_high_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn accumulator_high_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn accumulator_high_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn accumulator_high_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn quotient_low_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn quotient_low_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn quotient_low_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn quotient_low_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn quotient_low_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn quotient_high_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn quotient_high_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn quotient_high_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn quotient_high_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn quotient_high_limbs_range_constraint_4(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_4]
    }
    pub fn relation_wide_limbs_range_constraint_0(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0]
    }
    pub fn relation_wide_limbs_range_constraint_1(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1]
    }
    pub fn relation_wide_limbs_range_constraint_2(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2]
    }
    pub fn relation_wide_limbs_range_constraint_3(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3]
    }
    pub fn p_x_low_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn p_x_high_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn p_y_low_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn p_y_high_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn z_low_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn z_high_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn accumulator_low_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn accumulator_high_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn quotient_low_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn quotient_high_limbs_range_constraint_tail(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL]
    }
    pub fn p_x_low_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS]
    }
    pub fn p_y_low_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS]
    }
    pub fn p_x_high_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS]
    }
    pub fn p_y_high_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS]
    }
    pub fn z_low_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS]
    }
    pub fn z_high_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS]
    }
    pub fn quotient_low_binary_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_BINARY_LIMBS]
    }
    pub fn quotient_high_binary_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_BINARY_LIMBS]
    }
    pub fn relation_wide_limbs(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS]
    }
    pub fn x_lo_y_hi(&self) -> &T {
        &self.elements[TranslatorFlavour::X_LO_Y_HI]
    }
    pub fn x_hi_z_1(&self) -> &T {
        &self.elements[TranslatorFlavour::X_HI_Z_1]
    }
    pub fn y_lo_z_2(&self) -> &T {
        &self.elements[TranslatorFlavour::Y_LO_Z_2]
    }
}
impl<T: Default> TranslatorShiftedWitnessEntities<T> {
    pub fn ordered_range_constraints_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_0 - 1]
    }
    pub fn ordered_range_constraints_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_1 - 1]
    }
    pub fn ordered_range_constraints_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_2 - 1]
    }
    pub fn ordered_range_constraints_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_3 - 1]
    }
    pub fn ordered_range_constraints_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ORDERED_RANGE_CONSTRAINTS_4 - 1]
    }
    pub fn z_perm_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_PERM - 1]
    }
    pub fn accumulators_binary_limbs_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_0 - 1]
    }
    pub fn accumulators_binary_limbs_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_1 - 1]
    }
    pub fn accumulators_binary_limbs_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_2 - 1]
    }
    pub fn accumulators_binary_limbs_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATORS_BINARY_LIMBS_3 - 1]
    }
    pub fn p_x_low_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS - 1]
    }
    pub fn p_y_low_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS - 1]
    }
    pub fn p_x_high_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS - 1]
    }
    pub fn p_y_high_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS - 1]
    }
    pub fn z_low_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS - 1]
    }
    pub fn z_high_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS - 1]
    }
    pub fn quotient_low_binary_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_BINARY_LIMBS - 1]
    }
    pub fn quotient_high_binary_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_BINARY_LIMBS - 1]
    }
    pub fn relation_wide_limbs_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS - 1]
    }
    pub fn p_x_low_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn p_x_low_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn p_x_low_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn p_x_low_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn p_x_low_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn p_x_high_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn p_x_high_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn p_x_high_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn p_x_high_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn p_y_low_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn p_y_low_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn p_y_low_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn p_y_low_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn p_y_low_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn p_y_high_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn p_y_high_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn p_y_high_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn p_y_high_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn z_low_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn z_low_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn z_low_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn z_low_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn z_low_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn z_high_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn z_high_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn z_high_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn z_high_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn z_high_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn accumulator_low_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn accumulator_low_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn accumulator_low_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn accumulator_low_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn accumulator_low_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn accumulator_high_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn accumulator_high_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn accumulator_high_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn accumulator_high_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn quotient_low_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn quotient_low_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn quotient_low_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn quotient_low_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn quotient_low_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn quotient_high_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn quotient_high_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn quotient_high_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn quotient_high_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn p_x_high_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn relation_wide_limbs_range_constraint_0_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0 - 1]
    }
    pub fn relation_wide_limbs_range_constraint_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1 - 1]
    }
    pub fn relation_wide_limbs_range_constraint_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2 - 1]
    }
    pub fn relation_wide_limbs_range_constraint_3_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3 - 1]
    }
    pub fn p_y_high_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn quotient_high_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn p_x_low_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_LOW_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn p_x_high_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn p_y_low_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn p_y_high_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn z_low_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_LOW_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn z_high_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Z_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn accumulator_low_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn accumulator_high_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn quotient_low_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
    pub fn quotient_high_limbs_range_constraint_4_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_4 - 1]
    }
    pub fn x_lo_y_hi_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::X_LO_Y_HI - 1]
    }
    pub fn x_hi_z_1_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::X_HI_Z_1 - 1]
    }
    pub fn y_lo_z_2_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::Y_LO_Z_2 - 1]
    }
    pub fn accumulator_high_limbs_range_constraint_tail_shift(&self) -> &T {
        &self.elements[TranslatorFlavour::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL - 1]
    }
}
