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
        &[
            "TRANSCRIPT_ADD",                             // column 0
            "TRANSCRIPT_EQ",                              // column 1
            "TRANSCRIPT_MSM_TRANSITION",                  // column 2
            "TRANSCRIPT_PX",                              // column 3
            "TRANSCRIPT_PY",                              // column 4
            "TRANSCRIPT_Z1",                              // column 5
            "TRANSCRIPT_Z2",                              // column 6
            "TRANSCRIPT_Z1ZERO",                          // column 7
            "TRANSCRIPT_Z2ZERO",                          // column 8
            "TRANSCRIPT_OP",                              // column 9
            "TRANSCRIPT_MSM_X",                           // column 10
            "TRANSCRIPT_MSM_Y",                           // column 11
            "PRECOMPUTE_POINT_TRANSITION",                // column 12
            "PRECOMPUTE_S1LO",                            // column 13
            "PRECOMPUTE_S2HI",                            // column 14
            "PRECOMPUTE_S2LO",                            // column 15
            "PRECOMPUTE_S3HI",                            // column 16
            "PRECOMPUTE_S3LO",                            // column 17
            "PRECOMPUTE_S4HI",                            // column 18
            "PRECOMPUTE_S4LO",                            // column 19
            "PRECOMPUTE_SKEW",                            // column 20
            "MSM_SIZE_OF_MSM",                            // column 21
            "MSM_ADD2",                                   // column 22
            "MSM_ADD3",                                   // column 23
            "MSM_ADD4",                                   // column 24
            "MSM_X1",                                     // column 25
            "MSM_Y1",                                     // column 26
            "MSM_X2",                                     // column 27
            "MSM_Y2",                                     // column 28
            "MSM_X3",                                     // column 29
            "MSM_Y3",                                     // column 30
            "MSM_X4",                                     // column 31
            "MSM_Y4",                                     // column 32
            "MSM_COLLISION_X1",                           // column 33
            "MSM_COLLISION_X2",                           // column 34
            "MSM_COLLISION_X3",                           // column 35
            "MSM_COLLISION_X4",                           // column 36
            "MSM_LAMBDA1",                                // column 37
            "MSM_LAMBDA2",                                // column 38
            "MSM_LAMBDA3",                                // column 39
            "MSM_LAMBDA4",                                // column 40
            "MSM_SLICE1",                                 // column 41
            "MSM_SLICE2",                                 // column 42
            "MSM_SLICE3",                                 // column 43
            "MSM_SLICE4",                                 // column 44
            "TRANSCRIPT_RESET_ACCUMULATOR",               // column 45
            "LOOKUP_READ_COUNTS_0",                       // column 46
            "LOOKUP_READ_COUNTS_1",                       // column 47
            "TRANSCRIPT_BASE_INFINITY",                   // column 48
            "TRANSCRIPT_BASE_X_INVERSE",                  // column 49
            "TRANSCRIPT_BASE_Y_INVERSE",                  // column 50
            "TRANSCRIPT_ADD_X_EQUAL",                     // column 51
            "TRANSCRIPT_ADD_Y_EQUAL",                     // column 52
            "TRANSCRIPT_ADD_LAMBDA",                      // column 53
            "TRANSCRIPT_MSM_INTERMEDIATE_X",              // column 54
            "TRANSCRIPT_MSM_INTERMEDIATE_Y",              // column 55
            "TRANSCRIPT_MSM_INFINITY",                    // column 56
            "TRANSCRIPT_MSM_X_INVERSE",                   // column 57
            "TRANSCRIPT_MSM_COUNT_ZERO_AT_TRANSITION",    // column 58
            "TRANSCRIPT_MSM_COUNT_AT_TRANSITION_INVERSE", // column 59
        ]
    }

    pub fn to_be_shifted_without_accumulators_labels() -> &'static [&'static str] {
        &[
            "TRANSCRIPT_MUL",        // column 60
            "TRANSCRIPT_MSM_COUNT",  // column 61
            "PRECOMPUTE_SCALAR_SUM", // column 62
            "PRECOMPUTE_S1HI",       // column 63
            "PRECOMPUTE_DX",         // column 64
            "PRECOMPUTE_DY",         // column 65
            "PRECOMPUTE_TX",         // column 66
            "PRECOMPUTE_TY",         // column 67
            "MSM_TRANSITION",        // column 68
            "MSM_ADD",               // column 69
            "MSM_DOUBLE",            // column 70
            "MSM_SKEW",              // column 71
            "MSM_ACCUMULATOR_X",     // column 72
            "MSM_ACCUMULATOR_Y",     // column 73
            "MSM_COUNT",             // column 74
            "MSM_ROUND",             // column 75
            "MSM_ADD1",              // column 76
            "MSM_PC",                // column 77
            "PRECOMPUTE_PC",         // column 78
            "TRANSCRIPT_PC",         // column 79
            "PRECOMPUTE_ROUND",      // column 80
            "PRECOMPUTE_SELECT",     // column 81
        ]
    }
    pub fn to_be_shifted_accumulators_labels() -> &'static [&'static str] {
        &[
            "TRANSCRIPT_ACCUMULATOR_EMPTY", // column 82
            "TRANSCRIPT_ACCUMULATOR_X",     // column 83
            "TRANSCRIPT_ACCUMULATOR_Y",
        ] // column 84
    }
    //SHIFTED WITNESS ENTITIES
    const TRANSCRIPT_MUL_SHIFT: usize = 0; // column 0
    const TRANSCRIPT_MSM_COUNT_SHIFT: usize = 1; // column 1
    const PRECOMPUTE_SCALAR_SUM_SHIFT: usize = 2; // column 2
    const PRECOMPUTE_S1HI_SHIFT: usize = 3; // column 3
    const PRECOMPUTE_DX_SHIFT: usize = 4; // column 4
    const PRECOMPUTE_DY_SHIFT: usize = 5; // column 5
    const PRECOMPUTE_TX_SHIFT: usize = 6; // column 6
    const PRECOMPUTE_TY_SHIFT: usize = 7; // column 7
    const MSM_TRANSITION_SHIFT: usize = 8; // column 8
    const MSM_ADD_SHIFT: usize = 9; // column 9
    const MSM_DOUBLE_SHIFT: usize = 10; // column 10
    const MSM_SKEW_SHIFT: usize = 11; // column 11
    const MSM_ACCUMULATOR_X_SHIFT: usize = 12; // column 12
    const MSM_ACCUMULATOR_Y_SHIFT: usize = 13; // column 13
    const MSM_COUNT_SHIFT: usize = 14; // column 14
    const MSM_ROUND_SHIFT: usize = 15; // column 15
    const MSM_ADD1_SHIFT: usize = 16; // column 16
    const MSM_PC_SHIFT: usize = 17; // column 17
    const PRECOMPUTE_PC_SHIFT: usize = 18; // column 18
    const TRANSCRIPT_PC_SHIFT: usize = 19; // column 19
    const PRECOMPUTE_ROUND_SHIFT: usize = 20; // column 20
    const PRECOMPUTE_SELECT_SHIFT: usize = 21; // column 21
    const TRANSCRIPT_ACCUMULATOR_EMPTY_SHIFT: usize = 22; // column 22
    const TRANSCRIPT_ACCUMULATOR_X_SHIFT: usize = 23; // column 23
    const TRANSCRIPT_ACCUMULATOR_Y_SHIFT: usize = 24; // column 24
    const Z_PERM_SHIFT: usize = 25; // column 25

    //WITNESS ENTITIES
    const TRANSCRIPT_ADD: usize = 0; // column 0
    const TRANSCRIPT_EQ: usize = 1; // column 1
    const TRANSCRIPT_MSM_TRANSITION: usize = 2; // column 2
    const TRANSCRIPT_PX: usize = 3; // column 3
    const TRANSCRIPT_PY: usize = 4; // column 4
    const TRANSCRIPT_Z1: usize = 5; // column 5
    const TRANSCRIPT_Z2: usize = 6; // column 6
    const TRANSCRIPT_Z1ZERO: usize = 7; // column 7
    const TRANSCRIPT_Z2ZERO: usize = 8; // column 8
    const TRANSCRIPT_OP: usize = 9; // column 9
    const TRANSCRIPT_MSM_X: usize = 10; // column 10
    const TRANSCRIPT_MSM_Y: usize = 11; // column 11
    const PRECOMPUTE_POINT_TRANSITION: usize = 12; // column 12
    const PRECOMPUTE_S1LO: usize = 13; // column 13
    const PRECOMPUTE_S2HI: usize = 14; // column 14
    const PRECOMPUTE_S2LO: usize = 15; // column 15
    const PRECOMPUTE_S3HI: usize = 16; // column 16
    const PRECOMPUTE_S3LO: usize = 17; // column 17
    const PRECOMPUTE_S4HI: usize = 18; // column 18
    const PRECOMPUTE_S4LO: usize = 19; // column 19
    const PRECOMPUTE_SKEW: usize = 20; // column 20
    const MSM_SIZE_OF_MSM: usize = 21; // column 21
    const MSM_ADD2: usize = 22; // column 22
    const MSM_ADD3: usize = 23; // column 23
    const MSM_ADD4: usize = 24; // column 24
    const MSM_X1: usize = 25; // column 25
    const MSM_Y1: usize = 26; // column 26
    const MSM_X2: usize = 27; // column 27
    const MSM_Y2: usize = 28; // column 28
    const MSM_X3: usize = 29; // column 29
    const MSM_Y3: usize = 30; // column 30
    const MSM_X4: usize = 31; // column 31
    const MSM_Y4: usize = 32; // column 32
    const MSM_COLLISION_X1: usize = 33; // column 33
    const MSM_COLLISION_X2: usize = 34; // column 34
    const MSM_COLLISION_X3: usize = 35; // column 35
    const MSM_COLLISION_X4: usize = 36; // column 36
    const MSM_LAMBDA1: usize = 37; // column 37
    const MSM_LAMBDA2: usize = 38; // column 38
    const MSM_LAMBDA3: usize = 39; // column 39
    const MSM_LAMBDA4: usize = 40; // column 40
    const MSM_SLICE1: usize = 41; // column 41
    const MSM_SLICE2: usize = 42; // column 42
    const MSM_SLICE3: usize = 43; // column 43
    const MSM_SLICE4: usize = 44; // column 44
    const TRANSCRIPT_RESET_ACCUMULATOR: usize = 45; // column 45
    const LOOKUP_READ_COUNTS_0: usize = 46; // column 46
    const LOOKUP_READ_COUNTS_1: usize = 47; // column 47
    const TRANSCRIPT_BASE_INFINITY: usize = 48; // column 48
    const TRANSCRIPT_BASE_X_INVERSE: usize = 49; // column 49
    const TRANSCRIPT_BASE_Y_INVERSE: usize = 50; // column 50
    const TRANSCRIPT_ADD_X_EQUAL: usize = 51; // column 51
    const TRANSCRIPT_ADD_Y_EQUAL: usize = 52; // column 52
    const TRANSCRIPT_ADD_LAMBDA: usize = 53; // column 53
    const TRANSCRIPT_MSM_INTERMEDIATE_X: usize = 54; // column 54
    const TRANSCRIPT_MSM_INTERMEDIATE_Y: usize = 55; // column 55
    const TRANSCRIPT_MSM_INFINITY: usize = 56; // column 56
    const TRANSCRIPT_MSM_X_INVERSE: usize = 57; // column 57
    const TRANSCRIPT_MSM_COUNT_ZERO_AT_TRANSITION: usize = 58; // column 58
    const TRANSCRIPT_MSM_COUNT_AT_TRANSITION_INVERSE: usize = 59; // column 59
    const TRANSCRIPT_MUL: usize = 60; // column 60
    const TRANSCRIPT_MSM_COUNT: usize = 61; // column 61
    const PRECOMPUTE_SCALAR_SUM: usize = 62; // column 62
    const PRECOMPUTE_S1HI: usize = 63; // column 63
    const PRECOMPUTE_DX: usize = 64; // column 64
    const PRECOMPUTE_DY: usize = 65; // column 65
    const PRECOMPUTE_TX: usize = 66; // column 66
    const PRECOMPUTE_TY: usize = 67; // column 67
    const MSM_TRANSITION: usize = 68; // column 68
    const MSM_ADD: usize = 69; // column 69
    const MSM_DOUBLE: usize = 70; // column 70
    const MSM_SKEW: usize = 71; // column 71
    const MSM_ACCUMULATOR_X: usize = 72; // column 72
    const MSM_ACCUMULATOR_Y: usize = 73; // column 73
    const MSM_COUNT: usize = 74; // column 74
    const MSM_ROUND: usize = 75; // column 75
    const MSM_ADD1: usize = 76; // column 76
    const MSM_PC: usize = 77; // column 77
    const PRECOMPUTE_PC: usize = 78; // column 78
    const TRANSCRIPT_PC: usize = 79; // column 79
    const PRECOMPUTE_ROUND: usize = 80; // column 80
    const PRECOMPUTE_SELECT: usize = 81; // column 81
    const TRANSCRIPT_ACCUMULATOR_EMPTY: usize = 82; // column 82
    const TRANSCRIPT_ACCUMULATOR_X: usize = 83; // column 83
    const TRANSCRIPT_ACCUMULATOR_Y: usize = 84; // column 84
    const Z_PERM: usize = 85; // column 0
    const LOOKUP_INVERSES: usize = 86; // column 1
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
    const LAGRANGE_FIRST: usize = 0;
    const LAGRANGE_LAST: usize = 1;
    const LAGRANGE_ECC_OP: usize = 2;
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

    fn precomputed_entity_from_vec<T: Default + Clone + Sync>(
        _vec: Vec<crate::prelude::Polynomial<T>>,
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
        &self.elements[ECCVMFlavour::TRANSCRIPT_ADD
            ..ECCVMFlavour::TRANSCRIPT_MSM_COUNT_AT_TRANSITION_INVERSE + 1]
    }

    pub fn non_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_ADD
            ..ECCVMFlavour::TRANSCRIPT_MSM_COUNT_AT_TRANSITION_INVERSE + 1]
    }

    pub fn to_be_shifted_without_accumulators(&self) -> &[T] {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MUL..ECCVMFlavour::PRECOMPUTE_SELECT + 1]
    }

    pub fn to_be_shifted_without_accumulators_mut(&mut self) -> &mut [T] {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MUL..ECCVMFlavour::PRECOMPUTE_SELECT + 1]
    }

    pub fn to_be_shifted_accumulators(&self) -> &[T] {
        &self.elements
            [ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_EMPTY..ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_Y + 1]
    }

    pub fn to_be_shifted_accumulators_mut(&mut self) -> &mut [T] {
        &mut self.elements
            [ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_EMPTY..ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_Y + 1]
    }

    pub fn msm_add(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD]
    }
    pub fn msm_add_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD]
    }
    pub fn msm_skew(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SKEW]
    }
    pub fn msm_skew_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SKEW]
    }
    pub fn precompute_select(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SELECT]
    }
    pub fn precompute_select_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_SELECT]
    }
    pub fn precompute_round(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_ROUND]
    }
    pub fn precompute_pc(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_PC]
    }
    pub fn precompute_s1hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S1HI]
    }
    pub fn precompute_s1lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S1LO]
    }
    pub fn precompute_s2hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S2HI]
    }
    pub fn precompute_s2lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S2LO]
    }
    pub fn precompute_s3hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S3HI]
    }
    pub fn precompute_s3lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S3LO]
    }
    pub fn precompute_s4hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S4HI]
    }
    pub fn precompute_s4lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S4LO]
    }
    pub fn precompute_skew(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SKEW]
    }
    pub fn precompute_point_transition(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_POINT_TRANSITION]
    }
    pub fn precompute_tx(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_TX]
    }
    pub fn precompute_ty(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_TY]
    }
    pub fn precompute_scalar_sum(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SCALAR_SUM]
    }
    pub fn msm_transition_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_TRANSITION_SHIFT]
    }
    pub fn msm_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_PC_SHIFT]
    }
    pub fn msm_accumulator_x_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_X_SHIFT]
    }
    pub fn msm_accumulator_y_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_Y_SHIFT]
    }
    pub fn msm_size_of_msm(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SIZE_OF_MSM]
    }
    pub fn precompute_round_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_ROUND]
    }
    pub fn precompute_pc_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_PC]
    }
    pub fn precompute_s1hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S1HI]
    }
    pub fn precompute_s1lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S1LO]
    }
    pub fn precompute_s2hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S2HI]
    }
    pub fn precompute_s2lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S2LO]
    }
    pub fn precompute_s3hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S3HI]
    }
    pub fn precompute_s3lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S3LO]
    }
    pub fn precompute_s4hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S4HI]
    }
    pub fn precompute_s4lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S4LO]
    }
    pub fn precompute_skew_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_SKEW]
    }
    pub fn precompute_point_transition_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_POINT_TRANSITION]
    }
    pub fn precompute_tx_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_TX]
    }
    pub fn precompute_ty_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_TY]
    }
    pub fn precompute_scalar_sum_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_SCALAR_SUM]
    }
    pub fn msm_transition_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_TRANSITION_SHIFT]
    }
    pub fn msm_pc_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_PC_SHIFT]
    }
    pub fn msm_accumulator_x_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ACCUMULATOR_X_SHIFT]
    }
    pub fn msm_accumulator_y_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ACCUMULATOR_Y_SHIFT]
    }
    pub fn msm_size_of_msm_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SIZE_OF_MSM]
    }
    pub fn msm_pc(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_PC]
    }
    pub fn msm_count(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COUNT]
    }
    pub fn msm_round(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ROUND]
    }
    pub fn msm_add1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD1]
    }
    pub fn msm_slice1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE1]
    }
    pub fn msm_add2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD2]
    }
    pub fn msm_slice2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE2]
    }
    pub fn msm_add3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD3]
    }
    pub fn msm_slice3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE3]
    }
    pub fn msm_add4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD4]
    }
    pub fn msm_slice4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE4]
    }
    pub fn transcript_pc(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PC]
    }
    pub fn transcript_px(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PX]
    }
    pub fn transcript_op(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_OP]
    }
    pub fn transcript_py(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PY]
    }
    pub fn transcript_z1(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z1]
    }
    pub fn transcript_z2(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z2]
    }
    pub fn transcript_z1zero(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z1ZERO]
    }
    pub fn transcript_z2zero(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z2ZERO]
    }
    pub fn transcript_base_infinity(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_BASE_INFINITY]
    }
    pub fn transcript_mul(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MUL]
    }
    pub fn transcript_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PC_SHIFT]
    }
    pub fn transcript_msm_x(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_X]
    }
    pub fn transcript_msm_y(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_Y]
    }
    pub fn transcript_msm_transition(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_TRANSITION]
    }
    pub fn transcript_msm_count(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_COUNT]
    }
    pub fn msm_pc_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_PC]
    }
    pub fn msm_count_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_COUNT]
    }
    pub fn msm_round_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ROUND]
    }
    pub fn msm_add1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD1]
    }
    pub fn msm_slice1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE1]
    }
    pub fn msm_add2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD2]
    }
    pub fn msm_slice2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE2]
    }
    pub fn msm_add3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD3]
    }
    pub fn msm_slice3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE3]
    }
    pub fn msm_add4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD4]
    }
    pub fn msm_slice4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE4]
    }
    pub fn transcript_pc_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PC]
    }
    pub fn transcript_px_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PX]
    }
    pub fn transcript_py_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PY]
    }
    pub fn transcript_z1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z1]
    }
    pub fn transcript_z2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z2]
    }
    pub fn transcript_z1zero_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z1ZERO]
    }
    pub fn transcript_z2zero_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z2ZERO]
    }
    pub fn transcript_base_infinity_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_BASE_INFINITY]
    }
    pub fn transcript_mul_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MUL]
    }
    pub fn transcript_pc_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PC_SHIFT]
    }
    pub fn transcript_msm_x_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_X]
    }
    pub fn transcript_msm_y_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_Y]
    }
    pub fn transcript_msm_transition_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_TRANSITION]
    }
    pub fn transcript_msm_count_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_COUNT]
    }

    pub fn msm_x1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X1]
    }
    pub fn msm_x2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X2]
    }
    pub fn msm_x3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X3]
    }
    pub fn msm_x4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X4]
    }
    pub fn msm_y1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y1]
    }
    pub fn msm_y2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y2]
    }
    pub fn msm_y3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y3]
    }
    pub fn msm_y4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y4]
    }
    pub fn msm_x1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X1]
    }
    pub fn msm_x2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X2]
    }
    pub fn msm_x3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X3]
    }
    pub fn msm_x4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X4]
    }
    pub fn msm_y1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y1]
    }
    pub fn msm_y2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y2]
    }
    pub fn msm_y3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y3]
    }
    pub fn msm_y4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y4]
    }
}

impl<T: Default> ECCVMWitnessEntities<T> {
    pub fn non_shifted(&self) -> &[T] {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ADD
            ..ECCVMFlavour::TRANSCRIPT_MSM_COUNT_AT_TRANSITION_INVERSE + 1]
    }

    pub fn non_shifted_mut(&mut self) -> &mut [T] {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_ADD
            ..ECCVMFlavour::TRANSCRIPT_MSM_COUNT_AT_TRANSITION_INVERSE + 1]
    }

    pub fn to_be_shifted_without_accumulators(&self) -> &[T] {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MUL..ECCVMFlavour::PRECOMPUTE_SELECT + 1]
    }

    pub fn to_be_shifted_without_accumulators_mut(&mut self) -> &mut [T] {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MUL..ECCVMFlavour::PRECOMPUTE_SELECT + 1]
    }

    pub fn to_be_shifted_accumulators(&self) -> &[T] {
        &self.elements
            [ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_EMPTY..ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_Y + 1]
    }

    pub fn to_be_shifted_accumulators_mut(&mut self) -> &mut [T] {
        &mut self.elements
            [ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_EMPTY..ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_Y + 1]
    }

    pub fn msm_add(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD]
    }
    pub fn msm_add_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD]
    }
    pub fn msm_skew(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SKEW]
    }
    pub fn msm_skew_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SKEW]
    }
    pub fn precompute_select(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SELECT]
    }
    pub fn precompute_select_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_SELECT]
    }
    pub fn precompute_round(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_ROUND]
    }
    pub fn precompute_pc(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_PC]
    }
    pub fn precompute_s1hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S1HI]
    }
    pub fn precompute_s1lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S1LO]
    }
    pub fn precompute_s2hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S2HI]
    }
    pub fn precompute_s2lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S2LO]
    }
    pub fn precompute_s3hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S3HI]
    }
    pub fn precompute_s3lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S3LO]
    }
    pub fn precompute_s4hi(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S4HI]
    }
    pub fn precompute_s4lo(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S4LO]
    }
    pub fn precompute_skew(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SKEW]
    }
    pub fn precompute_point_transition(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_POINT_TRANSITION]
    }
    pub fn precompute_tx(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_TX]
    }
    pub fn precompute_ty(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_TY]
    }
    pub fn precompute_scalar_sum(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SCALAR_SUM]
    }
    pub fn msm_transition_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_TRANSITION_SHIFT]
    }
    pub fn msm_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_PC_SHIFT]
    }
    pub fn msm_accumulator_x_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_X_SHIFT]
    }
    pub fn msm_accumulator_y_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_Y_SHIFT]
    }
    pub fn msm_size_of_msm(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SIZE_OF_MSM]
    }
    pub fn precompute_round_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_ROUND]
    }
    pub fn precompute_pc_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_PC]
    }
    pub fn precompute_s1hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S1HI]
    }
    pub fn precompute_s1lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S1LO]
    }
    pub fn precompute_s2hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S2HI]
    }
    pub fn precompute_s2lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S2LO]
    }
    pub fn precompute_s3hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S3HI]
    }
    pub fn precompute_s3lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S3LO]
    }
    pub fn precompute_s4hi_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S4HI]
    }
    pub fn precompute_s4lo_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_S4LO]
    }
    pub fn precompute_skew_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_SKEW]
    }
    pub fn precompute_point_transition_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_POINT_TRANSITION]
    }
    pub fn precompute_tx_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_TX]
    }
    pub fn precompute_ty_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_TY]
    }
    pub fn precompute_scalar_sum_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::PRECOMPUTE_SCALAR_SUM]
    }
    pub fn msm_transition_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_TRANSITION_SHIFT]
    }
    pub fn msm_pc_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_PC_SHIFT]
    }
    pub fn msm_accumulator_x_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ACCUMULATOR_X_SHIFT]
    }
    pub fn msm_accumulator_y_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ACCUMULATOR_Y_SHIFT]
    }
    pub fn msm_size_of_msm_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SIZE_OF_MSM]
    }
    pub fn msm_pc(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_PC]
    }
    pub fn msm_count(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COUNT]
    }
    pub fn msm_round(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ROUND]
    }
    pub fn msm_add1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD1]
    }
    pub fn msm_slice1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE1]
    }
    pub fn msm_add2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD2]
    }
    pub fn msm_slice2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE2]
    }
    pub fn msm_add3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD3]
    }
    pub fn msm_slice3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE3]
    }
    pub fn msm_add4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD4]
    }
    pub fn msm_slice4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SLICE4]
    }
    pub fn transcript_pc(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PC]
    }
    pub fn transcript_px(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PX]
    }
    pub fn transcript_op(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_OP]
    }
    pub fn transcript_py(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PY]
    }
    pub fn transcript_z1(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z1]
    }
    pub fn transcript_z2(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z2]
    }
    pub fn transcript_z1zero(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z1ZERO]
    }
    pub fn transcript_z2zero(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_Z2ZERO]
    }
    pub fn transcript_base_infinity(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_BASE_INFINITY]
    }
    pub fn transcript_mul(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MUL]
    }
    pub fn transcript_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PC_SHIFT]
    }
    pub fn transcript_msm_x(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_X]
    }
    pub fn transcript_msm_y(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_Y]
    }
    pub fn transcript_msm_transition(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_TRANSITION]
    }
    pub fn transcript_msm_count(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_COUNT]
    }
    pub fn msm_pc_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_PC]
    }
    pub fn msm_count_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_COUNT]
    }
    pub fn msm_round_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ROUND]
    }
    pub fn msm_add1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD1]
    }
    pub fn msm_slice1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE1]
    }
    pub fn msm_add2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD2]
    }
    pub fn msm_slice2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE2]
    }
    pub fn msm_add3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD3]
    }
    pub fn msm_slice3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE3]
    }
    pub fn msm_add4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_ADD4]
    }
    pub fn msm_slice4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_SLICE4]
    }
    pub fn transcript_pc_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PC]
    }
    pub fn transcript_px_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PX]
    }
    pub fn transcript_py_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PY]
    }
    pub fn transcript_z1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z1]
    }
    pub fn transcript_z2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z2]
    }
    pub fn transcript_z1zero_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z1ZERO]
    }
    pub fn transcript_z2zero_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_Z2ZERO]
    }
    pub fn transcript_base_infinity_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_BASE_INFINITY]
    }
    pub fn transcript_mul_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MUL]
    }
    pub fn transcript_pc_shift_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_PC_SHIFT]
    }
    pub fn transcript_msm_x_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_X]
    }
    pub fn transcript_msm_y_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_Y]
    }
    pub fn transcript_msm_transition_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_TRANSITION]
    }
    pub fn transcript_msm_count_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::TRANSCRIPT_MSM_COUNT]
    }

    pub fn msm_x1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X1]
    }
    pub fn msm_x2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X2]
    }
    pub fn msm_x3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X3]
    }
    pub fn msm_x4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_X4]
    }
    pub fn msm_y1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y1]
    }
    pub fn msm_y2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y2]
    }
    pub fn msm_y3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y3]
    }
    pub fn msm_y4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_Y4]
    }
    pub fn msm_x1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X1]
    }
    pub fn msm_x2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X2]
    }
    pub fn msm_x3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X3]
    }
    pub fn msm_x4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_X4]
    }
    pub fn msm_y1_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y1]
    }
    pub fn msm_y2_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y2]
    }
    pub fn msm_y3_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y3]
    }
    pub fn msm_y4_mut(&mut self) -> &mut T {
        &mut self.elements[ECCVMFlavour::MSM_Y4]
    }

    pub fn transcript_msm_count_zero_at_transition(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_COUNT_ZERO_AT_TRANSITION]
    }
    pub fn transcript_add(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ADD]
    }
    pub fn transcript_eq(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_EQ]
    }
    pub fn transcript_accumulator_empty(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_EMPTY]
    }
    pub fn transcript_reset_accumulator(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_RESET_ACCUMULATOR]
    }
    pub fn transcript_msm_infinity(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_INFINITY]
    }
    pub fn transcript_add_x_equal(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ADD_X_EQUAL]
    }
    pub fn transcript_add_y_equal(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ADD_Y_EQUAL]
    }
    pub fn msm_transition(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_TRANSITION]
    }
    pub fn msm_double(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_DOUBLE]
    }
    pub fn msm_collision_x1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COLLISION_X1]
    }
    pub fn msm_collision_x2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COLLISION_X2]
    }
    pub fn msm_collision_x3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COLLISION_X3]
    }
    pub fn msm_collision_x4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COLLISION_X4]
    }
    pub fn msm_lambda1(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_LAMBDA1]
    }
    pub fn msm_lambda2(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_LAMBDA2]
    }
    pub fn msm_lambda3(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_LAMBDA3]
    }
    pub fn msm_lambda4(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_LAMBDA4]
    }
    pub fn msm_add1_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD1_SHIFT]
    }
    pub fn msm_accumulator_x(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_X]
    }
    pub fn msm_accumulator_y(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_Y]
    }
    pub fn msm_round_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ROUND_SHIFT]
    }
    pub fn msm_add_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD_SHIFT]
    }
    pub fn msm_skew_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SKEW_SHIFT]
    }
    pub fn msm_double_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_DOUBLE_SHIFT]
    }
    pub fn msm_count_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COUNT_SHIFT]
    }
    pub fn lookup_read_counts_0(&self) -> &T {
        &self.elements[ECCVMFlavour::LOOKUP_READ_COUNTS_0]
    }
    pub fn lookup_read_counts_1(&self) -> &T {
        &self.elements[ECCVMFlavour::LOOKUP_READ_COUNTS_1]
    }
}

impl<T: Default> ECCVMShiftedWitnessEntities<T> {
    pub fn z_perm_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::Z_PERM_SHIFT]
    }
    pub fn transcript_mul_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MUL_SHIFT]
    } // column 0
    pub fn transcript_msm_count_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_MSM_COUNT_SHIFT]
    } // column 1
    pub fn precompute_scalar_sum_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SCALAR_SUM_SHIFT]
    } // column 2
    pub fn precompute_s1hi_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_S1HI_SHIFT]
    } // column 3
    pub fn precompute_dx_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_DX_SHIFT]
    } // column 4
    pub fn precompute_dy_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_DY_SHIFT]
    } // column 5
    pub fn precompute_tx_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_TX_SHIFT]
    } // column 6
    pub fn precompute_ty_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_TY_SHIFT]
    } // column 7
    pub fn msm_transition_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_TRANSITION_SHIFT]
    } // column 8
    pub fn msm_add_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD_SHIFT]
    } // column 9
    pub fn msm_double_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_DOUBLE_SHIFT]
    } // column 10
    pub fn msm_skew_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_SKEW_SHIFT]
    } // column 11
    pub fn msm_accumulator_x_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_X_SHIFT]
    } // column 12
    pub fn msm_accumulator_y_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ACCUMULATOR_Y_SHIFT]
    } // column 13
    pub fn msm_count_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_COUNT_SHIFT]
    } // column 14
    pub fn msm_round_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ROUND_SHIFT]
    } // column 15
    pub fn msm_add1_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_ADD1_SHIFT]
    } // column 16
    pub fn msm_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::MSM_PC_SHIFT]
    } // column 17
    pub fn precompute_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_PC_SHIFT]
    } // column 18
    pub fn transcript_pc_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_PC_SHIFT]
    } // column 19
    pub fn precompute_round_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_ROUND_SHIFT]
    } // column 20
    pub fn precompute_select_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::PRECOMPUTE_SELECT_SHIFT]
    } // column 21
    pub fn transcript_accumulator_empty_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_EMPTY_SHIFT]
    } // column 22
    pub fn transcript_accumulator_x_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_X_SHIFT]
    } // column 23
    pub fn transcript_accumulator_y_shift(&self) -> &T {
        &self.elements[ECCVMFlavour::TRANSCRIPT_ACCUMULATOR_Y_SHIFT]
    }
}
