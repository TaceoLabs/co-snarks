use crate::{
    polynomials::polynomial_flavours::{
        PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour, ShiftedWitnessEntitiesFlavour,
        WitnessEntitiesFlavour,
    },
    prelude::{
        PrecomputedEntities, ProverWitnessEntities, ShiftedWitnessEntities, WitnessEntities,
    },
    prover_flavour::{Flavour, ProverFlavour},
};

#[derive(Default)]
pub struct TranslatorFlavour {}
impl TranslatorFlavour {
    pub const NUM_LIMB_BITS: usize = 68;
    pub const RESULT_ROW: usize = 2;
}

impl ProverFlavour for TranslatorFlavour {
    const FLAVOUR: Flavour = Flavour::Translator;

    type PrecomputedEntities<T: Default + Clone + std::marker::Sync> =
        TranslatorPrecomputedEntities<T>;

    type WitnessEntities<T: Default + std::marker::Sync> = TranslatorWitnessEntities<T>;

    type ShiftedWitnessEntities<T: Default + std::marker::Sync> =
        TranslatorShiftedWitnessEntities<T>;

    type ProverWitnessEntities<T: Default + std::marker::Sync> = TranslatorProverWitnessEntities<T>;

    const WITNESS_ENTITIES_SIZE: usize = 91;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 86;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 9;
    const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = 9; //Translator is always ZK
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
pub type TranslatorPrecomputedEntities<T> =
    PrecomputedEntities<T, { TranslatorFlavour::PRECOMPUTED_ENTITIES_SIZE }>;
pub type TranslatorProverWitnessEntities<T> =
    ProverWitnessEntities<T, { TranslatorFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;
pub type TranslatorShiftedWitnessEntities<T> =
    ShiftedWitnessEntities<T, { TranslatorFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;
pub type TranslatorWitnessEntities<T> =
    WitnessEntities<T, { TranslatorFlavour::WITNESS_ENTITIES_SIZE }>;

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
    //TODO FLORIN panic or something else?
    fn into_wires(self) -> impl Iterator<Item = T> {
        std::iter::empty()
    }
}
impl<T: Default> PrecomputedEntitiesFlavour<T> for TranslatorPrecomputedEntities<T> {
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
impl<T: Default> WitnessEntitiesFlavour<T> for TranslatorWitnessEntities<T> {
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
impl<T: Default> ShiftedWitnessEntitiesFlavour<T> for TranslatorShiftedWitnessEntities<T> {
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
}
