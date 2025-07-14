// use crate::{
//     polynomials::polynomial_flavours::{
//         PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour, ShiftedWitnessEntitiesFlavour,
//         WitnessEntitiesFlavour,
//     },
//     prelude::{
//         PrecomputedEntities, ProverWitnessEntities, ShiftedWitnessEntities, WitnessEntities,
//     },
//     prover_flavour::{Flavour, ProverFlavour},
// };

// #[derive(Default)]
// pub struct TranslatorFlavour {}
// impl TranslatorFlavour {
//     pub const NUM_LIMB_BITS: usize = 68;
//     pub const RESULT_ROW: usize = 2;
// }

// impl ProverFlavour for TranslatorFlavour {
//     const FLAVOUR: Flavour = Flavour::Translator;

//     type PrecomputedEntities<T: Default + Clone + std::marker::Sync> =
//         TranslatorPrecomputedEntities<T>;
//     type WitnessEntities<T: Default + std::marker::Sync> = TranslatorWitnessEntities<T>;
//     type ShiftedWitnessEntities<T: Default + std::marker::Sync> =
//         TranslatorShiftedWitnessEntities<T>;
//     type ProverWitnessEntities<T: Default + std::marker::Sync> = TranslatorProverWitnessEntities<T>;

//     const WITNESS_ENTITIES_SIZE: usize = 91;
//     const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 86;
//     const PRECOMPUTED_ENTITIES_SIZE: usize = 9;
//     const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
//     const BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;
//     const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = 9; //Translator is always ZK
//     const Q_M: usize = usize::MAX;
//     const Q_C: usize = usize::MAX;
//     const Q_L: usize = usize::MAX;
//     const Q_R: usize = usize::MAX;
//     const Q_O: usize = usize::MAX;
//     const Q_4: usize = usize::MAX;
//     const Q_BUSREAD: usize = usize::MAX;
//     const Q_LOOKUP: usize = usize::MAX;
//     const Q_ARITH: usize = usize::MAX;
//     const Q_DELTA_RANGE: usize = usize::MAX;
//     const Q_ELLIPTIC: usize = usize::MAX;
//     const Q_AUX: usize = usize::MAX;
//     const Q_POSEIDON2_EXTERNAL: usize = usize::MAX;
//     const Q_POSEIDON2_INTERNAL: usize = usize::MAX;
//     const SIGMA_1: usize = usize::MAX;
//     const SIGMA_2: usize = usize::MAX;
//     const SIGMA_3: usize = usize::MAX;
//     const SIGMA_4: usize = usize::MAX;
//     const ID_1: usize = usize::MAX;
//     const ID_2: usize = usize::MAX;
//     const ID_3: usize = usize::MAX;
//     const ID_4: usize = usize::MAX;
//     const TABLE_1: usize = usize::MAX;
//     const TABLE_2: usize = usize::MAX;
//     const TABLE_3: usize = usize::MAX;
//     const TABLE_4: usize = usize::MAX;
//     const LAGRANGE_FIRST: usize = usize::MAX;
//     const LAGRANGE_LAST: usize = usize::MAX;
//     const LAGRANGE_ECC_OP: usize = usize::MAX;
//     const DATABUS_ID: usize = usize::MAX;
//     const W_L: usize = usize::MAX;
//     const W_R: usize = usize::MAX;
//     const W_O: usize = usize::MAX;
//     const W_4: usize = usize::MAX;
//     const LOOKUP_READ_COUNTS: usize = usize::MAX;
//     const LOOKUP_READ_TAGS: usize = usize::MAX;
//     const ECC_OP_WIRE_1: usize = usize::MAX;
//     const ECC_OP_WIRE_2: usize = usize::MAX;
//     const ECC_OP_WIRE_3: usize = usize::MAX;
//     const ECC_OP_WIRE_4: usize = usize::MAX;
//     const CALLDATA: usize = usize::MAX;
//     const CALLDATA_READ_COUNTS: usize = usize::MAX;
//     const CALLDATA_READ_TAGS: usize = usize::MAX;
//     const CALLDATA_INVERSES: usize = usize::MAX;
//     const SECONDARY_CALLDATA: usize = usize::MAX;
//     const SECONDARY_CALLDATA_READ_COUNTS: usize = usize::MAX;
//     const SECONDARY_CALLDATA_READ_TAGS: usize = usize::MAX;
//     const SECONDARY_CALLDATA_INVERSES: usize = usize::MAX;
//     const RETURN_DATA: usize = usize::MAX;
//     const RETURN_DATA_READ_COUNTS: usize = usize::MAX;
//     const RETURN_DATA_READ_TAGS: usize = usize::MAX;
//     const RETURN_DATA_INVERSES: usize = usize::MAX;
//     const WITNESS_W_L: usize = usize::MAX;
//     const WITNESS_W_R: usize = usize::MAX;
//     const WITNESS_W_O: usize = usize::MAX;
//     const WITNESS_W_4: usize = usize::MAX;
//     const WITNESS_Z_PERM: usize = usize::MAX;
//     const WITNESS_LOOKUP_INVERSES: usize = usize::MAX;
//     const WITNESS_LOOKUP_READ_COUNTS: usize = usize::MAX;
//     const WITNESS_LOOKUP_READ_TAGS: usize = usize::MAX;
//     const WITNESS_ECC_OP_WIRE_1: usize = usize::MAX;
//     const WITNESS_ECC_OP_WIRE_2: usize = usize::MAX;
//     const WITNESS_ECC_OP_WIRE_3: usize = usize::MAX;
//     const WITNESS_ECC_OP_WIRE_4: usize = usize::MAX;
//     const WITNESS_CALLDATA: usize = usize::MAX;
//     const WITNESS_CALLDATA_READ_COUNTS: usize = usize::MAX;
//     const WITNESS_CALLDATA_READ_TAGS: usize = usize::MAX;
//     const WITNESS_CALLDATA_INVERSES: usize = usize::MAX;
//     const WITNESS_SECONDARY_CALLDATA: usize = usize::MAX;
//     const WITNESS_SECONDARY_CALLDATA_READ_COUNTS: usize = usize::MAX;
//     const WITNESS_SECONDARY_CALLDATA_READ_TAGS: usize = usize::MAX;
//     const WITNESS_SECONDARY_CALLDATA_INVERSES: usize = usize::MAX;
//     const WITNESS_RETURN_DATA: usize = usize::MAX;
//     const WITNESS_RETURN_DATA_READ_COUNTS: usize = usize::MAX;
//     const WITNESS_RETURN_DATA_READ_TAGS: usize = usize::MAX;
//     const WITNESS_RETURN_DATA_INVERSES: usize = usize::MAX;

//     fn prover_witness_entity_from_vec<T: Default + Sync + Clone>(
//         _vec: Vec<crate::prelude::Polynomial<T>>,
//     ) -> Self::ProverWitnessEntities<crate::prelude::Polynomial<T>> {
//         todo!()
//     }

//     fn precomputed_entity_from_vec<T: Default + Clone + Sync>(
//         _vec: Vec<crate::prelude::Polynomial<T>>,
//     ) -> Self::PrecomputedEntities<crate::prelude::Polynomial<T>> {
//         todo!()
//     }

//     type PolyG<'a, T: Default + 'a>;
// }
// pub type TranslatorPrecomputedEntities<T> =
//     PrecomputedEntities<T, { TranslatorFlavour::PRECOMPUTED_ENTITIES_SIZE }>;
// pub type TranslatorProverWitnessEntities<T> =
//     ProverWitnessEntities<T, { TranslatorFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;
// pub type TranslatorShiftedWitnessEntities<T> =
//     ShiftedWitnessEntities<T, { TranslatorFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;
// pub type TranslatorWitnessEntities<T> =
//     WitnessEntities<T, { TranslatorFlavour::WITNESS_ENTITIES_SIZE }>;

// impl<T: Default> ProverWitnessEntitiesFlavour<T> for TranslatorProverWitnessEntities<T> {
//     fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
//     where
//         T: 'a,
//     {
//         self.elements.iter()
//     }
//     fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
//     where
//         T: 'a,
//     {
//         self.elements.iter_mut()
//     }
//     fn into_iter(self) -> impl Iterator<Item = T> {
//         self.elements.into_iter()
//     }
//     fn into_wires(self) -> impl Iterator<Item = T> {
//         std::iter::empty()
//     }
// }
// impl<T: Default> PrecomputedEntitiesFlavour<T> for TranslatorPrecomputedEntities<T> {
//     fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
//     where
//         T: 'a,
//     {
//         self.elements.iter()
//     }
//     fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
//     where
//         T: 'a,
//     {
//         self.elements.iter_mut()
//     }
//     fn into_iter(self) -> impl Iterator<Item = T> {
//         self.elements.into_iter()
//     }

//     fn new() -> Self {
//         Self {
//             elements: std::array::from_fn(|_| T::default()),
//         }
//     }
// }
// impl<T: Default> WitnessEntitiesFlavour<T> for TranslatorWitnessEntities<T> {
//     fn new() -> Self {
//         Self {
//             elements: std::array::from_fn(|_| T::default()),
//         }
//     }
//     fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
//     where
//         T: 'a,
//     {
//         self.elements.iter()
//     }
//     fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
//     where
//         T: 'a,
//     {
//         self.elements.iter_mut()
//     }
//     fn into_iter(self) -> impl Iterator<Item = T> {
//         self.elements.into_iter()
//     }
// }
// impl<T: Default> ShiftedWitnessEntitiesFlavour<T> for TranslatorShiftedWitnessEntities<T> {
//     fn new() -> Self {
//         Self {
//             elements: std::array::from_fn(|_| T::default()),
//         }
//     }
//     fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
//     where
//         T: 'a,
//     {
//         self.elements.iter()
//     }
//     fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
//     where
//         T: 'a,
//     {
//         self.elements.iter_mut()
//     }
//     fn into_iter(self) -> impl Iterator<Item = T> {
//         self.elements.into_iter()
//     }
// }

// impl<T: Default> TranslatorProverWitnessEntities<T> {
//     pub fn accumulators_binary_limbs_0(&self) -> &T {
//         todo!()
//     }
//     pub fn accumulators_binary_limbs_1(&self) -> &T {
//         todo!()
//     }
//     pub fn accumulators_binary_limbs_2(&self) -> &T {
//         todo!()
//     }
//     pub fn accumulators_binary_limbs_3(&self) -> &T {
//         todo!()
//     }
// }
