use super::polynomial::Polynomial;
use crate::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use crate::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use crate::prover_flavour::ProverFlavour;
use ark_ff::PrimeField;
// use serde::{Deserialize, Serialize};

// This is what we get from the proving key, we shift at a later point
#[derive(Default)]
pub struct Polynomials<F: PrimeField, L: ProverFlavour> {
    pub witness: L::ProverWitnessEntities<Polynomial<F>>,
    pub precomputed: L::PrecomputedEntities<Polynomial<F>>,
}

impl<F: PrimeField, L: ProverFlavour> Polynomials<F, L> {
    pub fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Polynomial<F>> {
        self.witness.iter_mut().chain(self.precomputed.iter_mut())
    }
}

pub struct ProverWitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

#[derive(Clone)]
pub struct PrecomputedEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

pub struct WitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}
pub struct ShiftedWitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

impl<T: Default, const SIZE: usize> Default for ProverWitnessEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default, const SIZE: usize> Default for PrecomputedEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default, const SIZE: usize> Default for WitnessEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default, const SIZE: usize> Default for ShiftedWitnessEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}

impl<T: Default, const SIZE: usize> PrecomputedEntities<T, SIZE> {}

// pub trait PrecomputedEntities<T: Default> {
// const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
// #[derive(Default, Clone)]
// pub struct ShiftedWitnessEntities<T: Default> {
//     pub(crate) elements: [T; SHIFTED_WITNESS_ENTITIES_SIZE],
// }

// impl<T: Default> PrecomputedEntities<Vec<T>> {
//     pub fn new() -> Self {
//         Self {
//             elements: std::array::from_fn(|_| Vec::new()),
//         }
//     }

//     pub fn add(&mut self, precomputed_entities: PrecomputedEntities<T>) {
//         for (src, dst) in precomputed_entities.into_iter().zip(self.iter_mut()) {
//             dst.push(src);
//         }
//     }
// }

// impl<T: Default, const SIZE: usize> IntoIterator for PrecomputedEntities<T, SIZE> {
//     type Item = T;
//     type IntoIter = std::array::IntoIter<T, SIZE>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.elements.into_iter()
//     }
// }
// impl<T: Default, const SIZE: usize> IntoIterator for ProverWitnessEntities<T, SIZE> {
//     type Item = T;
//     type IntoIter = std::array::IntoIter<T, SIZE>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.elements.into_iter()
//     }
// }
// impl<T: Default, const SIZE: usize> IntoIterator for WitnessEntities<T, SIZE> {
//     type Item = T;
//     type IntoIter = std::array::IntoIter<T, SIZE>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.elements.into_iter()
//     }
// }
// impl<T: Default, const SIZE: usize> IntoIterator for ShiftedWitnessEntities<T, SIZE> {
//     type Item = T;
//     type IntoIter = std::array::IntoIter<T, SIZE>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.elements.into_iter()
//     }
// }
// impl<T: Default, const SIZE: usize> PrecomputedEntities<T, SIZE> {
//     pub fn iter(&self) -> impl Iterator<Item = &T> {
//         self.elements.iter()
//     }

//     pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
//         self.elements.iter_mut()
//     }
// }
// impl<T: Default, const SIZE: usize> ProverWitnessEntities<T, SIZE> {
//     pub fn iter(&self) -> impl Iterator<Item = &T> {
//         self.elements.iter()
//     }

//     pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
//         self.elements.iter_mut()
//     }
// }
// impl<T: Default, const SIZE: usize> WitnessEntities<T, SIZE> {
//     pub fn iter(&self) -> impl Iterator<Item = &T> {
//         self.elements.iter()
//     }

//     pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
//         self.elements.iter_mut()
//     }
// }
// impl<T: Default, const SIZE: usize> ShiftedWitnessEntities<T, SIZE> {
//     pub fn iter(&self) -> impl Iterator<Item = &T> {
//         self.elements.iter()
//     }

//     pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
//         self.elements.iter_mut()
//     }
// }

// impl<T: Default> IntoIterator for ProverWitnessEntities<T> {
//     type Item = T;
//     type IntoIter = std::array::IntoIter<T, { DUMMY_SIZE_FLORIN_PROVER_WITNESS }>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.elements.into_iter()
//     }
// }

// impl<T: Default> ProverWitnessEntities<T> {
//     /// column 0
//     // pub(crate) const W_L: usize = 0;
//     /// column 1
//     pub const W_R: usize = 1; // TODO FLORIN: REMOVE LATER
//     /// column 2
//     // pub(crate) const W_O: usize = 2;
//     /// column 3 (modified by prover)
//     pub(crate) const W_4: usize = 3; // TODO FLORIN: REMOVE LATER
//     /// column 6
//     // const LOOKUP_READ_COUNTS: usize = 4;
//     /// column 7
//     const LOOKUP_READ_TAGS: usize = 5; // TODO FLORIN: REMOVE LATER

//     // const Z_PERM: usize = 4; // column 4 (computed by prover)
//     // const LOOKUP_INVERSES: usize = 5; // column 5 (computed by prover);

//     pub fn iter(&self) -> impl Iterator<Item = &T> {
//         self.elements.iter()
//     }

//     pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
//         self.elements.iter_mut()
//     }

//     pub fn into_wires(self) -> impl Iterator<Item = T> {
//         self.elements
//             .into_iter()
//             // .skip(Self::W_L)
//             .take(Self::W_4 + 1 - L::W_L)
//     }

//     pub fn get_wires(&self) -> &[T] {
//         &self.elements[L::W_L..=L::W_4]
//     }

//     pub fn get_wires_mut(&mut self) -> &mut [T] {
//         &mut self.elements[L::W_L..=L::W_4]
//     }

//     pub fn w_l(&self) -> &T {
//         &self.elements[L::W_L]
//     }

//     pub fn w_l_mut(&mut self) -> &mut T {
//         &mut self.elements[L::W_L]
//     }

//     pub fn w_r(&self) -> &T {
//         &self.elements[L::W_R]
//     }

//     pub fn w_r_mut(&mut self) -> &mut T {
//         &mut self.elements[L::W_R]
//     }

//     pub fn w_o(&self) -> &T {
//         &self.elements[L::W_O]
//     }

//     pub fn w_o_mut(&mut self) -> &mut T {
//         &mut self.elements[L::W_O]
//     }

//     pub fn w_4(&self) -> &T {
//         &self.elements[L::W_4]
//     }

//     pub fn lookup_read_counts(&self) -> &T {
//         &self.elements[L::LOOKUP_READ_COUNTS]
//     }

//     pub fn lookup_read_counts_mut(&mut self) -> &mut T {
//         &mut self.elements[L::LOOKUP_READ_COUNTS]
//     }

//     pub fn lookup_read_tags(&self) -> &T {
//         &self.elements[L::LOOKUP_READ_TAGS]
//     }

//     pub fn lookup_read_tags_mut(&mut self) -> &mut T {
//         &mut self.elements[L::LOOKUP_READ_TAGS]
//     }

//     pub fn lookup_read_counts_and_tags(&self) -> &[T] {
//         &self.elements[L::LOOKUP_READ_COUNTS..Self::LOOKUP_READ_TAGS + 1]
//     }
//     pub fn lookup_read_counts_and_tags_mut(&mut self) -> &mut [T] {
//         &mut self.elements[L::LOOKUP_READ_COUNTS..Self::LOOKUP_READ_TAGS + 1]
//     }
//     pub fn calldata(&self) -> &T {
//         if let Some(idx) = L::CALLDATA {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::CALLDATA {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata(&self) -> &T {
//         if let Some(idx) = L::SECONDARY_CALLDATA {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::SECONDARY_CALLDATA {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data(&self) -> &T {
//         if let Some(idx) = L::RETURN_DATA {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::RETURN_DATA {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_1(&self) -> &T {
//         if let Some(idx) = L::ECC_OP_WIRE_1 {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_1_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::ECC_OP_WIRE_1 {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_2(&self) -> &T {
//         if let Some(idx) = L::ECC_OP_WIRE_2 {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_2_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::ECC_OP_WIRE_2 {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_3(&self) -> &T {
//         if let Some(idx) = L::ECC_OP_WIRE_3 {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_3_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::ECC_OP_WIRE_3 {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_4(&self) -> &T {
//         if let Some(idx) = L::ECC_OP_WIRE_4 {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn ecc_op_wire_4_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::ECC_OP_WIRE_4 {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_read_counts(&self) -> &T {
//         if let Some(idx) = L::CALLDATA_READ_COUNTS {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_read_counts_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::CALLDATA_READ_COUNTS {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_read_tags(&self) -> &T {
//         if let Some(idx) = L::CALLDATA_READ_TAGS {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_read_tags_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::CALLDATA_READ_TAGS {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_inverses(&self) -> &T {
//         if let Some(idx) = L::CALLDATA_INVERSES {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn calldata_inverses_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::CALLDATA_INVERSES {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_read_counts(&self) -> &T {
//         if let Some(idx) = L::SECONDARY_CALLDATA_READ_COUNTS {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::SECONDARY_CALLDATA_READ_COUNTS {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_read_tags(&self) -> &T {
//         if let Some(idx) = L::SECONDARY_CALLDATA_READ_TAGS {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::SECONDARY_CALLDATA_READ_TAGS {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_inverses(&self) -> &T {
//         if let Some(idx) = L::SECONDARY_CALLDATA_INVERSES {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::SECONDARY_CALLDATA_INVERSES {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_read_counts(&self) -> &T {
//         if let Some(idx) = L::RETURN_DATA_READ_COUNTS {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_read_counts_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::RETURN_DATA_READ_COUNTS {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_read_tags(&self) -> &T {
//         if let Some(idx) = L::RETURN_DATA_READ_TAGS {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_read_tags_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::RETURN_DATA_READ_TAGS {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_inverses(&self) -> &T {
//         if let Some(idx) = L::RETURN_DATA_INVERSES {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
//     pub fn return_data_inverses_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::RETURN_DATA_INVERSES {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }
// }

// impl<T: Default> PrecomputedEntities<T> {
//     // /// column 0
//     // pub(crate) const Q_M: usize = 0;
//     // /// column 1
//     // pub(crate) const Q_C: usize = 1;
//     // /// column 2
//     // pub(crate) const Q_L: usize = 2;
//     // /// column 3
//     // pub(crate) const Q_R: usize = 3;
//     // /// column 4
//     // pub(crate) const Q_O: usize = 4;
//     // /// column 5
//     // pub(crate) const Q_4: usize = 5;
//     // /// column 6
//     // pub(crate) const Q_LOOKUP: usize = 6;
//     // /// column 7
//     // pub(crate) const Q_ARITH: usize = 7;
//     // /// column 8
//     // pub(crate) const Q_DELTA_RANGE: usize = 8;
//     // /// column 9
//     // pub(crate) const Q_ELLIPTIC: usize = 9;
//     // /// column 10
//     // pub(crate) const Q_AUX: usize = 10;
//     // /// column 11
//     // pub(crate) const Q_POSEIDON2_EXTERNAL: usize = 11;
//     // /// column 12
//     // pub(crate) const Q_POSEIDON2_INTERNAL: usize = 12;
//     // /// column 13
//     // const SIGMA_1: usize = 13;
//     // /// column 14
//     // const SIGMA_2: usize = 14;
//     // /// column 15
//     // const SIGMA_3: usize = 15;
//     // /// column 16
//     // const SIGMA_4: usize = 16;
//     // /// column 17
//     // const ID_1: usize = 17;
//     // /// column 18
//     // const ID_2: usize = 18;
//     // /// column 19
//     // const ID_3: usize = 19;
//     // /// column 20
//     // const ID_4: usize = 20;
//     // /// column 21
//     // const TABLE_1: usize = 21;
//     // /// column 22
//     // const TABLE_2: usize = 22;
//     // /// column 23
//     // const TABLE_3: usize = 23;
//     // /// column 24
//     // const TABLE_4: usize = 24;
//     // /// column 25
//     // const LAGRANGE_FIRST: usize = 25;
//     // /// column 26
//     // const LAGRANGE_LAST: usize = 26;

//     pub fn iter(&self) -> impl Iterator<Item = &T> {
//         self.elements.iter()
//     }

//     pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
//         self.elements.iter_mut()
//     }

//     pub fn get_table_polynomials(&self) -> &[T] {
//         &self.elements[L::TABLE_1..=L::TABLE_4]
//     }

//     pub fn get_selectors_mut(&mut self) -> &mut [T] {
//         &mut self.elements[L::Q_M..=L::Q_POSEIDON2_INTERNAL]
//     }

//     pub fn get_sigmas_mut(&mut self) -> &mut [T] {
//         &mut self.elements[L::SIGMA_1..=L::SIGMA_4]
//     }

//     pub fn get_ids_mut(&mut self) -> &mut [T] {
//         &mut self.elements[L::ID_1..=L::ID_4]
//     }

//     pub fn get_table_polynomials_mut(&mut self) -> &mut [T] {
//         &mut self.elements[L::TABLE_1..=L::TABLE_4]
//     }

//     pub fn q_m(&self) -> &T {
//         &self.elements[L::Q_M]
//     }

//     pub fn q_c(&self) -> &T {
//         &self.elements[L::Q_C]
//     }

//     pub fn q_l(&self) -> &T {
//         &self.elements[L::Q_L]
//     }

//     pub fn q_r(&self) -> &T {
//         &self.elements[L::Q_R]
//     }

//     pub fn q_o(&self) -> &T {
//         &self.elements[L::Q_O]
//     }

//     pub fn q_4(&self) -> &T {
//         &self.elements[L::Q_4]
//     }

//     pub fn q_busread(&self) -> &T {
//         if let Some(idx) = L::Q_BUSREAD {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }

//     pub fn q_arith(&self) -> &T {
//         &self.elements[L::Q_ARITH]
//     }

//     pub fn q_delta_range(&self) -> &T {
//         &self.elements[L::Q_DELTA_RANGE]
//     }

//     pub fn q_elliptic(&self) -> &T {
//         &self.elements[L::Q_ELLIPTIC]
//     }

//     pub fn q_aux(&self) -> &T {
//         &self.elements[L::Q_AUX]
//     }

//     pub fn q_lookup(&self) -> &T {
//         &self.elements[L::Q_LOOKUP]
//     }

//     pub fn q_poseidon2_external(&self) -> &T {
//         &self.elements[L::Q_POSEIDON2_EXTERNAL]
//     }

//     pub fn q_poseidon2_internal(&self) -> &T {
//         &self.elements[L::Q_POSEIDON2_INTERNAL]
//     }

//     pub fn sigma_1(&self) -> &T {
//         &self.elements[L::SIGMA_1]
//     }

//     pub fn sigma_2(&self) -> &T {
//         &self.elements[L::SIGMA_2]
//     }

//     pub fn sigma_3(&self) -> &T {
//         &self.elements[L::SIGMA_3]
//     }

//     pub fn sigma_4(&self) -> &T {
//         &self.elements[L::SIGMA_4]
//     }

//     pub fn id_1(&self) -> &T {
//         &self.elements[L::ID_1]
//     }

//     pub fn id_2(&self) -> &T {
//         &self.elements[L::ID_2]
//     }

//     pub fn id_3(&self) -> &T {
//         &self.elements[L::ID_3]
//     }

//     pub fn id_4(&self) -> &T {
//         &self.elements[L::ID_4]
//     }

//     pub fn table_1(&self) -> &T {
//         &self.elements[L::TABLE_1]
//     }

//     pub fn table_2(&self) -> &T {
//         &self.elements[L::TABLE_2]
//     }

//     pub fn table_3(&self) -> &T {
//         &self.elements[L::TABLE_3]
//     }

//     pub fn table_4(&self) -> &T {
//         &self.elements[L::TABLE_4]
//     }

//     pub fn lagrange_first(&self) -> &T {
//         &self.elements[L::LAGRANGE_FIRST]
//     }

//     pub fn lagrange_last(&self) -> &T {
//         &self.elements[L::LAGRANGE_LAST]
//     }

//     pub fn lagrange_ecc_op(&self) -> &T {
//         if let Some(idx) = L::LAGRANGE_ECC_OP {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }

//     pub fn databus_id(&self) -> &T {
//         if let Some(idx) = L::DATABUS_ID {
//             &self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }

//     pub fn lagrange_first_mut(&mut self) -> &mut T {
//         &mut self.elements[L::LAGRANGE_FIRST]
//     }

//     pub fn lagrange_last_mut(&mut self) -> &mut T {
//         &mut self.elements[L::LAGRANGE_LAST]
//     }

//     pub fn lagrange_ecc_op_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::LAGRANGE_ECC_OP {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }

//     pub fn databus_id_mut(&mut self) -> &mut T {
//         if let Some(idx) = L::DATABUS_ID {
//             &mut self.elements[idx]
//         } else {
//             panic!("This should not be called with the UltraFlavor");
//         }
//     }

//     pub fn q_m_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_M]
//     }

//     pub fn q_c_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_C]
//     }

//     pub fn q_l_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_L]
//     }

//     pub fn q_r_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_R]
//     }

//     pub fn q_o_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_O]
//     }

//     pub fn q_4_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_4]
//     }

//     pub fn q_arith_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_ARITH]
//     }

//     pub fn q_delta_range_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_DELTA_RANGE]
//     }

//     pub fn q_elliptic_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_ELLIPTIC]
//     }

//     pub fn q_aux_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_AUX]
//     }

//     pub fn q_lookup_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_LOOKUP]
//     }

//     pub fn q_poseidon2_external_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_POSEIDON2_EXTERNAL]
//     }

//     pub fn q_poseidon2_internal_mut(&mut self) -> &mut T {
//         &mut self.elements[L::Q_POSEIDON2_INTERNAL]
//     }

//     pub fn table_1_mut(&mut self) -> &mut T {
//         &mut self.elements[L::TABLE_1]
//     }

//     pub fn table_2_mut(&mut self) -> &mut T {
//         &mut self.elements[L::TABLE_2]
//     }

//     pub fn table_3_mut(&mut self) -> &mut T {
//         &mut self.elements[L::TABLE_3]
//     }

//     pub fn table_4_mut(&mut self) -> &mut T {
//         &mut self.elements[L::TABLE_4]
//     }

//     pub fn sigma_1_mut(&mut self) -> &mut T {
//         &mut self.elements[L::SIGMA_1]
//     }

//     pub fn sigma_2_mut(&mut self) -> &mut T {
//         &mut self.elements[L::SIGMA_2]
//     }

//     pub fn sigma_3_mut(&mut self) -> &mut T {
//         &mut self.elements[L::SIGMA_3]
//     }

//     pub fn sigma_4_mut(&mut self) -> &mut T {
//         &mut self.elements[L::SIGMA_4]
//     }

//     pub fn id_1_mut(&mut self) -> &mut T {
//         &mut self.elements[L::ID_1]
//     }

//     pub fn id_2_mut(&mut self) -> &mut T {
//         &mut self.elements[L::ID_2]
//     }

//     pub fn id_3_mut(&mut self) -> &mut T {
//         &mut self.elements[L::ID_3]
//     }

//     pub fn id_4_mut(&mut self) -> &mut T {
//         &mut self.elements[L::ID_4]
//     }
// }
