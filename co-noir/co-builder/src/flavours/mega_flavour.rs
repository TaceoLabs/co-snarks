use crate::{
    polynomials::polynomial_flavours::{
        PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour, ShiftedWitnessEntitiesFlavour,
        WitnessEntitiesFlavour,
    },
    prover_flavour::{Flavour, ProverFlavour},
};
#[derive(Default)]
pub struct MegaFlavour {
    // phantom_data: PhantomData<F>,
}
#[derive(Default)]
pub struct MegaProverWitnessEntities<T: Default> {
    pub elements: [T; MegaFlavour::PROVER_WITNESS_ENTITIES_SIZE],
}
#[derive(Default, Clone)]
pub struct MegaPrecomputedEntities<T: Default> {
    pub elements: [T; MegaFlavour::PRECOMPUTED_ENTITIES_SIZE],
}
#[derive(Default)]
pub struct MegaShiftedWitnessEntities<T: Default> {
    pub elements: [T; MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE],
}
#[derive(Default)]
pub struct MegaWitnessEntities<T: Default> {
    pub elements: [T; MegaFlavour::WITNESS_ENTITIES_SIZE],
}

impl ProverFlavour for MegaFlavour {
    //     type ProverWitnessEntities<T: Default>: ();
    // type ShiftedWitnessEntities<T: Default>: ();
    // type WitnessEntities<T: Default>: ();
    // type PrecomputedEntities<T: Default>: ();

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
    const Q_BUSREAD: Option<usize> = Some(7);
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
    const LAGRANGE_ECC_OP: Option<usize> = Some(28);
    /// column 29
    const DATABUS_ID: Option<usize> = Some(29);

    // Witness entities:
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
    const ECC_OP_WIRE_1: Option<usize> = Some(6);
    const ECC_OP_WIRE_2: Option<usize> = Some(7);
    const ECC_OP_WIRE_3: Option<usize> = Some(8);
    const ECC_OP_WIRE_4: Option<usize> = Some(9);
    const CALLDATA: Option<usize> = Some(10);
    const CALLDATA_READ_COUNTS: Option<usize> = Some(11);
    const CALLDATA_READ_TAGS: Option<usize> = Some(12);
    const CALLDATA_INVERSES: Option<usize> = Some(13);
    const SECONDARY_CALLDATA: Option<usize> = Some(14);
    const SECONDARY_CALLDATA_READ_COUNTS: Option<usize> = Some(15);
    const SECONDARY_CALLDATA_READ_TAGS: Option<usize> = Some(16);
    const SECONDARY_CALLDATA_INVERSES: Option<usize> = Some(17);
    const RETURN_DATA: Option<usize> = Some(18);
    const RETURN_DATA_READ_COUNTS: Option<usize> = Some(19);
    const RETURN_DATA_READ_TAGS: Option<usize> = Some(20);
    const RETURN_DATA_INVERSES: Option<usize> = Some(21);
}

impl<T: Default> IntoIterator for MegaPrecomputedEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, { MegaFlavour::PRECOMPUTED_ENTITIES_SIZE }>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> MegaPrecomputedEntities<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }
}

impl PrecomputedEntitiesFlavour for MegaFlavour {
    type PrecomputedEntity<T: Default> = MegaPrecomputedEntities<T>;

    fn new<T: Default>() -> Self::PrecomputedEntity<Vec<T>> {
        Self::PrecomputedEntity {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    fn add<T: Default>(
        lhs: &mut Self::PrecomputedEntity<Vec<T>>,
        entity: Self::PrecomputedEntity<T>,
    ) {
        for (src, dst) in entity.into_iter().zip(lhs.iter_mut()) {
            dst.push(src);
        }
    }

    fn get_table_polynomials<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &[T] {
        &poly.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    fn get_selectors_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T] {
        &mut poly.elements[Self::Q_M..=Self::Q_POSEIDON2_INTERNAL]
    }

    fn get_sigmas_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T] {
        &mut poly.elements[Self::SIGMA_1..=Self::SIGMA_4]
    }

    fn get_ids_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T] {
        &mut poly.elements[Self::ID_1..=Self::ID_4]
    }

    fn get_table_polynomials_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T] {
        &mut poly.elements[Self::TABLE_1..=Self::TABLE_4]
    }

    fn q_m<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_M]
    }

    fn q_c<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_C]
    }

    fn q_l<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_L]
    }

    fn q_r<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_R]
    }

    fn q_o<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_O]
    }

    fn q_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_4]
    }

    fn q_busread<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        if let Some(idx) = Self::Q_BUSREAD {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }

    fn q_arith<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_ARITH]
    }

    fn q_delta_range<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_DELTA_RANGE]
    }

    fn q_elliptic<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_ELLIPTIC]
    }

    fn q_aux<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_AUX]
    }

    fn q_lookup<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_LOOKUP]
    }

    fn q_poseidon2_external<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_POSEIDON2_EXTERNAL]
    }

    fn q_poseidon2_internal<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::Q_POSEIDON2_INTERNAL]
    }

    fn sigma_1<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::SIGMA_1]
    }

    fn sigma_2<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::SIGMA_2]
    }

    fn sigma_3<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::SIGMA_3]
    }

    fn sigma_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::SIGMA_4]
    }

    fn id_1<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::ID_1]
    }

    fn id_2<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::ID_2]
    }

    fn id_3<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::ID_3]
    }

    fn id_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::ID_4]
    }

    fn table_1<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::TABLE_1]
    }

    fn table_2<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::TABLE_2]
    }

    fn table_3<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::TABLE_3]
    }

    fn table_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::TABLE_4]
    }

    fn lagrange_first<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::LAGRANGE_FIRST]
    }

    fn lagrange_last<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        &poly.elements[Self::LAGRANGE_LAST]
    }

    fn lagrange_ecc_op<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        if let Some(idx) = Self::LAGRANGE_ECC_OP {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }

    fn databus_id<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T {
        if let Some(idx) = Self::DATABUS_ID {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }

    fn lagrange_first_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::LAGRANGE_FIRST]
    }

    fn lagrange_last_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::LAGRANGE_LAST]
    }

    fn lagrange_ecc_op_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        if let Some(idx) = Self::LAGRANGE_ECC_OP {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }

    fn databus_id_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        if let Some(idx) = Self::DATABUS_ID {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }

    fn q_m_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_M]
    }

    fn q_c_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_C]
    }

    fn q_l_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_L]
    }

    fn q_r_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_R]
    }

    fn q_o_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_O]
    }

    fn q_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_4]
    }

    fn q_arith_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_ARITH]
    }

    fn q_delta_range_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_DELTA_RANGE]
    }

    fn q_elliptic_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_ELLIPTIC]
    }

    fn q_aux_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_AUX]
    }

    fn q_lookup_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_LOOKUP]
    }

    fn q_poseidon2_external_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_POSEIDON2_EXTERNAL]
    }

    fn q_poseidon2_internal_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::Q_POSEIDON2_INTERNAL]
    }

    fn table_1_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::TABLE_1]
    }

    fn table_2_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::TABLE_2]
    }

    fn table_3_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::TABLE_3]
    }

    fn table_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::TABLE_4]
    }

    fn sigma_1_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::SIGMA_1]
    }

    fn sigma_2_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::SIGMA_2]
    }

    fn sigma_3_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::SIGMA_3]
    }

    fn sigma_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::SIGMA_4]
    }

    fn id_1_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::ID_1]
    }

    fn id_2_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::ID_2]
    }

    fn id_3_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::ID_3]
    }

    fn id_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T {
        &mut poly.elements[Self::ID_4]
    }
}

impl<T: Default> IntoIterator for MegaProverWitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, { MegaFlavour::PROVER_WITNESS_ENTITIES_SIZE }>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> MegaProverWitnessEntities<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }
}

impl ProverWitnessEntitiesFlavour for MegaFlavour {
    type ProverWitnessEntity<T: Default> = MegaProverWitnessEntities<T>;

    fn new<T: Default>() -> Self::ProverWitnessEntity<Vec<T>> {
        Self::ProverWitnessEntity {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    fn add<T: Default>(
        lhs: &mut Self::ProverWitnessEntity<Vec<T>>,
        entity: Self::ProverWitnessEntity<T>,
    ) {
        for (src, dst) in entity.into_iter().zip(lhs.iter_mut()) {
            dst.push(src);
        }
    }

    fn into_wires<T: Default>(poly: Self::ProverWitnessEntity<T>) -> impl Iterator<Item = T> {
        poly.elements.into_iter().take(Self::W_4 + 1 - Self::W_L)
    }

    fn get_wires<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &[T] {
        &poly.elements[Self::W_L..=Self::W_4]
    }

    fn get_wires_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut [T] {
        &mut poly.elements[Self::W_L..=Self::W_4]
    }

    fn w_l<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_L]
    }

    fn w_l_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_L]
    }

    fn w_r<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_R]
    }

    fn w_r_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_R]
    }

    fn w_o<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_O]
    }

    fn w_o_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_O]
    }

    fn w_4<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_4]
    }

    fn lookup_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        &poly.elements[Self::LOOKUP_READ_COUNTS]
    }

    fn lookup_read_counts_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::LOOKUP_READ_COUNTS]
    }

    fn lookup_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        &poly.elements[Self::LOOKUP_READ_TAGS]
    }

    fn lookup_read_tags_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::LOOKUP_READ_TAGS]
    }

    fn lookup_read_counts_and_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &[T] {
        &poly.elements[Self::LOOKUP_READ_COUNTS..Self::LOOKUP_READ_TAGS + 1]
    }
    fn lookup_read_counts_and_tags_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut [T] {
        &mut poly.elements[Self::LOOKUP_READ_COUNTS..Self::LOOKUP_READ_TAGS + 1]
    }
    fn calldata<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_1<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_1 {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_1_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_1 {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_2<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_2 {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_2_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_2 {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_3<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_3 {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_3_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_3 {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_4<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_4 {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_4_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_4 {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA_READ_COUNTS {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_counts_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA_READ_COUNTS {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA_READ_TAGS {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_tags_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA_READ_TAGS {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_inverses<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA_INVERSES {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_inverses_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA_INVERSES {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_COUNTS {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_counts_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_COUNTS {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_TAGS {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_tags_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_TAGS {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_inverses<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_INVERSES {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_inverses_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_INVERSES {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA_READ_COUNTS {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_counts_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA_READ_COUNTS {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA_READ_TAGS {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_tags_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA_READ_TAGS {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_inverses<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA_INVERSES {
            &poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_inverses_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA_INVERSES {
            &mut poly.elements[idx]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
}

impl<T: Default> IntoIterator for MegaWitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, { MegaFlavour::WITNESS_ENTITIES_SIZE }>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> MegaWitnessEntities<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }
}

impl WitnessEntitiesFlavour for MegaFlavour {
    type WitnessEntity<T: Default> = MegaWitnessEntities<T>;

    fn new<T: Default>() -> Self::WitnessEntity<Vec<T>> {
        Self::WitnessEntity {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    fn add<T: Default>(lhs: &mut Self::WitnessEntity<Vec<T>>, entity: Self::WitnessEntity<T>) {
        for (src, dst) in entity.into_iter().zip(lhs.iter_mut()) {
            dst.push(src);
        }
    }

    fn to_be_shifted<T: Default>(poly: &Self::WitnessEntity<T>) -> &[T] {
        // &poly.elements[Self::W_L..=Self::Z_PERM]
        todo!("implement witness entities")
    }

    fn to_be_shifted_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut [T] {
        // &mut poly.elements[Self::W_L..=Self::Z_PERM]
        todo!("implement witness entities")
    }

    fn w_l<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        &poly.elements[Self::W_L]
    }

    fn w_r<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        &poly.elements[Self::W_R]
    }

    fn w_o<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        &poly.elements[Self::W_O]
    }

    fn w_4<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        &poly.elements[Self::W_4]
    }

    fn z_perm<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        // &poly.elements[Self::Z_PERM]
        todo!("implement witness entities")
    }

    fn lookup_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        // &poly.elements[Self::LOOKUP_INVERSES]
        todo!("implement witness entities")
    }

    fn lookup_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        &poly.elements[Self::LOOKUP_READ_COUNTS]
    }

    fn lookup_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        &poly.elements[Self::LOOKUP_READ_TAGS]
    }

    fn w_l_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_L]
    }

    fn w_r_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_R]
    }

    fn w_o_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_O]
    }

    fn w_4_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_4]
    }

    fn z_perm_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        // &mut poly.elements[Self::Z_PERM]
        todo!("implement witness entities")
    }

    fn lookup_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        // &mut poly.elements[Self::LOOKUP_INVERSES]
        todo!("implement witness entities")
    }

    fn lookup_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::LOOKUP_READ_COUNTS]
    }

    fn lookup_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::LOOKUP_READ_TAGS]
    }

    // We do +2 here because in this case we also consider z_perm and lookup_inverses
    fn calldata<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_1<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_1 {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_1_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_1 {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_2<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_2 {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_2_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_2 {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_3<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_3 {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_3_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_3 {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_4<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::ECC_OP_WIRE_4 {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn ecc_op_wire_4_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::ECC_OP_WIRE_4 {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA_READ_COUNTS {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA_READ_COUNTS {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA_READ_TAGS {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA_READ_TAGS {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::CALLDATA_INVERSES {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn calldata_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::CALLDATA_INVERSES {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_COUNTS {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_COUNTS {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_TAGS {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_READ_TAGS {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_INVERSES {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn secondary_calldata_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::SECONDARY_CALLDATA_INVERSES {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA_READ_COUNTS {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA_READ_COUNTS {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA_READ_TAGS {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA_READ_TAGS {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T {
        if let Some(idx) = Self::RETURN_DATA_INVERSES {
            &poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
    fn return_data_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T {
        if let Some(idx) = Self::RETURN_DATA_INVERSES {
            &mut poly.elements[idx + 2]
        } else {
            panic!("This should not be called with the UltraFlavor");
        }
    }
}

impl<T: Default> IntoIterator for MegaShiftedWitnessEntities<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, { MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE }>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<T: Default> MegaShiftedWitnessEntities<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }
}

impl ShiftedWitnessEntitiesFlavour for MegaFlavour {
    type ShiftedWitnessEntity<T: Default> = MegaShiftedWitnessEntities<T>;

    fn new<T: Default>() -> Self::ShiftedWitnessEntity<Vec<T>> {
        Self::ShiftedWitnessEntity {
            elements: std::array::from_fn(|_| Vec::new()),
        }
    }

    fn add<T: Default>(
        lhs: &mut Self::ShiftedWitnessEntity<Vec<T>>,
        entity: Self::ShiftedWitnessEntity<T>,
    ) {
        for (src, dst) in entity.into_iter().zip(lhs.iter_mut()) {
            dst.push(src);
        }
    }
    fn w_l<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_L]
    }

    fn w_r<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_R]
    }

    fn w_o<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_O]
    }

    fn w_4<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T {
        &poly.elements[Self::W_4]
    }

    fn z_perm<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T {
        // &poly.elements[Self::Z_PERM]
        todo!("implement shifted witness entities")
    }

    fn w_l_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_L]
    }

    fn w_r_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_R]
    }

    fn w_o_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_O]
    }

    fn w_4_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T {
        &mut poly.elements[Self::W_4]
    }

    fn z_perm_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T {
        // &mut poly.elements[Self::Z_PERM]
        todo!("implement shifted witness entities")
    }
}
