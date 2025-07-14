use crate::{
    polynomials::polynomial_flavours::{
        PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour, ShiftedWitnessEntitiesFlavour,
        WitnessEntitiesFlavour,
    },
    prelude::Polynomial,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    Ultra,
    Mega,
    ECCVM,
    Translator,
}

pub trait ProverFlavour: Default {
    const FLAVOUR: Flavour;
    type PrecomputedEntities<T: Default + Clone + std::marker::Sync>: PrecomputedEntitiesFlavour<T>
        + Default
        + Clone
        + std::marker::Sync;
    type WitnessEntities<T: Default + std::marker::Sync>: WitnessEntitiesFlavour<T>
        + Default
        + std::marker::Sync;
    type ShiftedWitnessEntities<T: Default + std::marker::Sync>: ShiftedWitnessEntitiesFlavour<T>
        + Default
        + std::marker::Sync;
    type ProverWitnessEntities<T: Default + std::marker::Sync>: ProverWitnessEntitiesFlavour<T>
        + Default
        + std::marker::Sync;
    const WITNESS_ENTITIES_SIZE: usize;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize;
    const PRECOMPUTED_ENTITIES_SIZE: usize;
    const PROVER_WITNESS_ENTITIES_SIZE: usize = Self::WITNESS_ENTITIES_SIZE - 2;
    const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
        + Self::PRECOMPUTED_ENTITIES_SIZE
        + Self::SHIFTED_WITNESS_ENTITIES_SIZE;
    //  The "partial length" of a relation is 1 + the degree of the relation
    const MAX_PARTIAL_RELATION_LENGTH: usize;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize;

    //Precomputed Entities:
    const Q_M: usize;
    const Q_C: usize;
    const Q_L: usize;
    const Q_R: usize;
    const Q_O: usize;
    const Q_4: usize;
    const Q_BUSREAD: usize;
    const Q_LOOKUP: usize;
    const Q_ARITH: usize;
    const Q_DELTA_RANGE: usize;
    const Q_ELLIPTIC: usize;
    const Q_AUX: usize;
    const Q_POSEIDON2_EXTERNAL: usize;
    const Q_POSEIDON2_INTERNAL: usize;
    const SIGMA_1: usize;
    const SIGMA_2: usize;
    const SIGMA_3: usize;
    const SIGMA_4: usize;
    const ID_1: usize;
    const ID_2: usize;
    const ID_3: usize;
    const ID_4: usize;
    const TABLE_1: usize;
    const TABLE_2: usize;
    const TABLE_3: usize;
    const TABLE_4: usize;
    const LAGRANGE_FIRST: usize;
    const LAGRANGE_LAST: usize;
    const LAGRANGE_ECC_OP: usize;
    const DATABUS_ID: usize;

    // Prover Witness entities:
    const W_L: usize;
    const W_R: usize;
    const W_O: usize;
    const W_4: usize;
    // const Z_PERM: usize;
    // const LOOKUP_INVERSES: usize;
    const LOOKUP_READ_COUNTS: usize;
    const LOOKUP_READ_TAGS: usize;
    const ECC_OP_WIRE_1: usize;
    const ECC_OP_WIRE_2: usize;
    const ECC_OP_WIRE_3: usize;
    const ECC_OP_WIRE_4: usize;
    const CALLDATA: usize;
    const CALLDATA_READ_COUNTS: usize;
    const CALLDATA_READ_TAGS: usize;
    const CALLDATA_INVERSES: usize;
    const SECONDARY_CALLDATA: usize;
    const SECONDARY_CALLDATA_READ_COUNTS: usize;
    const SECONDARY_CALLDATA_READ_TAGS: usize;
    const SECONDARY_CALLDATA_INVERSES: usize;
    const RETURN_DATA: usize;
    const RETURN_DATA_READ_COUNTS: usize;
    const RETURN_DATA_READ_TAGS: usize;
    const RETURN_DATA_INVERSES: usize;

    //  Witness entities:
    /// column 0
    const WITNESS_W_L: usize;
    /// column 1
    const WITNESS_W_R: usize;
    /// column 2
    const WITNESS_W_O: usize;
    /// column 3 (computed by prover)
    const WITNESS_W_4: usize;
    /// column 4 (computed by prover)
    const WITNESS_Z_PERM: usize;
    // /// column 5 (computed by prover);
    const WITNESS_LOOKUP_INVERSES: usize;
    /// column 6
    const WITNESS_LOOKUP_READ_COUNTS: usize;
    /// column 7
    const WITNESS_LOOKUP_READ_TAGS: usize;
    const WITNESS_ECC_OP_WIRE_1: usize;
    const WITNESS_ECC_OP_WIRE_2: usize;
    const WITNESS_ECC_OP_WIRE_3: usize;
    const WITNESS_ECC_OP_WIRE_4: usize;
    const WITNESS_CALLDATA: usize;
    const WITNESS_CALLDATA_READ_COUNTS: usize;
    const WITNESS_CALLDATA_READ_TAGS: usize;
    const WITNESS_CALLDATA_INVERSES: usize;
    const WITNESS_SECONDARY_CALLDATA: usize;
    const WITNESS_SECONDARY_CALLDATA_READ_COUNTS: usize;
    const WITNESS_SECONDARY_CALLDATA_READ_TAGS: usize;
    const WITNESS_SECONDARY_CALLDATA_INVERSES: usize;
    const WITNESS_RETURN_DATA: usize;
    const WITNESS_RETURN_DATA_READ_COUNTS: usize;
    const WITNESS_RETURN_DATA_READ_TAGS: usize;
    const WITNESS_RETURN_DATA_INVERSES: usize;

    fn prover_witness_entity_from_vec<T: Default + Sync + Clone>(
        vec: Vec<Polynomial<T>>,
    ) -> Self::ProverWitnessEntities<Polynomial<T>>;
    fn precomputed_entity_from_vec<T: Default + Clone + Sync>(
        vec: Vec<Polynomial<T>>,
    ) -> Self::PrecomputedEntities<Polynomial<T>>;
}
