use crate::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour, ShiftedWitnessEntitiesFlavour,
    WitnessEntitiesFlavour,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    Ultra,
    Mega,
}

pub trait ProverFlavour:
    Default
    + ProverWitnessEntitiesFlavour
    + ShiftedWitnessEntitiesFlavour
    + WitnessEntitiesFlavour
    + PrecomputedEntitiesFlavour
{
    const FLAVOUR: Flavour;
    // type ProverWitnessEntities<T: Default>: ProverWitnessEntities<T>;
    // type ShiftedWitnessEntities<T: Default>: ShiftedWitnessEntities<T>;
    // type WitnessEntities<T: Default>: WitnessEntities<T>;
    // type PrecomputedEntities<T: Default>: PrecomputedEntities<T>;

    const WITNESS_ENTITIES_SIZE: usize;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize;
    const PRECOMPUTED_ENTITIES_SIZE: usize;
    const PROVER_WITNESS_ENTITIES_SIZE: usize = Self::WITNESS_ENTITIES_SIZE - 2;
    const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
        + Self::PRECOMPUTED_ENTITIES_SIZE
        + Self::SHIFTED_WITNESS_ENTITIES_SIZE;

    //Precomputed Entities:
    const Q_M: usize;
    const Q_C: usize;
    const Q_L: usize;
    const Q_R: usize;
    const Q_O: usize;
    const Q_4: usize;
    const Q_BUSREAD: Option<usize>;
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
    const LAGRANGE_ECC_OP: Option<usize>;
    const DATABUS_ID: Option<usize>;

    // Witness entities:
    const W_L: usize;
    const W_R: usize;
    const W_O: usize;
    const W_4: usize;
    // const Z_PERM: usize;
    // const LOOKUP_INVERSES: usize;
    const LOOKUP_READ_COUNTS: usize;
    const LOOKUP_READ_TAGS: usize;
    const ECC_OP_WIRE_1: Option<usize>;
    const ECC_OP_WIRE_2: Option<usize>;
    const ECC_OP_WIRE_3: Option<usize>;
    const ECC_OP_WIRE_4: Option<usize>;
    const CALLDATA: Option<usize>;
    const CALLDATA_READ_COUNTS: Option<usize>;
    const CALLDATA_READ_TAGS: Option<usize>;
    const CALLDATA_INVERSES: Option<usize>;
    const SECONDARY_CALLDATA: Option<usize>;
    const SECONDARY_CALLDATA_READ_COUNTS: Option<usize>;
    const SECONDARY_CALLDATA_READ_TAGS: Option<usize>;
    const SECONDARY_CALLDATA_INVERSES: Option<usize>;
    const RETURN_DATA: Option<usize>;
    const RETURN_DATA_READ_COUNTS: Option<usize>;
    const RETURN_DATA_READ_TAGS: Option<usize>;
    const RETURN_DATA_INVERSES: Option<usize>;

    //  The "partial length" of a relation is 1 + the degree of the relation
    const MAX_PARTIAL_RELATION_LENGTH: usize;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize;
    // const NUM_SUBRELATIONS: usize;

    // fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]);
    // fn extend_and_batch_univariates<const SIZE: usize>(
    //     acc: &Self::AllRelationAcc,
    //     result: &mut Univariate<F, SIZE>,
    //     extended_random_poly: &Univariate<F, SIZE>,
    //     partial_evaluation_result: &F,
    // );
}
