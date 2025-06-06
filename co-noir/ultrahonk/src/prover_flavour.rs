use crate::prelude::Univariate;
use ark_ff::PrimeField;

pub trait ProverFlavour<F: PrimeField> {
    type RelationAccumulator: Default;
    const WITNESS_ENTITIES_SIZE: usize;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize;
    const PRECOMPUTED_ENTITIES_SIZE: usize;
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

    // Witness entities:
    const W_L: usize;
    const W_R: usize;
    const W_O: usize;
    const W_4: usize;
    const Z_PERM: usize;
    const LOOKUP_INVERSES: usize;
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

    const MAX_PARTIAL_RELATION_LENGTH: usize;

    fn scale(acc: &mut Self::RelationAccumulator, first_scalar: F, elements: &[F]);
    fn extend_and_batch_univariates<const SIZE: usize>(
        acc: &Self::RelationAccumulator,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    );
}
