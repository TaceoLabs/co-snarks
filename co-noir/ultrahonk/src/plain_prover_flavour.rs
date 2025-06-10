use crate::prelude::Univariate;
use ark_ff::PrimeField;
use co_builder::prover_flavour::ProverFlavour;

pub trait PlainProverFlavour<F: PrimeField>: Default + ProverFlavour<F> {
    type AllRelationAcc: Default;
    // const WITNESS_ENTITIES_SIZE: usize;
    // const SHIFTED_WITNESS_ENTITIES_SIZE: usize;
    // const PRECOMPUTED_ENTITIES_SIZE: usize;
    // const PROVER_WITNESS_ENTITIES_SIZE: usize = Self::WITNESS_ENTITIES_SIZE - 2;
    // const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
    //     + Self::PRECOMPUTED_ENTITIES_SIZE
    //     + Self::SHIFTED_WITNESS_ENTITIES_SIZE;

    // // Witness entities:
    // const W_L: usize;
    // const W_R: usize;
    // const W_O: usize;
    // const W_4: usize;
    // const Z_PERM: usize;
    // const LOOKUP_INVERSES: usize;
    // const LOOKUP_READ_COUNTS: usize;
    // const LOOKUP_READ_TAGS: usize;
    // const ECC_OP_WIRE_1: Option<usize>;
    // const ECC_OP_WIRE_2: Option<usize>;
    // const ECC_OP_WIRE_3: Option<usize>;
    // const ECC_OP_WIRE_4: Option<usize>;
    // const CALLDATA: Option<usize>;
    // const CALLDATA_READ_COUNTS: Option<usize>;
    // const CALLDATA_READ_TAGS: Option<usize>;
    // const CALLDATA_INVERSES: Option<usize>;
    // const SECONDARY_CALLDATA: Option<usize>;
    // const SECONDARY_CALLDATA_READ_COUNTS: Option<usize>;
    // const SECONDARY_CALLDATA_READ_TAGS: Option<usize>;
    // const SECONDARY_CALLDATA_INVERSES: Option<usize>;
    // const RETURN_DATA: Option<usize>;
    // const RETURN_DATA_READ_COUNTS: Option<usize>;
    // const RETURN_DATA_READ_TAGS: Option<usize>;
    // const RETURN_DATA_INVERSES: Option<usize>;

    //  The "partial length" of a relation is 1 + the degree of the relation
    // const MAX_PARTIAL_RELATION_LENGTH: usize;
    // const BATCHED_RELATION_PARTIAL_LENGTH: usize;
    // const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize;
    const NUM_SUBRELATIONS: usize;

    fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]);
    fn extend_and_batch_univariates<const SIZE: usize>(
        acc: &Self::AllRelationAcc,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    );
}
