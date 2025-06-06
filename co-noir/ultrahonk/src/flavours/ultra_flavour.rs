use ark_ff::PrimeField;

use crate::prover_flavour::ProverFlavour;

pub struct UltraFlavour;
// impl<F: PrimeField> ProverFlavour<F> for UltraFlavour {
//     type RelationAccumulator;

//     const WITNESS_ENTITIES_SIZE: usize;

//     const SHIFTED_WITNESS_ENTITIES_SIZE: usize;

//     const PRECOMPUTED_ENTITIES_SIZE: usize;

//     const W_L: usize;

//     const W_R: usize;

//     const W_O: usize;

//     const W_4: usize;

//     const Z_PERM: usize;

//     const LOOKUP_INVERSES: usize;

//     const LOOKUP_READ_COUNTS: usize;

//     const LOOKUP_READ_TAGS: usize;

//     const ECC_OP_WIRE_1: usize;

//     const ECC_OP_WIRE_2: usize;

//     const ECC_OP_WIRE_3: usize;

//     const ECC_OP_WIRE_4: usize;

//     const CALLDATA: usize;

//     const CALLDATA_READ_COUNTS: usize;

//     const CALLDATA_READ_TAGS: usize;

//     const CALLDATA_INVERSES: usize;

//     const SECONDARY_CALLDATA: usize;

//     const SECONDARY_CALLDATA_READ_COUNTS: usize;

//     const SECONDARY_CALLDATA_READ_TAGS: usize;

//     const SECONDARY_CALLDATA_INVERSES: usize;

//     const RETURN_DATA: usize;

//     const RETURN_DATA_READ_COUNTS: usize;

//     const RETURN_DATA_READ_TAGS: usize;

//     const RETURN_DATA_INVERSES: usize;

//     const Q_BUSREAD: usize;

//     const LAGRANGE_ECC_OP: usize;

//     const DATABUS_ID: usize;

//     fn scale(acc: &mut Self::RelationAccumulator, first_scalar: F, elements: &[F]) {
//         todo!()
//     }

//     fn extend_and_batch_univariates<const SIZE: usize>(
//         acc: &Self::RelationAccumulator,
//         result: &mut crate::prelude::Univariate<F, SIZE>,
//         extended_random_poly: &crate::prelude::Univariate<F, SIZE>,
//         partial_evaluation_result: &F,
//     ) {
//         todo!()
//     }

//     const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
//         + Self::PRECOMPUTED_ENTITIES_SIZE
//         + Self::SHIFTED_WITNESS_ENTITIES_SIZE;
// }
