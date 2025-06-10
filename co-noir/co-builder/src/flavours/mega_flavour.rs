use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::prover_flavour::ProverFlavour;

// use crate::{
//     decider::relations::{
//         auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc},
//         databus_lookup_relation::{DataBusLookupRelation, DataBusLookupRelationAcc},
//         delta_range_constraint_relation::{
//             DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
//         },
//         ecc_op_queue_relation::{EccOpQueueRelation, EccOpQueueRelationAcc},
//         elliptic_relation::{EllipticRelation, EllipticRelationAcc},
//         logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationAcc},
//         permutation_relation::{UltraPermutationRelation, UltraPermutationRelationAcc},
//         poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc},
//         poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationAcc},
//         ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationAcc},
//     },
//     prover_flavour::ProverFlavour,
// };

// #[derive(Default)]
// pub struct AllRelationAccMega<F: PrimeField> {
//     pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
//     pub(crate) r_perm: UltraPermutationRelationAcc<F>,
//     pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
//     pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
//     pub(crate) r_elliptic: EllipticRelationAcc<F>,
//     pub(crate) r_aux: AuxiliaryRelationAcc<F>,
//     pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
//     pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
//     pub(crate) r_ecc_op_queue: EccOpQueueRelationAcc<F>,
//     pub(crate) r_databus: DataBusLookupRelationAcc<F>,
// }
#[derive(Default)]
pub struct MegaFlavour<F: PrimeField> {
    phantom_data: PhantomData<F>,
}
impl<F: PrimeField> ProverFlavour<F> for MegaFlavour<F> {
    // type AllRelationAcc = AllRelationAccMega<F>;

    const WITNESS_ENTITIES_SIZE: usize = 24;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 30;
    const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
        + Self::PRECOMPUTED_ENTITIES_SIZE
        + Self::SHIFTED_WITNESS_ENTITIES_SIZE;

    const MAX_PARTIAL_RELATION_LENGTH: usize = 9;
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

    // const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
    //     + UltraPermutationRelation::NUM_RELATIONS
    //     + DeltaRangeConstraintRelation::NUM_RELATIONS
    //     + EllipticRelation::NUM_RELATIONS
    //     + AuxiliaryRelation::NUM_RELATIONS
    //     + LogDerivLookupRelation::NUM_RELATIONS
    //     + Poseidon2ExternalRelation::NUM_RELATIONS
    //     + Poseidon2InternalRelation::NUM_RELATIONS
    //     + EccOpQueueRelation::NUM_RELATIONS
    //     + DataBusLookupRelation::NUM_RELATIONS;

    // fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]) {
    //     assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
    //     acc.r_arith.scale(&[first_scalar, elements[0]]);
    //     acc.r_perm.scale(&elements[1..3]);
    //     acc.r_lookup.scale(&elements[3..5]);
    //     acc.r_delta.scale(&elements[5..9]);
    //     acc.r_elliptic.scale(&elements[9..11]);
    //     acc.r_aux.scale(&elements[11..17]);
    //     acc.r_ecc_op_queue.scale(&elements[17..25]);
    //     acc.r_databus.scale(&elements[25..31]);
    //     acc.r_pos_ext.scale(&elements[31..35]);
    //     acc.r_pos_int.scale(&elements[35..]);
    // }

    // fn extend_and_batch_univariates<const SIZE: usize>(
    //     acc: &Self::AllRelationAcc,
    //     result: &mut crate::prelude::Univariate<F, SIZE>,
    //     extended_random_poly: &crate::prelude::Univariate<F, SIZE>,
    //     partial_evaluation_result: &F,
    // ) {
    //     acc.r_arith.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_perm.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_lookup.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_delta.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_elliptic.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_aux.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_ecc_op_queue.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_databus.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_pos_ext.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    //     acc.r_pos_int.extend_and_batch_univariates(
    //         result,
    //         extended_random_poly,
    //         partial_evaluation_result,
    //     );
    // }
}

//  // Witness entities:
//     /// column 0
//     const W_L: usize = 0;
//     /// column 1
//     const W_R: usize = 1;
//     /// column 2
//     const W_O: usize = 2;
//     /// column 3 (computed by prover)
//     const W_4: usize = 3;
//     /// column 4 (computed by prover)
//     // const Z_PERM: usize = 4;
//     // /// column 5 (computed by prover);
//     // const LOOKUP_INVERSES: usize = 5;
//     /// column 6
//     const LOOKUP_READ_COUNTS: usize = ;
//     /// column 7
//     const LOOKUP_READ_TAGS: usize = 7;
//     const ECC_OP_WIRE_1: usize = 8;
//     const ECC_OP_WIRE_2: usize = 9;
//     const ECC_OP_WIRE_3: usize = 10;
//     const ECC_OP_WIRE_4: usize = 11;
//     const CALLDATA: usize = 12;
//     const CALLDATA_READ_COUNTS: usize = 13;
//     const CALLDATA_READ_TAGS: usize = 14;
//     const CALLDATA_INVERSES: usize = 15;
//     const SECONDARY_CALLDATA: usize = 16;
//     const SECONDARY_CALLDATA_READ_COUNTS: usize = 17;
//     const SECONDARY_CALLDATA_READ_TAGS: usize = 18;
//     const SECONDARY_CALLDATA_INVERSES: usize = 19;
//     const RETURN_DATA: usize = 20;
//     const RETURN_DATA_READ_COUNTS: usize = 21;
//     const RETURN_DATA_READ_TAGS: usize = 22;
//     const RETURN_DATA_INVERSES: usize = 23;
