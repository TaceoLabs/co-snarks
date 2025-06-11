use ark_ff::PrimeField;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::prelude::HonkCurve;

use crate::decider::sumcheck::round_prover::SumcheckProverRound;
use crate::decider::types::{ProverUnivariates, RelationParameters};
use crate::plain_prover_flavour::PlainProverFlavour;

use crate::decider::relations::{
    auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc},
    databus_lookup_relation::{DataBusLookupRelation, DataBusLookupRelationAcc},
    delta_range_constraint_relation::{
        DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
    },
    ecc_op_queue_relation::{EccOpQueueRelation, EccOpQueueRelationAcc},
    elliptic_relation::{EllipticRelation, EllipticRelationAcc},
    logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationAcc},
    permutation_relation::{UltraPermutationRelation, UltraPermutationRelationAcc},
    poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc},
    poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationAcc},
    ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationAcc},
};
use crate::transcript::TranscriptFieldType;

#[derive(Default)]
pub struct AllRelationAccMega<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_aux: AuxiliaryRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
    pub(crate) r_ecc_op_queue: EccOpQueueRelationAcc<F>,
    pub(crate) r_databus: DataBusLookupRelationAcc<F>,
}

impl<F: PrimeField> PlainProverFlavour<F> for MegaFlavour<F> {
    type AllRelationAcc = AllRelationAccMega<F>;

    const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
        + UltraPermutationRelation::NUM_RELATIONS
        + DeltaRangeConstraintRelation::NUM_RELATIONS
        + EllipticRelation::NUM_RELATIONS
        + AuxiliaryRelation::NUM_RELATIONS
        + LogDerivLookupRelation::NUM_RELATIONS
        + Poseidon2ExternalRelation::NUM_RELATIONS
        + Poseidon2InternalRelation::NUM_RELATIONS
        + EccOpQueueRelation::NUM_RELATIONS
        + DataBusLookupRelation::NUM_RELATIONS;

    fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]) {
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        acc.r_arith.scale(&[first_scalar, elements[0]]);
        acc.r_perm.scale(&elements[1..3]);
        acc.r_lookup.scale(&elements[3..5]);
        acc.r_delta.scale(&elements[5..9]);
        acc.r_elliptic.scale(&elements[9..11]);
        acc.r_aux.scale(&elements[11..17]);
        acc.r_ecc_op_queue.scale(&elements[17..25]);
        acc.r_databus.scale(&elements[25..31]);
        acc.r_pos_ext.scale(&elements[31..35]);
        acc.r_pos_int.scale(&elements[35..]);
    }

    fn extend_and_batch_univariates<const SIZE: usize>(
        acc: &Self::AllRelationAcc,
        result: &mut crate::prelude::Univariate<F, SIZE>,
        extended_random_poly: &crate::prelude::Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        acc.r_arith.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_perm.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_lookup.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_delta.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_elliptic.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_aux.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_ecc_op_queue.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_databus.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_pos_ext.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_pos_int.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
    }

    fn accumulate_relation_univariates<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        const UNIVARIATE_SIZE: usize,
    >(
        univariate_accumulators: &mut Self::AllRelationAcc,
        extended_edges: &ProverUnivariates<F, Self, UNIVARIATE_SIZE>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate relations");

        SumcheckProverRound::accumulate_one_relation_univariates::<
            UltraArithmeticRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            UltraPermutationRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            DeltaRangeConstraintRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_elliptic_curve_relation_univariates::<P, UNIVARIATE_SIZE>(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            AuxiliaryRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            LogDerivLookupRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            Poseidon2ExternalRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            Poseidon2InternalRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            EccOpQueueRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_ecc_op_queue,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            DataBusLookupRelation,
            UNIVARIATE_SIZE,
        >(
            &mut univariate_accumulators.r_databus,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
}
