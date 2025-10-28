use crate::{
    decider::{
        relations::{
            AllRelationEvaluations, Relation,
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::{EllipticRelation, EllipticRelationEvals},
            logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
            ultra_arithmetic_relation::UltraArithmeticRelation,
        },
        sumcheck::sumcheck_round_prover::SumcheckRoundOutput,
        types::{ClaimedEvaluations, RelationParameters},
    },
    prelude::GateSeparatorPolynomial,
};
use ark_ff::{One, Zero};
use co_noir_common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};

pub(crate) struct SumcheckVerifierRound<P: HonkCurve<TranscriptFieldType>> {
    pub(crate) target_total_sum: P::ScalarField,
    pub(crate) round_failed: bool,
}

impl<P: HonkCurve<TranscriptFieldType>> Default for SumcheckVerifierRound<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: HonkCurve<TranscriptFieldType>> SumcheckVerifierRound<P> {
    pub(crate) fn new() -> Self {
        Self {
            target_total_sum: P::ScalarField::zero(),
            round_failed: false,
        }
    }

    pub(crate) fn compute_next_target_sum<const SIZE: usize>(
        &mut self,
        univariate: &SumcheckRoundOutput<P::ScalarField, SIZE>,
        round_challenge: P::ScalarField,
        indicator: P::ScalarField,
    ) {
        tracing::trace!("Compute target sum");
        self.target_total_sum = (P::ScalarField::one() - indicator) * self.target_total_sum
            + indicator * univariate.evaluate(round_challenge);
    }

    pub(crate) fn check_sum<const SIZE: usize>(
        &mut self,
        univariate: &SumcheckRoundOutput<P::ScalarField, SIZE>,
        indicator: P::ScalarField,
    ) -> bool {
        tracing::trace!("Check sum");
        let total_sum = (P::ScalarField::one() - indicator) * self.target_total_sum
            + indicator * univariate.evaluations[0]
            + univariate.evaluations[1];
        let sumcheck_round_failed = self.target_total_sum != total_sum;

        self.round_failed = self.round_failed || sumcheck_round_failed;
        !sumcheck_round_failed
    }

    fn accumulate_one_relation_evaluations<R: Relation<P::ScalarField>>(
        univariate_accumulator: &mut R::VerifyAcc,
        extended_edges: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        R::verify_accumulate(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_elliptic_curve_relation_evaluations(
        univariate_accumulator: &mut EllipticRelationEvals<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        EllipticRelation::verify_accumulate::<P>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_relation_evaluations(
        univariate_accumulators: &mut AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Accumulate relations");

        Self::accumulate_one_relation_evaluations::<UltraArithmeticRelation>(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<UltraPermutationRelation>(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<DeltaRangeConstraintRelation>(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_elliptic_curve_relation_evaluations(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<LogDerivLookupRelation>(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<Poseidon2ExternalRelation>(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<Poseidon2InternalRelation>(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    pub(crate) fn compute_full_relation_purported_value(
        purported_evaluations: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[P::ScalarField; crate::NUM_ALPHAS],
    ) -> P::ScalarField {
        tracing::trace!("Compute full relation purported value");

        let mut relation_evaluations = AllRelationEvaluations::<P::ScalarField>::default();

        Self::accumulate_relation_evaluations(
            &mut relation_evaluations,
            purported_evaluations,
            relation_parameters,
            &gate_separators.partial_evaluation_result,
        );

        let running_challenge = P::ScalarField::one();

        relation_evaluations.scale_and_batch_elements(running_challenge, alphas)
    }
}
