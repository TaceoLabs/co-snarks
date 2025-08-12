use crate::plain_prover_flavour::UnivariateTrait;
use crate::{
    decider::{
        relations::{
            Relation,
            elliptic_relation::{EllipticRelation, EllipticRelationEvals},
        },
        types::{ClaimedEvaluations, RelationParameters},
    },
    plain_prover_flavour::PlainProverFlavour,
    prelude::GateSeparatorPolynomial,
};
use ark_ff::{One, Zero};
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;

pub(crate) struct SumcheckVerifierRound<P: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour> {
    pub(crate) target_total_sum: P::ScalarField,
    pub(crate) round_failed: bool,
    phantom: std::marker::PhantomData<L>,
}

impl<P: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour> Default
    for SumcheckVerifierRound<P, L>
{
    fn default() -> Self {
        Self::new()
    }
}
impl<P: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour> SumcheckVerifierRound<P, L> {
    pub(crate) fn new() -> Self {
        Self {
            target_total_sum: P::ScalarField::zero(),
            round_failed: false,
            phantom: std::marker::PhantomData,
        }
    }

    pub(crate) fn compute_next_target_sum(
        &mut self,
        univariate: &L::SumcheckRoundOutput<P::ScalarField>,
        round_challenge: P::ScalarField,
        indicator: P::ScalarField,
    ) {
        tracing::trace!("Compute target sum");
        self.target_total_sum = (P::ScalarField::one() - indicator) * self.target_total_sum
            + indicator * univariate.evaluate(round_challenge);
    }

    pub(crate) fn compute_next_target_sum_zk(
        &mut self,
        univariate: &L::SumcheckRoundOutputZK<P::ScalarField>,
        round_challenge: P::ScalarField,
        indicator: P::ScalarField,
    ) {
        tracing::trace!("Compute target sum");
        self.target_total_sum = (P::ScalarField::one() - indicator) * self.target_total_sum
            + indicator * univariate.evaluate(round_challenge);
    }

    pub(crate) fn check_sum(
        &mut self,
        univariate: &L::SumcheckRoundOutput<P::ScalarField>,
        indicator: P::ScalarField,
    ) -> bool {
        tracing::trace!("Check sum");
        let total_sum = (P::ScalarField::one() - indicator) * self.target_total_sum
            + indicator * univariate.evaluations_as_ref()[0]
            + univariate.evaluations_as_ref()[1];
        let sumcheck_round_failed = self.target_total_sum != total_sum;

        self.round_failed = self.round_failed || sumcheck_round_failed;
        !sumcheck_round_failed
    }

    pub(crate) fn check_sum_zk(
        &mut self,
        univariate: &L::SumcheckRoundOutputZK<P::ScalarField>,
        indicator: P::ScalarField,
    ) -> bool {
        tracing::trace!("Check sum");
        let total_sum = (P::ScalarField::one() - indicator) * self.target_total_sum
            + indicator * univariate.evaluations_as_ref()[0]
            + univariate.evaluations_as_ref()[1];
        let sumcheck_round_failed = self.target_total_sum != total_sum;

        self.round_failed = self.round_failed || sumcheck_round_failed;
        !sumcheck_round_failed
    }

    pub(crate) fn accumulate_one_relation_evaluations<R: Relation<P::ScalarField, L>>(
        univariate_accumulator: &mut R::VerifyAcc,
        extended_edges: &ClaimedEvaluations<P::ScalarField, L>,
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

    pub(crate) fn accumulate_elliptic_curve_relation_evaluations(
        univariate_accumulator: &mut EllipticRelationEvals<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, L>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        EllipticRelation::verify_accumulate::<P, L>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    pub(crate) fn compute_full_relation_purported_value(
        purported_evaluations: &ClaimedEvaluations<P::ScalarField, L>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[P::ScalarField],
    ) -> P::ScalarField {
        tracing::trace!("Compute full relation purported value");

        let mut relation_evaluations = L::AllRelationEvaluations::default();

        L::accumulate_relation_evaluations::<P>(
            &mut relation_evaluations,
            purported_evaluations,
            relation_parameters,
            &gate_sparators.partial_evaluation_result,
        );

        let running_challenge = P::ScalarField::one();

        L::scale_and_batch_elements(&relation_evaluations, running_challenge, alphas)
    }
}
