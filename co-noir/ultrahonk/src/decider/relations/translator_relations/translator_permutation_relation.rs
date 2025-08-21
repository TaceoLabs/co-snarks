use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::plain_prover_flavour::UnivariateTrait;
use crate::{
    decider::{
        types::{ClaimedEvaluations, RelationParameters},
        univariate::Univariate,
    },
    plain_prover_flavour::PlainProverFlavour,
};
use ark_ff::{PrimeField, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorPermutationRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 7>,
    pub(crate) r1: Univariate<F, 3>,
}

impl<F: PrimeField> TranslatorPermutationRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
        *current_scalar *= challenge;
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r1.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }

    pub(crate) fn extend_and_batch_univariates_with_distinct_challenges<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        running_challenge: &[Univariate<F, SIZE>],
    ) {
        panic!(
            "TranslatorFlavour should not need extend_and_batch_univariates_with_distinct_challenges"
        );
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorPermutationRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

impl<F: PrimeField> TranslatorPermutationRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }

    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut F,
        _linearly_dependent_contribution: &mut F,
        running_challenge: &[F],
    ) {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }
}

pub(crate) struct TranslatorPermutationRelation {}

impl TranslatorPermutationRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    fn compute_grand_product_numerator<F: PrimeField, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
    ) -> Univariate<F, SIZE> {
        let interleaved_range_constraints_0 = input.witness.interleaved_range_constraints_0();
        let interleaved_range_constraints_1 = input.witness.interleaved_range_constraints_1();
        let interleaved_range_constraints_2 = input.witness.interleaved_range_constraints_2();
        let interleaved_range_constraints_3 = input.witness.interleaved_range_constraints_3();

        let ordered_extra_range_constraints_numerator = input
            .precomputed
            .ordered_extra_range_constraints_numerator();

        let lagrange_masking = input.precomputed.lagrange_masking();
        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        (lagrange_masking.to_owned() * beta + interleaved_range_constraints_0 + &gamma)
            * (lagrange_masking.to_owned() * beta + interleaved_range_constraints_1 + &gamma)
            * (lagrange_masking.to_owned() * beta + interleaved_range_constraints_2 + &gamma)
            * (lagrange_masking.to_owned() * beta + interleaved_range_constraints_3 + &gamma)
            * (lagrange_masking.to_owned() * beta
                + ordered_extra_range_constraints_numerator
                + &gamma)
    }
    fn compute_grand_product_denominator<F: PrimeField, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
    ) -> Univariate<F, SIZE> {
        let ordered_range_constraints_0 = input.witness.ordered_range_constraints_0();
        let ordered_range_constraints_1 = input.witness.ordered_range_constraints_1();
        let ordered_range_constraints_2 = input.witness.ordered_range_constraints_2();
        let ordered_range_constraints_3 = input.witness.ordered_range_constraints_3();
        let ordered_range_constraints_4 = input.witness.ordered_range_constraints_4();

        let lagrange_masking = input.precomputed.lagrange_masking();

        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        (lagrange_masking.to_owned() * beta + ordered_range_constraints_0 + &gamma)
            * (lagrange_masking.to_owned() * beta + ordered_range_constraints_1 + &gamma)
            * (lagrange_masking.to_owned() * beta + ordered_range_constraints_2 + &gamma)
            * (lagrange_masking.to_owned() * beta + ordered_range_constraints_3 + &gamma)
            * (lagrange_masking.to_owned() * beta + ordered_range_constraints_4 + &gamma)
    }
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorPermutationRelation {
    type Acc = TranslatorPermutationRelationAcc<F>;
    type VerifyAcc = TranslatorPermutationRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>) -> bool {
        (input.witness.z_perm().to_owned() - input.shifted_witness.z_perm()).is_zero()
    }

    /**
     * @brief Expression for the generalized permutation sort gate.
     * @details The relation is defined as C(in(X)...) =
     *    q_delta_range * \sum{ i = [0, 3]} \alpha^i D_i(D_i - 1)(D_i - 2)(D_i - 3)
     *      where
     *      D_0 = w_2 - w_1
     *      D_1 = w_3 - w_2
     *      D_2 = w_4 - w_3
     *      D_3 = w_1_shift - w_4
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate TranslatorPermutationRelation");

        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm_shift();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();
        let numerator = TranslatorPermutationRelation::compute_grand_product_numerator(
            input,
            relation_parameters,
        );
        let denominator = TranslatorPermutationRelation::compute_grand_product_denominator(
            input,
            relation_parameters,
        );
        let mut tmp = z_perm.to_owned() + lagrange_first;
        tmp *= numerator;
        tmp -= (z_perm_shift.to_owned() + lagrange_last) * denominator;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }
        let mut tmp = lagrange_last.to_owned() + z_perm_shift;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, TranslatorFlavour>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        todo!()
    }

    fn accumulate_with_extended_parameters<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        todo!()
    }
}
