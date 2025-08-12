use super::Relation;
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
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct DeltaRangeConstraintRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 6>,
    pub(crate) r3: Univariate<F, 6>,
}

impl<F: PrimeField> DeltaRangeConstraintRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == DeltaRangeConstraintRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
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

        self.r2.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r3.extend_and_batch_univariates(
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
        self.r0
            .extend_and_batch_univariates(result, &running_challenge[0], &F::ONE, true);

        self.r1
            .extend_and_batch_univariates(result, &running_challenge[1], &F::ONE, true);

        self.r2
            .extend_and_batch_univariates(result, &running_challenge[2], &F::ONE, true);

        self.r3
            .extend_and_batch_univariates(result, &running_challenge[3], &F::ONE, true);
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DeltaRangeConstraintRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
}

impl<F: PrimeField> DeltaRangeConstraintRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == DeltaRangeConstraintRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
    }

    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut F,
        _linearly_dependent_contribution: &mut F,
        running_challenge: &[F],
    ) {
        assert!(running_challenge.len() == DeltaRangeConstraintRelation::NUM_RELATIONS);

        *linearly_independent_contribution += self.r0 * running_challenge[0]
            + self.r1 * running_challenge[1]
            + self.r2 * running_challenge[2]
            + self.r3 * running_challenge[3];
    }
}

pub(crate) struct DeltaRangeConstraintRelation {}

impl DeltaRangeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<F: PrimeField, L: PlainProverFlavour> Relation<F, L> for DeltaRangeConstraintRelation {
    type Acc = DeltaRangeConstraintRelationAcc<F>;
    type VerifyAcc = DeltaRangeConstraintRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool {
        <Self as Relation<F, L>>::check_skippable();
        input.precomputed.q_delta_range().is_zero()
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
        input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate DeltaRangeConstraintRelation");

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let q_delta_range = input.precomputed.q_delta_range();
        let minus_one = -F::one();
        let minus_two = -F::from(2u64);

        // Compute wire differences
        let delta_1 = w_2.to_owned() - w_1;
        let delta_2 = w_3.to_owned() - w_2;
        let delta_3 = w_4.to_owned() - w_3;
        let delta_4 = w_1_shift.to_owned() - w_4;

        // Contribution (1)
        let mut tmp = (delta_1.to_owned() + &minus_one).sqr() + &minus_one;
        tmp *= (delta_1.to_owned() + &minus_two).sqr() + &minus_one;
        tmp *= q_delta_range;
        tmp *= scaling_factor;

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2)
        let mut tmp = (delta_2.to_owned() + &minus_one).sqr() + &minus_one;
        tmp *= (delta_2.to_owned() + &minus_two).sqr() + &minus_one;
        tmp *= q_delta_range;
        tmp *= scaling_factor;

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3)
        let mut tmp = (delta_3.to_owned() + &minus_one).sqr() + &minus_one;
        tmp *= (delta_3.to_owned() + &minus_two).sqr() + &minus_one;
        tmp *= q_delta_range;
        tmp *= scaling_factor;

        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4)
        let mut tmp = (delta_4.to_owned() + &minus_one).sqr() + &minus_one;
        tmp *= (delta_4.to_owned() + &minus_two).sqr() + &minus_one;
        tmp *= q_delta_range;
        tmp *= scaling_factor;

        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate DeltaRangeConstraintRelation");

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let q_delta_range = input.precomputed.q_delta_range();
        let minus_one = -F::one();
        let minus_two = -F::from(2u64);

        // Compute wire differences
        let delta_1 = w_2.to_owned() - w_1;
        let delta_2 = w_3.to_owned() - w_2;
        let delta_3 = w_4.to_owned() - w_3;
        let delta_4 = w_1_shift.to_owned() - w_4;

        // Contribution (1)
        let mut tmp_1 = (delta_1.to_owned() + minus_one).square() + minus_one;
        tmp_1 *= (delta_1.to_owned() + minus_two).square() + minus_one;
        tmp_1 *= q_delta_range;
        tmp_1 *= scaling_factor;

        univariate_accumulator.r0 += tmp_1;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2)
        let mut tmp_2 = (delta_2.to_owned() + minus_one).square() + minus_one;
        tmp_2 *= (delta_2.to_owned() + minus_two).square() + minus_one;
        tmp_2 *= q_delta_range;
        tmp_2 *= scaling_factor;

        univariate_accumulator.r1 += tmp_2;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3)
        let mut tmp_3 = (delta_3.to_owned() + minus_one).square() + minus_one;
        tmp_3 *= (delta_3.to_owned() + minus_two).square() + minus_one;
        tmp_3 *= q_delta_range;
        tmp_3 *= scaling_factor;

        univariate_accumulator.r2 += tmp_3;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4)
        let mut tmp_4 = (delta_4.to_owned() + minus_one).square() + minus_one;
        tmp_4 *= (delta_4.to_owned() + minus_two).square() + minus_one;
        tmp_4 *= q_delta_range;
        tmp_4 *= scaling_factor;

        univariate_accumulator.r3 += tmp_4;
    }

    fn accumulate_with_extended_parameters<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        Self::accumulate(
            univariate_accumulator,
            input,
            &RelationParameters::default(),
            scaling_factor,
        );
    }
}
