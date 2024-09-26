use super::Relation;
use crate::decider::{
    sumcheck::sumcheck_round::SumcheckRoundOutput,
    types::{ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ff::{PrimeField, Zero};

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

    pub(crate) fn extend_and_batch_univariates(
        &self,
        result: &mut SumcheckRoundOutput<F>,
        extended_random_poly: &SumcheckRoundOutput<F>,
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
}

pub(crate) struct DeltaRangeConstraintRelation {}

impl DeltaRangeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<F: PrimeField> Relation<F> for DeltaRangeConstraintRelation {
    type Acc = DeltaRangeConstraintRelationAcc<F>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        <Self as Relation<F>>::check_skippable();
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
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
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
        let mut tmp_1 = (delta_1.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_1 *= (delta_1.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_1 *= q_delta_range;
        tmp_1 *= scaling_factor;

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp_1.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2)
        let mut tmp_2 = (delta_2.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_2 *= (delta_2.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_2 *= q_delta_range;
        tmp_2 *= scaling_factor;

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp_2.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3)
        let mut tmp_3 = (delta_3.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_3 *= (delta_3.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_3 *= q_delta_range;
        tmp_3 *= scaling_factor;

        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp_3.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4)
        let mut tmp_4 = (delta_4.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_4 *= (delta_4.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_4 *= q_delta_range;
        tmp_4 *= scaling_factor;

        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp_4.evaluations[i];
        }
    }
}
