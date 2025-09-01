use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::decider::{types::RelationParameters, univariate::Univariate};
use ark_ff::PrimeField;
use co_builder::flavours::translator_flavour::TranslatorFlavour;

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorDeltaRangeConstraintRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 7>,
    pub(crate) r1: Univariate<F, 7>,
    pub(crate) r2: Univariate<F, 7>,
    pub(crate) r3: Univariate<F, 7>,
    pub(crate) r4: Univariate<F, 7>,
    pub(crate) r5: Univariate<F, 3>,
    pub(crate) r6: Univariate<F, 3>,
    pub(crate) r7: Univariate<F, 3>,
    pub(crate) r8: Univariate<F, 3>,
    pub(crate) r9: Univariate<F, 3>,
}

impl<F: PrimeField> TranslatorDeltaRangeConstraintRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
        *current_scalar *= challenge;
        self.r2 *= *current_scalar;
        *current_scalar *= challenge;
        self.r3 *= *current_scalar;
        *current_scalar *= challenge;
        self.r4 *= *current_scalar;
        *current_scalar *= challenge;
        self.r5 *= *current_scalar;
        *current_scalar *= challenge;
        self.r6 *= *current_scalar;
        *current_scalar *= challenge;
        self.r7 *= *current_scalar;
        *current_scalar *= challenge;
        self.r8 *= *current_scalar;
        *current_scalar *= challenge;
        self.r9 *= *current_scalar;
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
        self.r4.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r5.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r6.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r7.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r8.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r9.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct TranslatorDeltaRangeConstraintRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
    pub(crate) r4: F,
    pub(crate) r5: F,
    pub(crate) r6: F,
    pub(crate) r7: F,
    pub(crate) r8: F,
    pub(crate) r9: F,
}

pub(crate) struct TranslatorDeltaRangeConstraintRelation {}

impl TranslatorDeltaRangeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 10;
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorDeltaRangeConstraintRelation {
    type Acc = TranslatorDeltaRangeConstraintRelationAcc<F>;
    type VerifyAcc = TranslatorDeltaRangeConstraintRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(
        _input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
    ) -> bool {
        false
    }

    /**
     * @brief Expression for the generalized permutation sort relation
     *
     * @details The relation enforces 2 constraints on each of the ordered_range_constraints wires:
     * 1) 2 sequential values are non-descending and have a difference of at most 3, except for the value at last index
     * 2) The value at last index is  2¹⁴ - 1
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate TranslatorDeltaRangeConstraintRelation");

        let minus_one = F::from(-1);
        let minus_two = F::from(-2);
        let minus_three = F::from(-3);
        let micro_limb_bits = 14;
        let maximum_sort_value = -F::from((1 << micro_limb_bits) - 1);

        let ordered_range_constraints_0 = input.witness.ordered_range_constraints_0();
        let ordered_range_constraints_1 = input.witness.ordered_range_constraints_1();
        let ordered_range_constraints_2 = input.witness.ordered_range_constraints_2();
        let ordered_range_constraints_3 = input.witness.ordered_range_constraints_3();
        let ordered_range_constraints_4 = input.witness.ordered_range_constraints_4();
        let ordered_range_constraints_0_shift =
            input.shifted_witness.ordered_range_constraints_0_shift();
        let ordered_range_constraints_1_shift =
            input.shifted_witness.ordered_range_constraints_1_shift();
        let ordered_range_constraints_2_shift =
            input.shifted_witness.ordered_range_constraints_2_shift();
        let ordered_range_constraints_3_shift =
            input.shifted_witness.ordered_range_constraints_3_shift();
        let ordered_range_constraints_4_shift =
            input.shifted_witness.ordered_range_constraints_4_shift();
        // Represents the positon of the final non masked witness index
        let lagrange_real_last = input.precomputed.lagrange_real_last();
        let lagrange_masking = input.precomputed.lagrange_masking();

        let is_last_witness_or_masking = (lagrange_real_last.to_owned() + &minus_one)
            * (lagrange_masking.to_owned() + &minus_one);

        // Compute wire differences
        let delta_1 = ordered_range_constraints_0_shift.to_owned() - ordered_range_constraints_0;
        let delta_2 = ordered_range_constraints_1_shift.to_owned() - ordered_range_constraints_1;
        let delta_3 = ordered_range_constraints_2_shift.to_owned() - ordered_range_constraints_2;
        let delta_4 = ordered_range_constraints_3_shift.to_owned() - ordered_range_constraints_3;
        let delta_5 = ordered_range_constraints_4_shift.to_owned() - ordered_range_constraints_4;

        // Contribution (1) (contributions 1-5 ensure that the sequential values have a difference of {0,1,2,3})
        let mut tmp_1 = delta_1.clone();
        tmp_1 *= delta_1.clone() + &minus_one;
        tmp_1 *= delta_1.clone() + &minus_two;
        tmp_1 *= delta_1 + &minus_three;
        tmp_1 *= &is_last_witness_or_masking;
        tmp_1 *= scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp_1.evaluations[i];
        }

        // Contribution (2)
        let mut tmp_2 = delta_2.clone();
        tmp_2 *= delta_2.clone() + &minus_one;
        tmp_2 *= delta_2.clone() + &minus_two;
        tmp_2 *= delta_2.clone() + &minus_three;
        tmp_2 *= &is_last_witness_or_masking;
        tmp_2 *= scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp_2.evaluations[i];
        }

        // Contribution (3)
        let mut tmp_3 = delta_3.clone();
        tmp_3 *= delta_3.clone() + &minus_one;
        tmp_3 *= delta_3.clone() + &minus_two;
        tmp_3 *= delta_3.clone() + &minus_three;
        tmp_3 *= &is_last_witness_or_masking;
        tmp_3 *= scaling_factor;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp_3.evaluations[i];
        }

        // Contribution (4)
        let mut tmp_4 = delta_4.clone();
        tmp_4 *= delta_4.clone() + &minus_one;
        tmp_4 *= delta_4.clone() + &minus_two;
        tmp_4 *= delta_4.clone() + &minus_three;
        tmp_4 *= &is_last_witness_or_masking;
        tmp_4 *= scaling_factor;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp_4.evaluations[i];
        }

        // Contribution (5)
        let mut tmp_5 = delta_5.clone();
        tmp_5 *= delta_5.clone() + &minus_one;
        tmp_5 *= delta_5.clone() + &minus_two;
        tmp_5 *= delta_5.clone() + &minus_three;
        tmp_5 *= is_last_witness_or_masking;
        tmp_5 *= scaling_factor;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp_5.evaluations[i];
        }

        let ordered_range_constraints_0 = input.witness.ordered_range_constraints_0();
        let ordered_range_constraints_1 = input.witness.ordered_range_constraints_1();
        let ordered_range_constraints_2 = input.witness.ordered_range_constraints_2();
        let ordered_range_constraints_3 = input.witness.ordered_range_constraints_3();
        let ordered_range_constraints_4 = input.witness.ordered_range_constraints_4();
        let lagrange_real_last = input.precomputed.lagrange_real_last();

        // Contribution (6) (Contributions 6-10 ensure that the last value is the designated maximum value. We don't
        // need to constrain the first value to be 0, because the shift mechanic does this for us)
        let tmp_5 = (ordered_range_constraints_0.to_owned() + &maximum_sort_value)
            * lagrange_real_last
            * scaling_factor;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp_5.evaluations[i];
        }
        // Contribution (7)
        let tmp_6 = (ordered_range_constraints_1.to_owned() + &maximum_sort_value)
            * lagrange_real_last
            * scaling_factor;
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp_6.evaluations[i];
        }
        // Contribution (8)
        let tmp_7 = (ordered_range_constraints_2.to_owned() + &maximum_sort_value)
            * lagrange_real_last
            * scaling_factor;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp_7.evaluations[i];
        }
        // Contribution (9)
        let tmp_8 = (ordered_range_constraints_3.to_owned() + &maximum_sort_value)
            * lagrange_real_last
            * scaling_factor;
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp_8.evaluations[i];
        }
        // Contribution (10)
        let tmp_9 = (ordered_range_constraints_4.to_owned() + &maximum_sort_value)
            * lagrange_real_last
            * scaling_factor;
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp_9.evaluations[i];
        }
    }
}
