use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::decider::{types::RelationParameters, univariate::Univariate};
use ark_ff::{PrimeField, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorZeroConstraintsRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 3>,
    pub(crate) r1: Univariate<F, 3>,
    pub(crate) r2: Univariate<F, 3>,
    pub(crate) r3: Univariate<F, 3>,
    pub(crate) r4: Univariate<F, 3>,
    pub(crate) r5: Univariate<F, 3>,
    pub(crate) r6: Univariate<F, 3>,
    pub(crate) r7: Univariate<F, 3>,
    pub(crate) r8: Univariate<F, 3>,
    pub(crate) r9: Univariate<F, 3>,
    pub(crate) r10: Univariate<F, 3>,
    pub(crate) r11: Univariate<F, 3>,
    pub(crate) r12: Univariate<F, 3>,
    pub(crate) r13: Univariate<F, 3>,
    pub(crate) r14: Univariate<F, 3>,
    pub(crate) r15: Univariate<F, 3>,
    pub(crate) r16: Univariate<F, 3>,
    pub(crate) r17: Univariate<F, 3>,
    pub(crate) r18: Univariate<F, 3>,
    pub(crate) r19: Univariate<F, 3>,
    pub(crate) r20: Univariate<F, 3>,
    pub(crate) r21: Univariate<F, 3>,
    pub(crate) r22: Univariate<F, 3>,
    pub(crate) r23: Univariate<F, 3>,
    pub(crate) r24: Univariate<F, 3>,
    pub(crate) r25: Univariate<F, 3>,
    pub(crate) r26: Univariate<F, 3>,
    pub(crate) r27: Univariate<F, 3>,
    pub(crate) r28: Univariate<F, 3>,
    pub(crate) r29: Univariate<F, 3>,
    pub(crate) r30: Univariate<F, 3>,
    pub(crate) r31: Univariate<F, 3>,
    pub(crate) r32: Univariate<F, 3>,
    pub(crate) r33: Univariate<F, 3>,
    pub(crate) r34: Univariate<F, 3>,
    pub(crate) r35: Univariate<F, 3>,
    pub(crate) r36: Univariate<F, 3>,
    pub(crate) r37: Univariate<F, 3>,
    pub(crate) r38: Univariate<F, 3>,
    pub(crate) r39: Univariate<F, 3>,
    pub(crate) r40: Univariate<F, 3>,
    pub(crate) r41: Univariate<F, 3>,
    pub(crate) r42: Univariate<F, 3>,
    pub(crate) r43: Univariate<F, 3>,
    pub(crate) r44: Univariate<F, 3>,
    pub(crate) r45: Univariate<F, 3>,
    pub(crate) r46: Univariate<F, 3>,
    pub(crate) r47: Univariate<F, 3>,
    pub(crate) r48: Univariate<F, 3>,
    pub(crate) r49: Univariate<F, 3>,
    pub(crate) r50: Univariate<F, 3>,
    pub(crate) r51: Univariate<F, 3>,
    pub(crate) r52: Univariate<F, 3>,
    pub(crate) r53: Univariate<F, 3>,
    pub(crate) r54: Univariate<F, 3>,
    pub(crate) r55: Univariate<F, 3>,
    pub(crate) r56: Univariate<F, 3>,
    pub(crate) r57: Univariate<F, 3>,
    pub(crate) r58: Univariate<F, 3>,
    pub(crate) r59: Univariate<F, 3>,
    pub(crate) r60: Univariate<F, 3>,
    pub(crate) r61: Univariate<F, 3>,
    pub(crate) r62: Univariate<F, 3>,
    pub(crate) r63: Univariate<F, 3>,
}

impl<F: PrimeField> TranslatorZeroConstraintsRelationAcc<F> {
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
        self.r10 *= *current_scalar;
        *current_scalar *= challenge;
        self.r11 *= *current_scalar;
        *current_scalar *= challenge;
        self.r12 *= *current_scalar;
        *current_scalar *= challenge;
        self.r13 *= *current_scalar;
        *current_scalar *= challenge;
        self.r14 *= *current_scalar;
        *current_scalar *= challenge;
        self.r15 *= *current_scalar;
        *current_scalar *= challenge;
        self.r16 *= *current_scalar;
        *current_scalar *= challenge;
        self.r17 *= *current_scalar;
        *current_scalar *= challenge;
        self.r18 *= *current_scalar;
        *current_scalar *= challenge;
        self.r19 *= *current_scalar;
        *current_scalar *= challenge;
        self.r20 *= *current_scalar;
        *current_scalar *= challenge;
        self.r21 *= *current_scalar;
        *current_scalar *= challenge;
        self.r22 *= *current_scalar;
        *current_scalar *= challenge;
        self.r23 *= *current_scalar;
        *current_scalar *= challenge;
        self.r24 *= *current_scalar;
        *current_scalar *= challenge;
        self.r25 *= *current_scalar;
        *current_scalar *= challenge;
        self.r26 *= *current_scalar;
        *current_scalar *= challenge;
        self.r27 *= *current_scalar;
        *current_scalar *= challenge;
        self.r28 *= *current_scalar;
        *current_scalar *= challenge;
        self.r29 *= *current_scalar;
        *current_scalar *= challenge;
        self.r30 *= *current_scalar;
        *current_scalar *= challenge;
        self.r31 *= *current_scalar;
        *current_scalar *= challenge;
        self.r32 *= *current_scalar;
        *current_scalar *= challenge;
        self.r33 *= *current_scalar;
        *current_scalar *= challenge;
        self.r34 *= *current_scalar;
        *current_scalar *= challenge;
        self.r35 *= *current_scalar;
        *current_scalar *= challenge;
        self.r36 *= *current_scalar;
        *current_scalar *= challenge;
        self.r37 *= *current_scalar;
        *current_scalar *= challenge;
        self.r38 *= *current_scalar;
        *current_scalar *= challenge;
        self.r39 *= *current_scalar;
        *current_scalar *= challenge;
        self.r40 *= *current_scalar;
        *current_scalar *= challenge;
        self.r41 *= *current_scalar;
        *current_scalar *= challenge;
        self.r42 *= *current_scalar;
        *current_scalar *= challenge;
        self.r43 *= *current_scalar;
        *current_scalar *= challenge;
        self.r44 *= *current_scalar;
        *current_scalar *= challenge;
        self.r45 *= *current_scalar;
        *current_scalar *= challenge;
        self.r46 *= *current_scalar;
        *current_scalar *= challenge;
        self.r47 *= *current_scalar;
        *current_scalar *= challenge;
        self.r48 *= *current_scalar;
        *current_scalar *= challenge;
        self.r49 *= *current_scalar;
        *current_scalar *= challenge;
        self.r50 *= *current_scalar;
        *current_scalar *= challenge;
        self.r51 *= *current_scalar;
        *current_scalar *= challenge;
        self.r52 *= *current_scalar;
        *current_scalar *= challenge;
        self.r53 *= *current_scalar;
        *current_scalar *= challenge;
        self.r54 *= *current_scalar;
        *current_scalar *= challenge;
        self.r55 *= *current_scalar;
        *current_scalar *= challenge;
        self.r56 *= *current_scalar;
        *current_scalar *= challenge;
        self.r57 *= *current_scalar;
        *current_scalar *= challenge;
        self.r58 *= *current_scalar;
        *current_scalar *= challenge;
        self.r59 *= *current_scalar;
        *current_scalar *= challenge;
        self.r60 *= *current_scalar;
        *current_scalar *= challenge;
        self.r61 *= *current_scalar;
        *current_scalar *= challenge;
        self.r62 *= *current_scalar;
        *current_scalar *= challenge;
        self.r63 *= *current_scalar;
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
        self.r10.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r11.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r12.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r13.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r14.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r15.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r16.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r17.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r18.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r19.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r20.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r21.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r22.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r23.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r24.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r25.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r26.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r27.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r28.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r29.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r30.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r31.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r32.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r33.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r34.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r35.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r36.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r37.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r38.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r39.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r40.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r41.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r42.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r43.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r44.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r45.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r46.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r47.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r48.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r49.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r50.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r51.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r52.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r53.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r54.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r55.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r56.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r57.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r58.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r59.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r60.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r61.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r62.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r63.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct TranslatorZeroConstraintsRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
}

pub(crate) struct TranslatorZeroConstraintsRelation {}

impl TranslatorZeroConstraintsRelation {
    pub(crate) const NUM_RELATIONS: usize = 64;
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorZeroConstraintsRelation {
    type Acc = TranslatorZeroConstraintsRelationAcc<F>;
    type VerifyAcc = TranslatorZeroConstraintsRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>) -> bool {
        (input.precomputed.lagrange_even_in_minicircuit().to_owned()
            + input.precomputed.lagrange_last_in_minicircuit()
            - &F::ONE)
            .is_zero()
    }

    /**
     * @brief Relation enforcing all the range-constraint polynomials to be zero after the minicircuit
     * @details This relation ensures that while we are out of the minicircuit the range constraint polynomials are zero
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
        let minus_one = -F::one();

        let lagrange_even_in_minicircuit = input.precomputed.lagrange_even_in_minicircuit();
        let lagrange_odd_in_minicircuit = input.precomputed.lagrange_odd_in_minicircuit();

        let p_x_low_limbs_range_constraint_0 = input.witness.p_x_low_limbs_range_constraint_0();
        let p_x_low_limbs_range_constraint_1 = input.witness.p_x_low_limbs_range_constraint_1();
        let p_x_low_limbs_range_constraint_2 = input.witness.p_x_low_limbs_range_constraint_2();
        let p_x_low_limbs_range_constraint_3 = input.witness.p_x_low_limbs_range_constraint_3();
        let p_x_low_limbs_range_constraint_4 = input.witness.p_x_low_limbs_range_constraint_4();
        let p_x_high_limbs_range_constraint_0 = input.witness.p_x_high_limbs_range_constraint_0();
        let p_x_high_limbs_range_constraint_1 = input.witness.p_x_high_limbs_range_constraint_1();
        let p_x_high_limbs_range_constraint_2 = input.witness.p_x_high_limbs_range_constraint_2();
        let p_x_high_limbs_range_constraint_3 = input.witness.p_x_high_limbs_range_constraint_3();
        let p_x_high_limbs_range_constraint_4 = input.witness.p_x_high_limbs_range_constraint_4();
        let p_y_low_limbs_range_constraint_0 = input.witness.p_y_low_limbs_range_constraint_0();
        let p_y_low_limbs_range_constraint_1 = input.witness.p_y_low_limbs_range_constraint_1();
        let p_y_low_limbs_range_constraint_2 = input.witness.p_y_low_limbs_range_constraint_2();
        let p_y_low_limbs_range_constraint_3 = input.witness.p_y_low_limbs_range_constraint_3();
        let p_y_low_limbs_range_constraint_4 = input.witness.p_y_low_limbs_range_constraint_4();
        let p_y_high_limbs_range_constraint_0 = input.witness.p_y_high_limbs_range_constraint_0();
        let p_y_high_limbs_range_constraint_1 = input.witness.p_y_high_limbs_range_constraint_1();
        let p_y_high_limbs_range_constraint_2 = input.witness.p_y_high_limbs_range_constraint_2();
        let p_y_high_limbs_range_constraint_3 = input.witness.p_y_high_limbs_range_constraint_3();
        let p_y_high_limbs_range_constraint_4 = input.witness.p_y_high_limbs_range_constraint_4();
        let z_low_limbs_range_constraint_0 = input.witness.z_low_limbs_range_constraint_0();
        let z_low_limbs_range_constraint_1 = input.witness.z_low_limbs_range_constraint_1();
        let z_low_limbs_range_constraint_2 = input.witness.z_low_limbs_range_constraint_2();
        let z_low_limbs_range_constraint_3 = input.witness.z_low_limbs_range_constraint_3();
        let z_low_limbs_range_constraint_4 = input.witness.z_low_limbs_range_constraint_4();
        let z_high_limbs_range_constraint_0 = input.witness.z_high_limbs_range_constraint_0();
        let z_high_limbs_range_constraint_1 = input.witness.z_high_limbs_range_constraint_1();
        let z_high_limbs_range_constraint_2 = input.witness.z_high_limbs_range_constraint_2();
        let z_high_limbs_range_constraint_3 = input.witness.z_high_limbs_range_constraint_3();
        let z_high_limbs_range_constraint_4 = input.witness.z_high_limbs_range_constraint_4();
        let accumulator_low_limbs_range_constraint_0 =
            input.witness.accumulator_low_limbs_range_constraint_0();
        let accumulator_low_limbs_range_constraint_1 =
            input.witness.accumulator_low_limbs_range_constraint_1();
        let accumulator_low_limbs_range_constraint_2 =
            input.witness.accumulator_low_limbs_range_constraint_2();
        let accumulator_low_limbs_range_constraint_3 =
            input.witness.accumulator_low_limbs_range_constraint_3();
        let accumulator_low_limbs_range_constraint_4 =
            input.witness.accumulator_low_limbs_range_constraint_4();
        let accumulator_high_limbs_range_constraint_0 =
            input.witness.accumulator_high_limbs_range_constraint_0();
        let accumulator_high_limbs_range_constraint_1 =
            input.witness.accumulator_high_limbs_range_constraint_1();
        let accumulator_high_limbs_range_constraint_2 =
            input.witness.accumulator_high_limbs_range_constraint_2();
        let accumulator_high_limbs_range_constraint_3 =
            input.witness.accumulator_high_limbs_range_constraint_3();
        let accumulator_high_limbs_range_constraint_4 =
            input.witness.accumulator_high_limbs_range_constraint_4();
        let quotient_low_limbs_range_constraint_0 =
            input.witness.quotient_low_limbs_range_constraint_0();
        let quotient_low_limbs_range_constraint_1 =
            input.witness.quotient_low_limbs_range_constraint_1();
        let quotient_low_limbs_range_constraint_2 =
            input.witness.quotient_low_limbs_range_constraint_2();
        let quotient_low_limbs_range_constraint_3 =
            input.witness.quotient_low_limbs_range_constraint_3();
        let quotient_low_limbs_range_constraint_4 =
            input.witness.quotient_low_limbs_range_constraint_4();
        let quotient_high_limbs_range_constraint_0 =
            input.witness.quotient_high_limbs_range_constraint_0();
        let quotient_high_limbs_range_constraint_1 =
            input.witness.quotient_high_limbs_range_constraint_1();
        let quotient_high_limbs_range_constraint_2 =
            input.witness.quotient_high_limbs_range_constraint_2();
        let quotient_high_limbs_range_constraint_3 =
            input.witness.quotient_high_limbs_range_constraint_3();
        let quotient_high_limbs_range_constraint_4 =
            input.witness.quotient_high_limbs_range_constraint_4();
        let relation_wide_limbs_range_constraint_0 =
            input.witness.relation_wide_limbs_range_constraint_0();
        let relation_wide_limbs_range_constraint_1 =
            input.witness.relation_wide_limbs_range_constraint_1();
        let relation_wide_limbs_range_constraint_2 =
            input.witness.relation_wide_limbs_range_constraint_2();
        let relation_wide_limbs_range_constraint_3 =
            input.witness.relation_wide_limbs_range_constraint_3();
        let p_x_low_limbs_range_constraint_tail =
            input.witness.p_x_low_limbs_range_constraint_tail();
        let p_x_high_limbs_range_constraint_tail =
            input.witness.p_x_high_limbs_range_constraint_tail();
        let p_y_low_limbs_range_constraint_tail =
            input.witness.p_y_low_limbs_range_constraint_tail();
        let p_y_high_limbs_range_constraint_tail =
            input.witness.p_y_high_limbs_range_constraint_tail();
        let z_low_limbs_range_constraint_tail = input.witness.z_low_limbs_range_constraint_tail();
        let z_high_limbs_range_constraint_tail = input.witness.z_high_limbs_range_constraint_tail();
        let accumulator_low_limbs_range_constraint_tail =
            input.witness.accumulator_low_limbs_range_constraint_tail();
        let accumulator_high_limbs_range_constraint_tail =
            input.witness.accumulator_high_limbs_range_constraint_tail();
        let quotient_low_limbs_range_constraint_tail =
            input.witness.quotient_low_limbs_range_constraint_tail();
        let quotient_high_limbs_range_constraint_tail =
            input.witness.quotient_high_limbs_range_constraint_tail();

        // 0 in the minicircuit, -1 outside
        let not_in_minicircuit_by_scaling =
            (lagrange_odd_in_minicircuit.to_owned() + lagrange_even_in_minicircuit + &minus_one)
                * scaling_factor;

        // Contribution 0, ensure p_x_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = p_x_low_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 1, ensure p_x_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = p_x_low_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 2, ensure p_x_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = p_x_low_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 3, ensure p_x_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = p_x_low_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 4, ensure p_x_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = p_x_low_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 5, ensure p_x_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = p_x_high_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 6, ensure p_x_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = p_x_high_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 7, ensure p_x_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = p_x_high_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 8, ensure p_x_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = p_x_high_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 9, ensure p_x_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = p_x_high_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 10, ensure p_y_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = p_y_low_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r10.evaluations.len() {
            univariate_accumulator.r10.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 11, ensure p_y_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = p_y_low_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r11.evaluations.len() {
            univariate_accumulator.r11.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 12, ensure p_y_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = p_y_low_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r12.evaluations.len() {
            univariate_accumulator.r12.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 13, ensure p_y_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = p_y_low_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r13.evaluations.len() {
            univariate_accumulator.r13.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 14, ensure p_y_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = p_y_low_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r14.evaluations.len() {
            univariate_accumulator.r14.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 15, ensure p_y_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = p_y_high_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r15.evaluations.len() {
            univariate_accumulator.r15.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 16, ensure p_y_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = p_y_high_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r16.evaluations.len() {
            univariate_accumulator.r16.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 17, ensure p_y_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = p_y_high_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r17.evaluations.len() {
            univariate_accumulator.r17.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 18, ensure p_y_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = p_y_high_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r18.evaluations.len() {
            univariate_accumulator.r18.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 19, ensure p_y_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = p_y_high_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r19.evaluations.len() {
            univariate_accumulator.r19.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 20, ensure z_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = z_low_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r20.evaluations.len() {
            univariate_accumulator.r20.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 21, ensure z_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = z_low_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r21.evaluations.len() {
            univariate_accumulator.r21.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 22, ensure z_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = z_low_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r22.evaluations.len() {
            univariate_accumulator.r22.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 23, ensure z_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = z_low_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r23.evaluations.len() {
            univariate_accumulator.r23.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 24, ensure z_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = z_low_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r24.evaluations.len() {
            univariate_accumulator.r24.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 25, ensure z_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = z_high_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r25.evaluations.len() {
            univariate_accumulator.r25.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 26, ensure z_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = z_high_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r26.evaluations.len() {
            univariate_accumulator.r26.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 27, ensure z_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = z_high_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r27.evaluations.len() {
            univariate_accumulator.r27.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 28, ensure z_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = z_high_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r28.evaluations.len() {
            univariate_accumulator.r28.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 29, ensure z_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = z_high_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r29.evaluations.len() {
            univariate_accumulator.r29.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 30, ensure accumulator_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp =
            accumulator_low_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r30.evaluations.len() {
            univariate_accumulator.r30.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 31, ensure accumulator_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp =
            accumulator_low_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r31.evaluations.len() {
            univariate_accumulator.r31.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 32, ensure accumulator_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp =
            accumulator_low_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r32.evaluations.len() {
            univariate_accumulator.r32.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 33, ensure accumulator_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp =
            accumulator_low_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r33.evaluations.len() {
            univariate_accumulator.r33.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 34, ensure accumulator_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp =
            accumulator_low_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r34.evaluations.len() {
            univariate_accumulator.r34.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 35, ensure accumulator_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp =
            accumulator_high_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r35.evaluations.len() {
            univariate_accumulator.r35.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 36, ensure accumulator_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp =
            accumulator_high_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r36.evaluations.len() {
            univariate_accumulator.r36.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 37, ensure accumulator_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp =
            accumulator_high_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r37.evaluations.len() {
            univariate_accumulator.r37.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 38, ensure accumulator_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp =
            accumulator_high_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r38.evaluations.len() {
            univariate_accumulator.r38.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 39, ensure accumulator_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp =
            accumulator_high_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r39.evaluations.len() {
            univariate_accumulator.r39.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 40, ensure quotient_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = quotient_low_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r40.evaluations.len() {
            univariate_accumulator.r40.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 41, ensure quotient_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = quotient_low_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r41.evaluations.len() {
            univariate_accumulator.r41.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 42, ensure quotient_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = quotient_low_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r42.evaluations.len() {
            univariate_accumulator.r42.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 43, ensure quotient_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = quotient_low_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r43.evaluations.len() {
            univariate_accumulator.r43.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 44, ensure quotient_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = quotient_low_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r44.evaluations.len() {
            univariate_accumulator.r44.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 45, ensure quotient_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp =
            quotient_high_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r45.evaluations.len() {
            univariate_accumulator.r45.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 46, ensure quotient_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp =
            quotient_high_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r46.evaluations.len() {
            univariate_accumulator.r46.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 47, ensure quotient_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp =
            quotient_high_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r47.evaluations.len() {
            univariate_accumulator.r47.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 48, ensure quotient_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp =
            quotient_high_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r48.evaluations.len() {
            univariate_accumulator.r48.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 49, ensure quotient_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp =
            quotient_high_limbs_range_constraint_4.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r49.evaluations.len() {
            univariate_accumulator.r49.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 50, ensure relation_wide_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp =
            relation_wide_limbs_range_constraint_0.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r50.evaluations.len() {
            univariate_accumulator.r50.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 51, ensure relation_wide_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp =
            relation_wide_limbs_range_constraint_1.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r51.evaluations.len() {
            univariate_accumulator.r51.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 52, ensure relation_wide_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp =
            relation_wide_limbs_range_constraint_2.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r52.evaluations.len() {
            univariate_accumulator.r52.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 53, ensure relation_wide_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp =
            relation_wide_limbs_range_constraint_3.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r53.evaluations.len() {
            univariate_accumulator.r53.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 54, ensure p_x_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = p_x_low_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r54.evaluations.len() {
            univariate_accumulator.r54.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 55, ensure p_x_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = p_x_high_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r55.evaluations.len() {
            univariate_accumulator.r55.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 56, ensure p_y_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = p_y_low_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r56.evaluations.len() {
            univariate_accumulator.r56.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 57, ensure p_y_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = p_y_high_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r57.evaluations.len() {
            univariate_accumulator.r57.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 58, ensure z_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = z_low_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r58.evaluations.len() {
            univariate_accumulator.r58.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 59, ensure z_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = z_high_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r59.evaluations.len() {
            univariate_accumulator.r59.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 60, ensure accumulator_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp =
            accumulator_low_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r60.evaluations.len() {
            univariate_accumulator.r60.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 61, ensure accumulator_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = accumulator_high_limbs_range_constraint_tail.to_owned()
            * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r61.evaluations.len() {
            univariate_accumulator.r61.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 62, ensure quotient_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp =
            quotient_low_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r62.evaluations.len() {
            univariate_accumulator.r62.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution 63, ensure quotient_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp =
            quotient_high_limbs_range_constraint_tail.to_owned() * &not_in_minicircuit_by_scaling;
        for i in 0..univariate_accumulator.r63.evaluations.len() {
            univariate_accumulator.r63.evaluations[i] += tmp.evaluations[i];
        }
    }
}
