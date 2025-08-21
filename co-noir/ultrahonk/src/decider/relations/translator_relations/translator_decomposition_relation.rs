use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::decider::univariate::Univariate;
use ark_ff::One;
use ark_ff::{PrimeField, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use num_bigint::BigUint;

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorDecompositionRelationAcc<F: PrimeField> {
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
}

impl<F: PrimeField> TranslatorDecompositionRelationAcc<F> {
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
            false,
        );
        self.r2.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r3.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r4.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r5.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r6.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r7.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r8.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r9.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r10.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r11.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r12.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r13.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r14.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r15.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r16.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r17.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r18.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r19.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r20.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r21.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r22.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r23.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r24.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r25.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r26.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r27.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r28.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r29.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r30.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r31.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r32.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r33.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r34.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r35.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r36.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r37.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r38.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r39.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r40.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r41.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r42.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r43.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r44.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r45.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r46.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r47.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
    }
}

#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct TranslatorDecompositionRelationEvals<F: PrimeField> {
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
    pub(crate) r10: F,
    pub(crate) r11: F,
    pub(crate) r12: F,
    pub(crate) r13: F,
    pub(crate) r14: F,
    pub(crate) r15: F,
    pub(crate) r16: F,
    pub(crate) r17: F,
    pub(crate) r18: F,
    pub(crate) r19: F,
    pub(crate) r20: F,
    pub(crate) r21: F,
    pub(crate) r22: F,
    pub(crate) r23: F,
    pub(crate) r24: F,
    pub(crate) r25: F,
    pub(crate) r26: F,
    pub(crate) r27: F,
    pub(crate) r28: F,
    pub(crate) r29: F,
    pub(crate) r30: F,
    pub(crate) r31: F,
    pub(crate) r32: F,
    pub(crate) r33: F,
    pub(crate) r34: F,
    pub(crate) r35: F,
    pub(crate) r36: F,
    pub(crate) r37: F,
    pub(crate) r38: F,
    pub(crate) r39: F,
    pub(crate) r40: F,
    pub(crate) r41: F,
    pub(crate) r42: F,
    pub(crate) r43: F,
    pub(crate) r44: F,
    pub(crate) r45: F,
    pub(crate) r46: F,
    pub(crate) r47: F,
}

pub(crate) struct TranslatorDecompositionRelation {}

impl TranslatorDecompositionRelation {
    pub(crate) const NUM_RELATIONS: usize = 48;
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorDecompositionRelation {
    type Acc = TranslatorDecompositionRelationAcc<F>;

    type VerifyAcc = TranslatorDecompositionRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>) -> bool {
        input.precomputed.lagrange_even_in_minicircuit().is_zero()
    }

    /**
     * @brief Expression for decomposition of various values into smaller limbs or microlimbs.
     * @details This relation enforces three types of subrelations:
     * 1) A subrelation decomposing a value from the transcript (for example, z1) into 68-bit limbs. These relations
     *    will have the structure `lagrange_even_in_minicircuit⋅(a - a_low - a_high⋅2⁶⁸)`
     * 2) A subrelation decomposing a value  of one of the limbs used in bigfield computation (for example, the lower
     *    wide relation limb) into 14-bit limbs. These relations will have the structure `lagrange_even_in_minicircuit⋅(a -
     * a_0 - a_1⋅2¹⁴ -
     * ....)` 3) A subrelation making a microlimb range constraint more constraining. For example, we want to constrain
     *    some values to 12 bits instead of 14. So we add a constraint `lagrange_even_in_minicircuit⋅(a_highest⋅4 -
     * a_tail)`. In a separate relation both a_highest and a_tail are constrained to be 14 bits, but this relation
     *    changes the constraint on a_highest to be 12 bits.
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        _relation_parameters: &crate::prelude::RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate TranslatorDecompositionRelation");

        const NUM_LIMB_BITS: usize = 68; // Number of bits in a standard limb used for bigfield operations
        const NUM_MICRO_LIMB_BITS: usize = 14; // Number of bits in a standard limb used for bigfield operations

        // Value to multiply an element by to perform an appropriate shift
        let limb_shift: F = (BigUint::one() << NUM_LIMB_BITS).into();

        // Values to multiply an element by to perform an appropriate shift
        let micro_limb_shift: F = (BigUint::one() << NUM_MICRO_LIMB_BITS).into();
        let micro_limb_shiftx2 = micro_limb_shift * micro_limb_shift;
        let micro_limb_shiftx3 = micro_limb_shiftx2 * micro_limb_shift;
        let micro_limb_shiftx4 = micro_limb_shiftx3 * micro_limb_shift;
        let micro_limb_shiftx5 = micro_limb_shiftx4 * micro_limb_shift;

        // Shifts used to constrain ranges further
        let shift_12_to_14 = F::from(4); // Shift used to range constrain the last microlimb of 68-bit limbs (standard limbs)
        let shift_10_to_14 = F::from(16); // Shift used to range constrain the last microlimb of 52-bit limb (top quotient limb)
        let shift_8_to_14 = F::from(64); // Shift used to range constrain the last microlimb of 50-bit
        // limbs (top limb of standard 254-bit value)
        let shift_4_to_14 = F::from(1024); // Shift used to range constrain the last mircrolimb of 60-bit limbs from z scalars

        let p_x_low_limbs = input.witness.p_x_low_limbs();
        let p_x_low_limbs_range_constraint_0 = input.witness.p_x_low_limbs_range_constraint_0();
        let p_x_low_limbs_range_constraint_1 = input.witness.p_x_low_limbs_range_constraint_1();
        let p_x_low_limbs_range_constraint_2 = input.witness.p_x_low_limbs_range_constraint_2();
        let p_x_low_limbs_range_constraint_3 = input.witness.p_x_low_limbs_range_constraint_3();
        let p_x_low_limbs_range_constraint_4 = input.witness.p_x_low_limbs_range_constraint_4();
        let p_x_low_limbs_shift = input.shifted_witness.p_x_low_limbs_shift();
        let p_x_low_limbs_range_constraint_0_shift = input
            .shifted_witness
            .p_x_low_limbs_range_constraint_0_shift();
        let p_x_low_limbs_range_constraint_1_shift = input
            .shifted_witness
            .p_x_low_limbs_range_constraint_1_shift();
        let p_x_low_limbs_range_constraint_2_shift = input
            .shifted_witness
            .p_x_low_limbs_range_constraint_2_shift();
        let p_x_low_limbs_range_constraint_3_shift = input
            .shifted_witness
            .p_x_low_limbs_range_constraint_3_shift();
        let p_x_low_limbs_range_constraint_4_shift = input
            .shifted_witness
            .p_x_low_limbs_range_constraint_4_shift();
        let p_x_high_limbs = input.witness.p_x_high_limbs();
        let p_x_high_limbs_range_constraint_0 = input.witness.p_x_high_limbs_range_constraint_0();
        let p_x_high_limbs_range_constraint_1 = input.witness.p_x_high_limbs_range_constraint_1();
        let p_x_high_limbs_range_constraint_2 = input.witness.p_x_high_limbs_range_constraint_2();
        let p_x_high_limbs_range_constraint_3 = input.witness.p_x_high_limbs_range_constraint_3();
        let p_x_high_limbs_range_constraint_4 = input.witness.p_x_high_limbs_range_constraint_4();
        let p_x_high_limbs_shift = input.shifted_witness.p_x_high_limbs_shift();
        let p_x_high_limbs_range_constraint_0_shift = input
            .shifted_witness
            .p_x_high_limbs_range_constraint_0_shift();
        let p_x_high_limbs_range_constraint_1_shift = input
            .shifted_witness
            .p_x_high_limbs_range_constraint_1_shift();
        let p_x_high_limbs_range_constraint_2_shift = input
            .shifted_witness
            .p_x_high_limbs_range_constraint_2_shift();
        let p_x_high_limbs_range_constraint_3_shift = input
            .shifted_witness
            .p_x_high_limbs_range_constraint_3_shift();
        let p_y_low_limbs = input.witness.p_y_low_limbs();
        let p_y_low_limbs_range_constraint_0 = input.witness.p_y_low_limbs_range_constraint_0();
        let p_y_low_limbs_range_constraint_1 = input.witness.p_y_low_limbs_range_constraint_1();
        let p_y_low_limbs_range_constraint_2 = input.witness.p_y_low_limbs_range_constraint_2();
        let p_y_low_limbs_range_constraint_3 = input.witness.p_y_low_limbs_range_constraint_3();
        let p_y_low_limbs_range_constraint_4 = input.witness.p_y_low_limbs_range_constraint_4();
        let p_y_low_limbs_shift = input.shifted_witness.p_y_low_limbs_shift();
        let p_y_low_limbs_range_constraint_0_shift = input
            .shifted_witness
            .p_y_low_limbs_range_constraint_0_shift();
        let p_y_low_limbs_range_constraint_1_shift = input
            .shifted_witness
            .p_y_low_limbs_range_constraint_1_shift();
        let p_y_low_limbs_range_constraint_2_shift = input
            .shifted_witness
            .p_y_low_limbs_range_constraint_2_shift();
        let p_y_low_limbs_range_constraint_3_shift = input
            .shifted_witness
            .p_y_low_limbs_range_constraint_3_shift();
        let p_y_low_limbs_range_constraint_4_shift = input
            .shifted_witness
            .p_y_low_limbs_range_constraint_4_shift();
        let p_y_high_limbs = input.witness.p_y_high_limbs();
        let p_y_high_limbs_range_constraint_0 = input.witness.p_y_high_limbs_range_constraint_0();
        let p_y_high_limbs_range_constraint_1 = input.witness.p_y_high_limbs_range_constraint_1();
        let p_y_high_limbs_range_constraint_2 = input.witness.p_y_high_limbs_range_constraint_2();
        let p_y_high_limbs_range_constraint_3 = input.witness.p_y_high_limbs_range_constraint_3();
        let p_y_high_limbs_range_constraint_4 = input.witness.p_y_high_limbs_range_constraint_4();
        let p_y_high_limbs_shift = input.shifted_witness.p_y_high_limbs_shift();
        let p_y_high_limbs_range_constraint_0_shift = input
            .shifted_witness
            .p_y_high_limbs_range_constraint_0_shift();
        let p_y_high_limbs_range_constraint_1_shift = input
            .shifted_witness
            .p_y_high_limbs_range_constraint_1_shift();
        let p_y_high_limbs_range_constraint_2_shift = input
            .shifted_witness
            .p_y_high_limbs_range_constraint_2_shift();
        let p_y_high_limbs_range_constraint_3_shift = input
            .shifted_witness
            .p_y_high_limbs_range_constraint_3_shift();
        let z_low_limbs = input.witness.z_low_limbs();
        let z_low_limbs_range_constraint_0 = input.witness.z_low_limbs_range_constraint_0();
        let z_low_limbs_range_constraint_1 = input.witness.z_low_limbs_range_constraint_1();
        let z_low_limbs_range_constraint_2 = input.witness.z_low_limbs_range_constraint_2();
        let z_low_limbs_range_constraint_3 = input.witness.z_low_limbs_range_constraint_3();
        let z_low_limbs_range_constraint_4 = input.witness.z_low_limbs_range_constraint_4();
        let z_low_limbs_shift = input.shifted_witness.z_low_limbs_shift();
        let z_low_limbs_range_constraint_0_shift =
            input.shifted_witness.z_low_limbs_range_constraint_0_shift();
        let z_low_limbs_range_constraint_1_shift =
            input.shifted_witness.z_low_limbs_range_constraint_1_shift();
        let z_low_limbs_range_constraint_2_shift =
            input.shifted_witness.z_low_limbs_range_constraint_2_shift();
        let z_low_limbs_range_constraint_3_shift =
            input.shifted_witness.z_low_limbs_range_constraint_3_shift();
        let z_low_limbs_range_constraint_4_shift =
            input.shifted_witness.z_low_limbs_range_constraint_4_shift();
        let z_high_limbs = input.witness.z_high_limbs();
        let z_high_limbs_range_constraint_0 = input.witness.z_high_limbs_range_constraint_0();
        let z_high_limbs_range_constraint_1 = input.witness.z_high_limbs_range_constraint_1();
        let z_high_limbs_range_constraint_2 = input.witness.z_high_limbs_range_constraint_2();
        let z_high_limbs_range_constraint_3 = input.witness.z_high_limbs_range_constraint_3();
        let z_high_limbs_range_constraint_4 = input.witness.z_high_limbs_range_constraint_4();
        let z_high_limbs_shift = input.shifted_witness.z_high_limbs_shift();
        let z_high_limbs_range_constraint_0_shift = input
            .shifted_witness
            .z_high_limbs_range_constraint_0_shift();
        let z_high_limbs_range_constraint_1_shift = input
            .shifted_witness
            .z_high_limbs_range_constraint_1_shift();
        let z_high_limbs_range_constraint_2_shift = input
            .shifted_witness
            .z_high_limbs_range_constraint_2_shift();
        let z_high_limbs_range_constraint_3_shift = input
            .shifted_witness
            .z_high_limbs_range_constraint_3_shift();
        let z_high_limbs_range_constraint_4_shift = input
            .shifted_witness
            .z_high_limbs_range_constraint_4_shift();
        let accumulators_binary_limbs_0 = input.witness.accumulators_binary_limbs_0();
        let accumulators_binary_limbs_1 = input.witness.accumulators_binary_limbs_1();
        let accumulators_binary_limbs_2 = input.witness.accumulators_binary_limbs_2();
        let accumulators_binary_limbs_3 = input.witness.accumulators_binary_limbs_3();
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
        let accumulator_low_limbs_range_constraint_0_shift = input
            .shifted_witness
            .accumulator_low_limbs_range_constraint_0_shift();
        let accumulator_low_limbs_range_constraint_1_shift = input
            .shifted_witness
            .accumulator_low_limbs_range_constraint_1_shift();
        let accumulator_low_limbs_range_constraint_2_shift = input
            .shifted_witness
            .accumulator_low_limbs_range_constraint_2_shift();
        let accumulator_low_limbs_range_constraint_3_shift = input
            .shifted_witness
            .accumulator_low_limbs_range_constraint_3_shift();
        let accumulator_low_limbs_range_constraint_4_shift = input
            .shifted_witness
            .accumulator_low_limbs_range_constraint_4_shift();
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
        let accumulator_high_limbs_range_constraint_0_shift = input
            .shifted_witness
            .accumulator_high_limbs_range_constraint_0_shift();
        let accumulator_high_limbs_range_constraint_1_shift = input
            .shifted_witness
            .accumulator_high_limbs_range_constraint_1_shift();
        let accumulator_high_limbs_range_constraint_2_shift = input
            .shifted_witness
            .accumulator_high_limbs_range_constraint_2_shift();
        let accumulator_high_limbs_range_constraint_3_shift = input
            .shifted_witness
            .accumulator_high_limbs_range_constraint_3_shift();
        let quotient_low_binary_limbs = input.witness.quotient_low_binary_limbs();
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
        let quotient_low_binary_limbs_shift =
            input.shifted_witness.quotient_low_binary_limbs_shift();
        let quotient_low_limbs_range_constraint_0_shift = input
            .shifted_witness
            .quotient_low_limbs_range_constraint_0_shift();
        let quotient_low_limbs_range_constraint_1_shift = input
            .shifted_witness
            .quotient_low_limbs_range_constraint_1_shift();
        let quotient_low_limbs_range_constraint_2_shift = input
            .shifted_witness
            .quotient_low_limbs_range_constraint_2_shift();
        let quotient_low_limbs_range_constraint_3_shift = input
            .shifted_witness
            .quotient_low_limbs_range_constraint_3_shift();
        let quotient_low_limbs_range_constraint_4_shift = input
            .shifted_witness
            .quotient_low_limbs_range_constraint_4_shift();
        let quotient_high_binary_limbs = input.witness.quotient_high_binary_limbs();
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
        let quotient_high_binary_limbs_shift =
            input.shifted_witness.quotient_high_binary_limbs_shift();
        let quotient_high_limbs_range_constraint_0_shift = input
            .shifted_witness
            .quotient_high_limbs_range_constraint_0_shift();
        let quotient_high_limbs_range_constraint_1_shift = input
            .shifted_witness
            .quotient_high_limbs_range_constraint_1_shift();
        let quotient_high_limbs_range_constraint_2_shift = input
            .shifted_witness
            .quotient_high_limbs_range_constraint_2_shift();
        let quotient_high_limbs_range_constraint_3_shift = input
            .shifted_witness
            .quotient_high_limbs_range_constraint_3_shift();
        let relation_wide_limbs = input.witness.relation_wide_limbs();
        let relation_wide_limbs_range_constraint_0 =
            input.witness.relation_wide_limbs_range_constraint_0();
        let relation_wide_limbs_range_constraint_1 =
            input.witness.relation_wide_limbs_range_constraint_1();
        let relation_wide_limbs_range_constraint_2 =
            input.witness.relation_wide_limbs_range_constraint_2();
        let relation_wide_limbs_range_constraint_3 =
            input.witness.relation_wide_limbs_range_constraint_3();
        let p_x_high_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .p_x_high_limbs_range_constraint_tail_shift();
        let accumulator_high_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .accumulator_high_limbs_range_constraint_tail_shift();
        let relation_wide_limbs_shift = input.shifted_witness.relation_wide_limbs_shift();
        let relation_wide_limbs_range_constraint_0_shift = input
            .shifted_witness
            .relation_wide_limbs_range_constraint_0_shift();
        let relation_wide_limbs_range_constraint_1_shift = input
            .shifted_witness
            .relation_wide_limbs_range_constraint_1_shift();
        let relation_wide_limbs_range_constraint_2_shift = input
            .shifted_witness
            .relation_wide_limbs_range_constraint_2_shift();
        let relation_wide_limbs_range_constraint_3_shift = input
            .shifted_witness
            .relation_wide_limbs_range_constraint_3_shift();
        let p_y_high_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .p_y_high_limbs_range_constraint_tail_shift();
        let quotient_high_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .quotient_high_limbs_range_constraint_tail_shift();
        let p_x_low_limbs_range_constraint_tail =
            input.witness.p_x_low_limbs_range_constraint_tail();
        let p_x_low_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .p_x_low_limbs_range_constraint_tail_shift();
        let p_x_high_limbs_range_constraint_tail =
            input.witness.p_x_high_limbs_range_constraint_tail();
        let p_x_high_limbs_range_constraint_4_shift = input
            .shifted_witness
            .p_x_high_limbs_range_constraint_4_shift();
        let p_y_low_limbs_range_constraint_tail =
            input.witness.p_y_low_limbs_range_constraint_tail();
        let p_y_low_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .p_y_low_limbs_range_constraint_tail_shift();
        let p_y_high_limbs_range_constraint_tail =
            input.witness.p_y_high_limbs_range_constraint_tail();
        let p_y_high_limbs_range_constraint_4_shift = input
            .shifted_witness
            .p_y_high_limbs_range_constraint_4_shift();
        let z_low_limbs_range_constraint_tail = input.witness.z_low_limbs_range_constraint_tail();
        let z_low_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .z_low_limbs_range_constraint_tail_shift();
        let z_high_limbs_range_constraint_tail = input.witness.z_high_limbs_range_constraint_tail();
        let z_high_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .z_high_limbs_range_constraint_tail_shift();
        let accumulator_low_limbs_range_constraint_tail =
            input.witness.accumulator_low_limbs_range_constraint_tail();
        let accumulator_low_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .accumulator_low_limbs_range_constraint_tail_shift();
        let accumulator_high_limbs_range_constraint_tail =
            input.witness.accumulator_high_limbs_range_constraint_tail();
        let accumulator_high_limbs_range_constraint_4_shift = input
            .shifted_witness
            .accumulator_high_limbs_range_constraint_4_shift();
        let quotient_low_limbs_range_constraint_tail =
            input.witness.quotient_low_limbs_range_constraint_tail();
        let quotient_low_limbs_range_constraint_tail_shift = input
            .shifted_witness
            .quotient_low_limbs_range_constraint_tail_shift();
        let quotient_high_limbs_range_constraint_tail =
            input.witness.quotient_high_limbs_range_constraint_tail();
        let quotient_high_limbs_range_constraint_4_shift = input
            .shifted_witness
            .quotient_high_limbs_range_constraint_4_shift();
        let x_lo_y_hi = input.witness.x_lo_y_hi();
        let x_hi_z_1 = input.witness.x_hi_z_1();
        let y_lo_z_2 = input.witness.y_lo_z_2();
        let x_lo_y_hi_shift = input.shifted_witness.x_lo_y_hi_shift();
        let x_hi_z_1_shift = input.shifted_witness.x_hi_z_1_shift();
        let y_lo_z_2_shift = input.shifted_witness.y_lo_z_2_shift();
        let lagrange_even_in_minicircuit = input.precomputed.lagrange_even_in_minicircuit();

        // Contributions that decompose 50, 52, 68 or 84 bit limbs used for computation into range-constrained chunks
        // Contribution 1 , P_x lowest limb decomposition
        let mut tmp_1 = (p_x_low_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + p_x_low_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + p_x_low_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + p_x_low_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4
            + p_x_low_limbs_range_constraint_0)
            - p_x_low_limbs;
        tmp_1 *= lagrange_even_in_minicircuit;
        tmp_1 *= scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp_1.evaluations[i];
        }

        // Contribution 2 , P_x second lowest limb decomposition
        let mut tmp_2 = (p_x_low_limbs_range_constraint_1_shift.to_owned() * micro_limb_shift
            + p_x_low_limbs_range_constraint_0_shift
            + p_x_low_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + p_x_low_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + p_x_low_limbs_range_constraint_4_shift.to_owned() * micro_limb_shiftx4)
            - p_x_low_limbs_shift;
        tmp_2 *= lagrange_even_in_minicircuit;
        tmp_2 *= scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp_2.evaluations[i];
        }

        // Contribution 3 , P_x third limb decomposition
        let mut tmp_3 = (p_x_high_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + p_x_high_limbs_range_constraint_0
            + p_x_high_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + p_x_high_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + p_x_high_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - p_x_high_limbs;
        tmp_3 *= lagrange_even_in_minicircuit;
        tmp_3 *= scaling_factor;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp_3.evaluations[i];
        }

        // Contribution 4 , P_x highest limb decomposition
        let mut tmp_4 = (p_x_high_limbs_range_constraint_1_shift.to_owned() * micro_limb_shift
            + p_x_high_limbs_range_constraint_0_shift
            + p_x_high_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + p_x_high_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3)
            - p_x_high_limbs_shift;
        tmp_4 *= lagrange_even_in_minicircuit;
        tmp_4 *= scaling_factor;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp_4.evaluations[i];
        }

        // Contribution 5 , P_y lowest limb decomposition
        let mut tmp_5 = (p_y_low_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + p_y_low_limbs_range_constraint_0
            + p_y_low_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + p_y_low_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + p_y_low_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - p_y_low_limbs;
        tmp_5 *= lagrange_even_in_minicircuit;
        tmp_5 *= scaling_factor;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp_5.evaluations[i];
        }

        // Contribution 6 , P_y second lowest limb decomposition
        let mut tmp_6 = (p_y_low_limbs_range_constraint_1_shift.to_owned() * micro_limb_shift
            + p_y_low_limbs_range_constraint_0_shift
            + p_y_low_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + p_y_low_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + p_y_low_limbs_range_constraint_4_shift.to_owned() * micro_limb_shiftx4)
            - p_y_low_limbs_shift;
        tmp_6 *= lagrange_even_in_minicircuit;
        tmp_6 *= scaling_factor;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp_6.evaluations[i];
        }

        // Contribution 7 , P_y third limb decomposition
        let mut tmp_7 = (p_y_high_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + p_y_high_limbs_range_constraint_0
            + p_y_high_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + p_y_high_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + p_y_high_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - p_y_high_limbs;
        tmp_7 *= lagrange_even_in_minicircuit;
        tmp_7 *= scaling_factor;
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp_7.evaluations[i];
        }

        // Contribution 8 , P_y highest limb decomposition
        let mut tmp_8 = (p_y_high_limbs_range_constraint_1_shift.to_owned() * micro_limb_shift
            + p_y_high_limbs_range_constraint_0_shift
            + p_y_high_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + p_y_high_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3)
            - p_y_high_limbs_shift;
        tmp_8 *= lagrange_even_in_minicircuit;
        tmp_8 *= scaling_factor;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp_8.evaluations[i];
        }

        // Contribution 9 , z_1 low limb decomposition
        let mut tmp_9 = (z_low_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + z_low_limbs_range_constraint_0
            + z_low_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + z_low_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + z_low_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - z_low_limbs;
        tmp_9 *= lagrange_even_in_minicircuit;
        tmp_9 *= scaling_factor;
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp_9.evaluations[i];
        }

        // Contribution 10 , z_2 low limb decomposition
        let mut tmp_10 = (z_low_limbs_range_constraint_1_shift.to_owned() * micro_limb_shift
            + z_low_limbs_range_constraint_0_shift
            + z_low_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + z_low_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + z_low_limbs_range_constraint_4_shift.to_owned() * micro_limb_shiftx4)
            - z_low_limbs_shift;
        tmp_10 *= lagrange_even_in_minicircuit;
        tmp_10 *= scaling_factor;
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp_10.evaluations[i];
        }

        // Contribution 11 , z_1 high limb decomposition
        let mut tmp_11 = (z_high_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + z_high_limbs_range_constraint_0
            + z_high_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + z_high_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + z_high_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - z_high_limbs;
        tmp_11 *= lagrange_even_in_minicircuit;
        tmp_11 *= scaling_factor;
        for i in 0..univariate_accumulator.r10.evaluations.len() {
            univariate_accumulator.r10.evaluations[i] += tmp_11.evaluations[i];
        }

        // Contribution 12 , z_2 high limb decomposition
        let mut tmp_12 = (z_high_limbs_range_constraint_1_shift.to_owned() * micro_limb_shift
            + z_high_limbs_range_constraint_0_shift
            + z_high_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + z_high_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + z_high_limbs_range_constraint_4_shift.to_owned() * micro_limb_shiftx4)
            - z_high_limbs_shift;
        tmp_12 *= lagrange_even_in_minicircuit;
        tmp_12 *= scaling_factor;
        for i in 0..univariate_accumulator.r11.evaluations.len() {
            univariate_accumulator.r11.evaluations[i] += tmp_12.evaluations[i];
        }

        // Contribution 13 , accumulator lowest limb decomposition
        let mut tmp_13 = (accumulator_low_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + accumulator_low_limbs_range_constraint_0
            + accumulator_low_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + accumulator_low_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + accumulator_low_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - accumulators_binary_limbs_0;
        tmp_13 *= lagrange_even_in_minicircuit;
        tmp_13 *= scaling_factor;
        for i in 0..univariate_accumulator.r12.evaluations.len() {
            univariate_accumulator.r12.evaluations[i] += tmp_13.evaluations[i];
        }
        // Contribution 14 , accumulator second limb decomposition
        let mut tmp_14 = (accumulator_low_limbs_range_constraint_1_shift.to_owned()
            * micro_limb_shift
            + accumulator_low_limbs_range_constraint_0_shift
            + accumulator_low_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + accumulator_low_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + accumulator_low_limbs_range_constraint_4_shift.to_owned() * micro_limb_shiftx4)
            - accumulators_binary_limbs_1;
        tmp_14 *= lagrange_even_in_minicircuit;
        tmp_14 *= scaling_factor;
        for i in 0..univariate_accumulator.r13.evaluations.len() {
            univariate_accumulator.r13.evaluations[i] += tmp_14.evaluations[i];
        }

        // Contribution 15 , accumulator second highest limb decomposition
        let mut tmp_15 = (accumulator_high_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + accumulator_high_limbs_range_constraint_0
            + accumulator_high_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + accumulator_high_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + accumulator_high_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - accumulators_binary_limbs_2;
        tmp_15 *= lagrange_even_in_minicircuit;
        tmp_15 *= scaling_factor;
        for i in 0..univariate_accumulator.r14.evaluations.len() {
            univariate_accumulator.r14.evaluations[i] += tmp_15.evaluations[i];
        }
        // Contribution 16 , accumulator highest limb decomposition
        let mut tmp_16 = (accumulator_high_limbs_range_constraint_1_shift.to_owned()
            * micro_limb_shift
            + accumulator_high_limbs_range_constraint_0_shift
            + accumulator_high_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + accumulator_high_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3)
            - accumulators_binary_limbs_3;
        tmp_16 *= lagrange_even_in_minicircuit;
        tmp_16 *= scaling_factor;
        for i in 0..univariate_accumulator.r15.evaluations.len() {
            univariate_accumulator.r15.evaluations[i] += tmp_16.evaluations[i];
        }

        // Contribution 15 , quotient lowest limb decomposition
        let mut tmp_17 = (quotient_low_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + quotient_low_limbs_range_constraint_0
            + quotient_low_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + quotient_low_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + quotient_low_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - quotient_low_binary_limbs;
        tmp_17 *= lagrange_even_in_minicircuit;
        tmp_17 *= scaling_factor;
        for i in 0..univariate_accumulator.r16.evaluations.len() {
            univariate_accumulator.r16.evaluations[i] += tmp_17.evaluations[i];
        }
        // Contribution 16 , quotient second lowest limb decomposition
        let mut tmp_18 = (quotient_low_limbs_range_constraint_1_shift.to_owned()
            * micro_limb_shift
            + quotient_low_limbs_range_constraint_0_shift
            + quotient_low_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + quotient_low_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + quotient_low_limbs_range_constraint_4_shift.to_owned() * micro_limb_shiftx4)
            - quotient_low_binary_limbs_shift;
        tmp_18 *= lagrange_even_in_minicircuit;
        tmp_18 *= scaling_factor;
        for i in 0..univariate_accumulator.r17.evaluations.len() {
            univariate_accumulator.r17.evaluations[i] += tmp_18.evaluations[i];
        }

        // Contribution 19 , quotient second highest limb decomposition
        let mut tmp_19 = (quotient_high_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + quotient_high_limbs_range_constraint_0
            + quotient_high_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + quotient_high_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + quotient_high_limbs_range_constraint_4.to_owned() * micro_limb_shiftx4)
            - quotient_high_binary_limbs;
        tmp_19 *= lagrange_even_in_minicircuit;
        tmp_19 *= scaling_factor;
        for i in 0..univariate_accumulator.r18.evaluations.len() {
            univariate_accumulator.r18.evaluations[i] += tmp_19.evaluations[i];
        }
        // Contribution 20 , quotient highest limb decomposition
        let mut tmp_20 = (quotient_high_limbs_range_constraint_1_shift.to_owned()
            * micro_limb_shift
            + quotient_high_limbs_range_constraint_0_shift
            + quotient_high_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + quotient_high_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3)
            - quotient_high_binary_limbs_shift;
        tmp_20 *= lagrange_even_in_minicircuit;
        tmp_20 *= scaling_factor;
        for i in 0..univariate_accumulator.r19.evaluations.len() {
            univariate_accumulator.r19.evaluations[i] += tmp_20.evaluations[i];
        }

        // Contribution 21 , decomposition of the low wide relation limb used for the bigfield relation.
        // N.B. top microlimbs of relation wide limbs are stored in microlimbs for range constraints of P_x, P_y,
        // accumulator and quotient. This is to save space and because these microlimbs are not used by their namesakes,
        // since top limbs in 254/6-bit values use one less microlimb for the top 50/52-bit limb
        let mut tmp_21 = (relation_wide_limbs_range_constraint_1.to_owned() * micro_limb_shift
            + relation_wide_limbs_range_constraint_0
            + relation_wide_limbs_range_constraint_2.to_owned() * micro_limb_shiftx2
            + relation_wide_limbs_range_constraint_3.to_owned() * micro_limb_shiftx3
            + p_x_high_limbs_range_constraint_tail_shift.to_owned() * micro_limb_shiftx4
            + accumulator_high_limbs_range_constraint_tail_shift.to_owned() * micro_limb_shiftx5)
            - relation_wide_limbs;
        tmp_21 *= lagrange_even_in_minicircuit;
        tmp_21 *= scaling_factor;
        for i in 0..univariate_accumulator.r20.evaluations.len() {
            univariate_accumulator.r20.evaluations[i] += tmp_21.evaluations[i];
        }

        // Contribution 22 , decomposition of high relation limb
        let mut tmp_22 = (relation_wide_limbs_range_constraint_1_shift.to_owned()
            * micro_limb_shift
            + relation_wide_limbs_range_constraint_0_shift
            + relation_wide_limbs_range_constraint_2_shift.to_owned() * micro_limb_shiftx2
            + relation_wide_limbs_range_constraint_3_shift.to_owned() * micro_limb_shiftx3
            + p_y_high_limbs_range_constraint_tail_shift.to_owned() * micro_limb_shiftx4
            + quotient_high_limbs_range_constraint_tail_shift.to_owned() * micro_limb_shiftx5)
            - relation_wide_limbs_shift;
        tmp_22 *= lagrange_even_in_minicircuit;
        tmp_22 *= scaling_factor;
        for i in 0..univariate_accumulator.r21.evaluations.len() {
            univariate_accumulator.r21.evaluations[i] += tmp_22.evaluations[i];
        }

        // Contributions enfocing a reduced range constraint on high limbs (these relation force the last microlimb in
        // each limb to be more severely range constrained)

        // Contribution 23, range constrain the highest microlimb of lowest P.x limb to be 12 bits (68 % 14 = 12)
        let mut tmp_23 = p_x_low_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - p_x_low_limbs_range_constraint_tail;
        tmp_23 *= lagrange_even_in_minicircuit;
        tmp_23 *= scaling_factor;
        for i in 0..univariate_accumulator.r22.evaluations.len() {
            univariate_accumulator.r22.evaluations[i] += tmp_23.evaluations[i];
        }

        // Contribution 24, range constrain the highest microlimb of second lowest P.x limb to be 12 bits
        let mut tmp_24 = p_x_low_limbs_range_constraint_4_shift.to_owned() * shift_12_to_14
            - p_x_low_limbs_range_constraint_tail_shift;
        tmp_24 *= lagrange_even_in_minicircuit;
        tmp_24 *= scaling_factor;
        for i in 0..univariate_accumulator.r23.evaluations.len() {
            univariate_accumulator.r23.evaluations[i] += tmp_24.evaluations[i];
        }

        // Contribution 25, range constrain the highest microlimb of second highest P.x limb to be 12 bits
        let mut tmp_25 = p_x_high_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - p_x_high_limbs_range_constraint_tail;
        tmp_25 *= lagrange_even_in_minicircuit;
        tmp_25 *= scaling_factor;
        for i in 0..univariate_accumulator.r24.evaluations.len() {
            univariate_accumulator.r24.evaluations[i] += tmp_25.evaluations[i];
        }

        // Contribution 26, range constrain the highest microilmb of highest P.x limb to be 8 bits (50 % 14 = 8)
        let mut tmp_26 = p_x_high_limbs_range_constraint_3_shift.to_owned() * shift_8_to_14
            - p_x_high_limbs_range_constraint_4_shift;

        tmp_26 *= lagrange_even_in_minicircuit;
        tmp_26 *= scaling_factor;
        for i in 0..univariate_accumulator.r25.evaluations.len() {
            univariate_accumulator.r25.evaluations[i] += tmp_26.evaluations[i];
        }

        // Contribution 27, range constrain the highest microlimb of lowest P.y limb to be 12 bits (68 % 14 = 12)
        let mut tmp_27 = p_y_low_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - p_y_low_limbs_range_constraint_tail;
        tmp_27 *= lagrange_even_in_minicircuit;
        tmp_27 *= scaling_factor;
        for i in 0..univariate_accumulator.r26.evaluations.len() {
            univariate_accumulator.r26.evaluations[i] += tmp_27.evaluations[i];
        }

        // Contribution 28, range constrain the highest microlimb of second lowest P.y limb to be 12 bits (68 % 14 = 12)
        let mut tmp_28 = p_y_low_limbs_range_constraint_4_shift.to_owned() * shift_12_to_14
            - p_y_low_limbs_range_constraint_tail_shift;
        tmp_28 *= lagrange_even_in_minicircuit;
        tmp_28 *= scaling_factor;
        for i in 0..univariate_accumulator.r27.evaluations.len() {
            univariate_accumulator.r27.evaluations[i] += tmp_28.evaluations[i];
        }

        // Contribution 29, range constrain the highest microlimb of second highest P.y limb to be 12 bits (68 % 14 =
        // 12)
        let mut tmp_29 = p_y_high_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - p_y_high_limbs_range_constraint_tail;
        tmp_29 *= lagrange_even_in_minicircuit;
        tmp_29 *= scaling_factor;
        for i in 0..univariate_accumulator.r28.evaluations.len() {
            univariate_accumulator.r28.evaluations[i] += tmp_29.evaluations[i];
        }

        // Contribution 30, range constrain the highest microlimb of highest P.y limb to be 8 bits (50 % 14 = 8)
        let mut tmp_30 = p_y_high_limbs_range_constraint_3_shift.to_owned() * shift_8_to_14
            - p_y_high_limbs_range_constraint_4_shift;
        tmp_30 *= lagrange_even_in_minicircuit;
        tmp_30 *= scaling_factor;
        for i in 0..univariate_accumulator.r29.evaluations.len() {
            univariate_accumulator.r29.evaluations[i] += tmp_30.evaluations[i];
        }

        // Contribution 31, range constrain the highest microlimb of low z1 limb to be 12 bits (68 % 14 = 12)
        let mut tmp_31 = z_low_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - z_low_limbs_range_constraint_tail;
        tmp_31 *= lagrange_even_in_minicircuit;
        tmp_31 *= scaling_factor;
        for i in 0..univariate_accumulator.r30.evaluations.len() {
            univariate_accumulator.r30.evaluations[i] += tmp_31.evaluations[i];
        }

        // Contribution 32, range constrain the highest microlimb of low z2 limb to be 12 bits (68 % 14 = 12)
        let mut tmp_32 = z_low_limbs_range_constraint_4_shift.to_owned() * shift_12_to_14
            - z_low_limbs_range_constraint_tail_shift;
        tmp_32 *= lagrange_even_in_minicircuit;
        tmp_32 *= scaling_factor;
        for i in 0..univariate_accumulator.r31.evaluations.len() {
            univariate_accumulator.r31.evaluations[i] += tmp_32.evaluations[i];
        }

        // Contribution 33, range constrain the highest microlimb of high z1 limb to be 4 bits (60 % 14 = 12)
        let mut tmp_33 = z_high_limbs_range_constraint_4.to_owned() * shift_4_to_14
            - z_high_limbs_range_constraint_tail;
        tmp_33 *= lagrange_even_in_minicircuit;
        tmp_33 *= scaling_factor;
        for i in 0..univariate_accumulator.r32.evaluations.len() {
            univariate_accumulator.r32.evaluations[i] += tmp_33.evaluations[i];
        }

        // Contribution 34, range constrain the highest microlimb of high z2 limb to be 4 bits (60 % 14 = 12)
        let mut tmp_34 = z_high_limbs_range_constraint_4_shift.to_owned() * shift_4_to_14
            - z_high_limbs_range_constraint_tail_shift;
        tmp_34 *= lagrange_even_in_minicircuit;
        tmp_34 *= scaling_factor;
        for i in 0..univariate_accumulator.r33.evaluations.len() {
            univariate_accumulator.r33.evaluations[i] += tmp_34.evaluations[i];
        }

        // Contribution 35, range constrain the highest microlimb of lowest current accumulator limb to be 12 bits (68 %
        // 14 = 12)
        let mut tmp_35 = accumulator_low_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - accumulator_low_limbs_range_constraint_tail;
        tmp_35 *= lagrange_even_in_minicircuit;
        tmp_35 *= scaling_factor;
        for i in 0..univariate_accumulator.r34.evaluations.len() {
            univariate_accumulator.r34.evaluations[i] += tmp_35.evaluations[i];
        }

        // Contribution 36, range constrain the highest microlimb of second lowest current accumulator limb to be 12
        // bits (68 % 14 = 12)
        let mut tmp_36 = accumulator_low_limbs_range_constraint_4_shift.to_owned() * shift_12_to_14
            - accumulator_low_limbs_range_constraint_tail_shift;
        tmp_36 *= lagrange_even_in_minicircuit;
        tmp_36 *= scaling_factor;
        for i in 0..univariate_accumulator.r35.evaluations.len() {
            univariate_accumulator.r35.evaluations[i] += tmp_36.evaluations[i];
        }

        // Contribution 37, range constrain the highest microlimb of second highest current accumulator limb to be 12
        // bits (68 % 14 = 12)
        let mut tmp_37 = accumulator_high_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - accumulator_high_limbs_range_constraint_tail;
        tmp_37 *= lagrange_even_in_minicircuit;
        tmp_37 *= scaling_factor;
        for i in 0..univariate_accumulator.r36.evaluations.len() {
            univariate_accumulator.r36.evaluations[i] += tmp_37.evaluations[i];
        }

        // Contribution 38, range constrain the highest microlimb of highest current accumulator limb to be 8 bits (50 %
        // 14 = 12)
        let mut tmp_38 = accumulator_high_limbs_range_constraint_3_shift.to_owned() * shift_8_to_14
            - accumulator_high_limbs_range_constraint_4_shift;
        tmp_38 *= lagrange_even_in_minicircuit;
        tmp_38 *= scaling_factor;
        for i in 0..univariate_accumulator.r37.evaluations.len() {
            univariate_accumulator.r37.evaluations[i] += tmp_38.evaluations[i];
        }

        // Contribution 39, range constrain the highest microlimb of lowest quotient limb to be 12 bits (68 % 14 = 12)
        let mut tmp_39 = quotient_low_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - quotient_low_limbs_range_constraint_tail;
        tmp_39 *= lagrange_even_in_minicircuit;
        tmp_39 *= scaling_factor;
        for i in 0..univariate_accumulator.r38.evaluations.len() {
            univariate_accumulator.r38.evaluations[i] += tmp_39.evaluations[i];
        }

        // Contribution 40, range constrain the highest microlimb of second lowest quotient limb to be 12 bits (68 % 14
        // = 12)
        let mut tmp_40 = quotient_low_limbs_range_constraint_4_shift.to_owned() * shift_12_to_14
            - quotient_low_limbs_range_constraint_tail_shift;
        tmp_40 *= lagrange_even_in_minicircuit;
        tmp_40 *= scaling_factor;
        for i in 0..univariate_accumulator.r39.evaluations.len() {
            univariate_accumulator.r39.evaluations[i] += tmp_40.evaluations[i];
        }

        // Contribution 41, range constrain the highest microlimb of second highest quotient limb to be 12 bits (68 % 14
        // = 12)
        let mut tmp_41 = quotient_high_limbs_range_constraint_4.to_owned() * shift_12_to_14
            - quotient_high_limbs_range_constraint_tail;
        tmp_41 *= lagrange_even_in_minicircuit;
        tmp_41 *= scaling_factor;
        for i in 0..univariate_accumulator.r40.evaluations.len() {
            univariate_accumulator.r40.evaluations[i] += tmp_41.evaluations[i];
        }

        // Contribution 42, range constrain the highest microlimb of highest quotient limb to be 10 bits (52 % 14 = 12)
        let mut tmp_42 = quotient_high_limbs_range_constraint_3_shift.to_owned() * shift_10_to_14
            - quotient_high_limbs_range_constraint_4_shift;
        tmp_42 *= lagrange_even_in_minicircuit;
        tmp_42 *= scaling_factor;
        for i in 0..univariate_accumulator.r41.evaluations.len() {
            univariate_accumulator.r41.evaluations[i] += tmp_42.evaluations[i];
        }

        // Contributions where we decompose initial EccOpQueue values into 68-bit limbs

        // Contribution 43, decompose x_lo
        let mut tmp_43 = (p_x_low_limbs_shift.to_owned() * limb_shift + p_x_low_limbs) - x_lo_y_hi;
        tmp_43 *= lagrange_even_in_minicircuit;
        tmp_43 *= scaling_factor;
        for i in 0..univariate_accumulator.r42.evaluations.len() {
            univariate_accumulator.r42.evaluations[i] += tmp_43.evaluations[i];
        }

        // Contribution 44, decompose x_hi
        let mut tmp_44 = (p_x_high_limbs_shift.to_owned() * limb_shift + p_x_high_limbs) - x_hi_z_1;
        tmp_44 *= lagrange_even_in_minicircuit;
        tmp_44 *= scaling_factor;
        for i in 0..univariate_accumulator.r43.evaluations.len() {
            univariate_accumulator.r43.evaluations[i] += tmp_44.evaluations[i];
        }
        // Contribution 45, decompose y_lo
        let mut tmp_45 = (p_y_low_limbs_shift.to_owned() * limb_shift + p_y_low_limbs) - y_lo_z_2;
        tmp_45 *= lagrange_even_in_minicircuit;
        tmp_45 *= scaling_factor;
        for i in 0..univariate_accumulator.r44.evaluations.len() {
            univariate_accumulator.r44.evaluations[i] += tmp_45.evaluations[i];
        }

        // Contribution 46, decompose y_hi
        let mut tmp_46 =
            (p_y_high_limbs_shift.to_owned() * limb_shift + p_y_high_limbs) - x_lo_y_hi_shift;
        tmp_46 *= lagrange_even_in_minicircuit;
        tmp_46 *= scaling_factor;
        for i in 0..univariate_accumulator.r45.evaluations.len() {
            univariate_accumulator.r45.evaluations[i] += tmp_46.evaluations[i];
        }

        // Contribution 47, decompose z1
        let mut tmp_47 = (z_high_limbs.to_owned() * limb_shift + z_low_limbs) - x_hi_z_1_shift;
        tmp_47 *= lagrange_even_in_minicircuit;
        tmp_47 *= scaling_factor;
        for i in 0..univariate_accumulator.r46.evaluations.len() {
            univariate_accumulator.r46.evaluations[i] += tmp_47.evaluations[i];
        }

        // Contribution 48, decompose z2
        let mut tmp_48 =
            (z_high_limbs_shift.to_owned() * limb_shift + z_low_limbs_shift) - y_lo_z_2_shift;
        tmp_48 *= lagrange_even_in_minicircuit;
        tmp_48 *= scaling_factor;
        for i in 0..univariate_accumulator.r47.evaluations.len() {
            univariate_accumulator.r47.evaluations[i] += tmp_48.evaluations[i];
        }
    }
}
