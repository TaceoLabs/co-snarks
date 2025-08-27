use crate::plain_prover_flavour::UnivariateTrait;
use crate::prelude::Univariate;
use ark_ec::AffineRepr;
use ark_ff::One;
use ark_ff::PrimeField;
use co_builder::prelude::offset_generator_scaled;
use co_builder::{
    flavours::eccvm_flavour::ECCVMFlavour,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour, prelude::HonkCurve,
};
use common::transcript::TranscriptFieldType;

#[derive(Clone, Debug, Default)]
pub(crate) struct EccTranscriptRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 8>,
    pub(crate) r1: Univariate<F, 8>,
    pub(crate) r2: Univariate<F, 8>,
    pub(crate) r3: Univariate<F, 8>,
    pub(crate) r4: Univariate<F, 8>,
    pub(crate) r5: Univariate<F, 8>,
    pub(crate) r6: Univariate<F, 8>,
    pub(crate) r7: Univariate<F, 8>,
    pub(crate) r8: Univariate<F, 8>,
    pub(crate) r9: Univariate<F, 8>,
    pub(crate) r10: Univariate<F, 8>,
    pub(crate) r11: Univariate<F, 8>,
    pub(crate) r12: Univariate<F, 8>,
    pub(crate) r13: Univariate<F, 8>,
    pub(crate) r14: Univariate<F, 8>,
    pub(crate) r15: Univariate<F, 8>,
    pub(crate) r16: Univariate<F, 8>,
    pub(crate) r17: Univariate<F, 8>,
    pub(crate) r18: Univariate<F, 8>,
    pub(crate) r19: Univariate<F, 8>,
    pub(crate) r20: Univariate<F, 8>,
    pub(crate) r21: Univariate<F, 8>,
    pub(crate) r22: Univariate<F, 8>,
    pub(crate) r23: Univariate<F, 8>,
    pub(crate) r24: Univariate<F, 8>,
}
#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct EccTranscriptRelationEvals<F: PrimeField> {
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
}

pub(crate) struct EccTranscriptRelation {}

impl<F: PrimeField> EccTranscriptRelationAcc<F> {
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
    }
}

impl EccTranscriptRelation {
    pub(crate) const NUM_RELATIONS: usize = 25;
    pub(crate) const SKIPPABLE: bool = false;

    pub(crate) fn skip<F: PrimeField, const SIZE: usize>(
        _input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> bool {
        false
    }

    pub(crate) fn accumulate<P: HonkCurve<TranscriptFieldType>, const SIZE: usize>(
        univariate_accumulator: &mut EccTranscriptRelationAcc<P::ScalarField>,
        input: &crate::decider::types::ProverUnivariatesSized<P::ScalarField, ECCVMFlavour, SIZE>,
        _relation_parameters: &crate::prelude::RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        let result = offset_generator_scaled::<P::CycleGroup>();

        let ox = result
            .x()
            .expect("Offset generator x coordinate should not be None");
        let oy = result
            .y()
            .expect("Offset generator y coordinate should not be None");

        let z1 = input.witness.transcript_z1();
        let z2 = input.witness.transcript_z2();
        let z1_zero = input.witness.transcript_z1zero();
        let z2_zero = input.witness.transcript_z2zero();
        let op = input.witness.transcript_op();
        let q_add = input.witness.transcript_add();
        let q_mul = input.witness.transcript_mul();
        let q_mul_shift = input.shifted_witness.transcript_mul_shift();
        let q_eq = input.witness.transcript_eq();
        let msm_transition = input.witness.transcript_msm_transition();
        let msm_count = input.witness.transcript_msm_count();
        let msm_count_shift = input.shifted_witness.transcript_msm_count_shift();
        let pc = input.witness.transcript_pc();
        let pc_shift = input.shifted_witness.transcript_pc_shift();
        let transcript_accumulator_x_shift = input.shifted_witness.transcript_accumulator_x_shift();
        let transcript_accumulator_y_shift = input.shifted_witness.transcript_accumulator_y_shift();
        let transcript_accumulator_x = input.witness.transcript_accumulator_x();
        let transcript_accumulator_y = input.witness.transcript_accumulator_y();
        let transcript_msm_x = input.witness.transcript_msm_intermediate_x();
        let transcript_msm_y = input.witness.transcript_msm_intermediate_y();
        let transcript_px = input.witness.transcript_px();
        let transcript_py = input.witness.transcript_py();
        let is_accumulator_empty = input.witness.transcript_accumulator_empty();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();
        let is_accumulator_empty_shift = input.shifted_witness.transcript_accumulator_empty_shift();
        let q_reset_accumulator = input.witness.transcript_reset_accumulator();
        let lagrange_second = input.precomputed.lagrange_second();
        let transcript_pinfinity = input.witness.transcript_base_infinity();
        let transcript_px_inverse = input.witness.transcript_base_x_inverse();
        let transcript_py_inverse = input.witness.transcript_base_y_inverse();
        let transcript_add_x_equal = input.witness.transcript_add_x_equal();
        let transcript_add_y_equal = input.witness.transcript_add_y_equal();
        let transcript_add_lambda = input.witness.transcript_add_lambda();
        let transcript_msm_infinity = input.witness.transcript_msm_infinity();

        let minus_one = P::ScalarField::from(-1);
        let is_not_first_row = lagrange_first.to_owned() * minus_one + &P::ScalarField::one();
        let is_not_last_row = lagrange_last.to_owned() * minus_one + &P::ScalarField::one();
        let is_not_first_or_last_row = lagrange_first.to_owned() * minus_one
            + lagrange_last.to_owned() * minus_one
            + &P::ScalarField::one();
        let is_not_infinity = transcript_pinfinity.to_owned() * minus_one + &P::ScalarField::one();
        /*
         * @brief Validate correctness of z1_zero, z2_zero.
         * If z1_zero = 0 and operation is a MUL, we will write a scalar mul instruction into our multiplication table.
         * If z1_zero = 1 and operation is a MUL, we will NOT write a scalar mul instruction.
         * (same with z2_zero).
         * z1_zero / z2_zero is user-defined.
         * We constraint z1_zero such that if z1_zero == 1, we require z1 == 0. (same for z2_zero).
         * We do *NOT* constrain z1 != 0 if z1_zero = 0. If the user sets z1_zero = 0 and z1 = 0,
         * this will add a scalar mul instruction into the multiplication table, where the scalar multiplier is 0.
         * This is inefficient but will still produce the correct output.
         */
        let tmp = (z1.to_owned() * z1_zero) * scaling_factor; // if z1_zero = 1, z1 must be 0. degree 2
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = (z2.to_owned() * z2_zero) * scaling_factor; // degree 2
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `op` opcode is well formed.
         * `op` is defined to be q_reset_accumulator + 2 * q_eq + 4 * q_mul + 8 * q_add,
         * where q_reset_accumulator, q_eq, q_mul, q_add are all boolean
         * (TODO: bool constrain these efficiently #2223)
         */
        let mut tmp = q_add.to_owned() * P::ScalarField::from(2);
        tmp += q_mul;
        tmp += tmp.clone();
        tmp += q_eq;
        tmp += tmp.clone();
        tmp += q_reset_accumulator;
        tmp = (tmp.clone() - op) * scaling_factor; // degree 1
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `pc` is updated correctly.
         * pc stands for Point Counter. It decrements by 1 for every 128-bit multiplication operation.
         * If q_mul = 1, pc decrements by !z1_zero + !z2_zero, else pc decrements by 0
         * @note pc starts out at its max value and decrements down to 0. This keeps the degree of the pc polynomial smol
         */
        let pc_delta = pc_shift.to_owned() * minus_one + pc;
        let num_muls_in_row = ((z1_zero.to_owned() * minus_one + &P::ScalarField::one())
            + (z2_zero.to_owned() * minus_one + &P::ScalarField::one()))
            * (transcript_pinfinity.to_owned() * minus_one + &P::ScalarField::one());
        let tmp = (q_mul.to_owned() * minus_one * num_muls_in_row.clone() + pc_delta)
            * scaling_factor
            * is_not_first_row.clone(); // degree 4
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `msm_transition` is well-formed.
         *
         * If the current row is the last mul instruction in a multiscalar multiplication, msm_transition = 1.
         * i.e. if q_mul == 1 and q_mul_shift == 0, msm_transition = 1, else is 0
         * We also require that `msm_count + [current msm number] > 0`
         */
        let msm_transition_check =
            (q_mul_shift.to_owned() * minus_one + &P::ScalarField::one()) * q_mul; // degree 2
        // let num_muls_total = msm_count + num_muls_in_row;
        let msm_count_zero_at_transition = input.witness.transcript_msm_count_zero_at_transition();
        let msm_count_at_transition_inverse =
            input.witness.transcript_msm_count_at_transition_inverse();

        let msm_count_total = msm_count.to_owned() + num_muls_in_row; // degree 3

        let mut msm_count_zero_at_transition_check =
            msm_count_zero_at_transition.to_owned() * msm_count_total.clone();
        msm_count_zero_at_transition_check += (msm_count_total * msm_count_at_transition_inverse
            - 1)
            * (msm_count_zero_at_transition.to_owned() * minus_one + &P::ScalarField::one());
        let tmp =
            msm_transition_check.to_owned() * msm_count_zero_at_transition_check * scaling_factor; // degree 3
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }

        // Validate msm_transition_msm_count is correct
        // ensure msm_transition is zero if count is zero

        let tmp = ((msm_count_zero_at_transition.to_owned() * minus_one + &P::ScalarField::one())
            * msm_transition_check
            * minus_one
            + msm_transition)
            * scaling_factor; // degree 3
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `msm_count` resets when we end a multiscalar multiplication.
         * msm_count tracks the number of scalar muls in the current active multiscalar multiplication.
         * (if no msm active, msm_count == 0)
         * If current row ends an MSM, `msm_count_shift = 0` (msm_count value at next row)
         */
        let tmp = (msm_transition.to_owned() * msm_count_shift) * scaling_factor; // degree 2
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `msm_count` updates correctly for mul operations.
         * msm_count updates by (!z1_zero + !z2_zero) if current op is a mul instruction (and msm is not terminating at next
         * row).
         */
        let msm_count_delta = msm_count.to_owned() * minus_one + msm_count_shift; // degree 4
        let num_counts = ((z1_zero.to_owned() * minus_one + &P::ScalarField::one())
            + (z2_zero.to_owned() * minus_one + &P::ScalarField::one()))
            * (transcript_pinfinity.to_owned() * minus_one + &P::ScalarField::one());
        let tmp = (msm_transition.to_owned() * minus_one + &P::ScalarField::one())
            * is_not_first_row.clone()
            * (q_mul.to_owned() * minus_one * (num_counts) + msm_count_delta)
            * scaling_factor;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Opcode exclusion tests. We have the following assertions:
         * 1. If q_mul = 1, (q_add, eq, reset) are zero
         * 2. If q_add = 1, (q_mul, eq, reset) are zero
         * 3. If q_eq =  1, (q_add, q_mul) are zero (is established by previous 2 checks)
         */
        let mut opcode_exclusion_relation = (q_add.to_owned() + q_eq + q_reset_accumulator) * q_mul;
        opcode_exclusion_relation += (q_mul.to_owned() + q_eq + q_reset_accumulator) * q_add;
        let tmp = opcode_exclusion_relation * scaling_factor; // degree 2
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief `eq` opcode.
         * Let lhs = transcript_P and rhs = transcript_accumulator
         * If eq = 1, we must validate the following cases:
         * IF lhs and rhs are not at infinity THEN lhs == rhs
         * ELSE lhs and rhs are BOTH points at infinity
         **/
        let both_infinity = transcript_pinfinity.to_owned() * is_accumulator_empty;
        let both_not_infinity = (transcript_pinfinity.to_owned() * minus_one
            + &P::ScalarField::one())
            * (is_accumulator_empty.to_owned() * minus_one + &P::ScalarField::one());
        let infinity_exclusion_check = transcript_pinfinity.to_owned() + is_accumulator_empty
            - both_infinity.clone()
            - both_infinity;
        let eq_x_diff = transcript_accumulator_x.to_owned() * minus_one + transcript_px;
        let eq_y_diff = transcript_accumulator_y.to_owned() * minus_one + transcript_py;
        let eq_x_diff_relation = (eq_x_diff.to_owned() * both_not_infinity.clone()
            + infinity_exclusion_check.clone())
            * q_eq; // degree 4
        let eq_y_diff_relation =
            (eq_y_diff.to_owned() * both_not_infinity + infinity_exclusion_check) * q_eq; // degree 4
        let tmp = eq_x_diff_relation * scaling_factor; // degree 4
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = eq_y_diff_relation * scaling_factor; // degree 4
        for i in 0..univariate_accumulator.r10.evaluations.len() {
            univariate_accumulator.r10.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Initial condition check on 1st row.
         * We require the following values are 0 on 1st row:
         * is_accumulator_empty = 1
         * msm_count = 0
         * note...actually second row? bleurgh
         * NOTE: we want pc = 0 at lagrange_last :o
         */
        let tmp = (is_accumulator_empty.to_owned() * minus_one + &P::ScalarField::one())
            * lagrange_second
            * scaling_factor; // degree 2
        for i in 0..univariate_accumulator.r11.evaluations.len() {
            univariate_accumulator.r11.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = lagrange_second.to_owned() * msm_count * scaling_factor; // degree 2
        for i in 0..univariate_accumulator.r12.evaluations.len() {
            univariate_accumulator.r12.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief On-curve validation checks.
         * If q_mul = 1 OR q_add = 1 OR q_eq = 1, require (transcript_Px, transcript_Py) is valid ecc point
         * q_mul/q_add/q_eq mutually exclusive, can represent as sum of 3
         */
        let validate_on_curve = q_add.to_owned() + q_mul + q_eq;
        let on_curve_check = transcript_py.to_owned() * transcript_py
            + transcript_px.to_owned() * minus_one * transcript_px * transcript_px
            + &(P::get_curve_b() * minus_one);
        let tmp = validate_on_curve * on_curve_check * is_not_infinity * scaling_factor; // degree 6
        for i in 0..univariate_accumulator.r13.evaluations.len() {
            univariate_accumulator.r13.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate relations from ECC Group Operations are well formed
         *
         */

        let is_double = transcript_add_x_equal.to_owned() * transcript_add_y_equal;
        let is_add = transcript_add_x_equal.to_owned() * minus_one + &P::ScalarField::one();
        let add_result_is_infinity = (transcript_add_y_equal.to_owned() * minus_one
            + &P::ScalarField::one())
            * transcript_add_x_equal; // degree 2
        let rhs_x = transcript_accumulator_x;
        let rhs_y = transcript_accumulator_y;
        let out_x = transcript_accumulator_x_shift;
        let out_y = transcript_accumulator_y_shift;
        let lambda = transcript_add_lambda;
        let lhs_x = transcript_px.to_owned() * q_add + transcript_msm_x.to_owned() * msm_transition;
        let lhs_y = transcript_py.to_owned() * q_add + transcript_msm_y.to_owned() * msm_transition;
        let lhs_infinity = transcript_pinfinity.to_owned() * q_add
            + transcript_msm_infinity.to_owned() * msm_transition;
        let rhs_infinity = is_accumulator_empty;
        let result_is_lhs =
            (lhs_infinity.to_owned() * minus_one + &P::ScalarField::one()) * rhs_infinity; // degree 2
        let result_is_rhs =
            (rhs_infinity.to_owned() * minus_one + &P::ScalarField::one()) * lhs_infinity.clone(); // degree 2
        let result_infinity_from_inputs = lhs_infinity * rhs_infinity; // degree 2
        let result_infinity_from_operation = (transcript_add_y_equal.to_owned() * minus_one
            + &P::ScalarField::one())
            * transcript_add_x_equal; // degree 2
        // infinity_from_inputs and infinity_from_operation mutually exclusive so we can perform an OR by adding
        // (mutually exclusive because if result_infinity_from_inputs then transcript_add_y_equal = 1 (both y are 0)
        let result_is_infinity = result_infinity_from_inputs + result_infinity_from_operation; // degree 2
        let any_add_is_active = q_add.to_owned() + msm_transition;

        // Valdiate `transcript_add_lambda` is well formed if we are adding msm output into accumulator

        let msm_x = transcript_msm_x;
        let msm_y = transcript_msm_y;
        let mut transcript_msm_lambda_relation = Univariate::<P::ScalarField, SIZE>::default();
        // Group operation is point addition

        let lambda_denominator = msm_x.to_owned() * minus_one + rhs_x;
        let lambda_numerator = msm_y.to_owned() * minus_one + rhs_y;
        let lambda_relation = lambda_denominator * lambda + lambda_numerator.to_owned() * minus_one; // degree 2
        transcript_msm_lambda_relation += lambda_relation * is_add.clone(); // degree 3

        // Group operation is point doubling

        let lambda_denominator = msm_y.to_owned() + msm_y;
        let lambda_numerator = msm_x.to_owned() * msm_x * P::ScalarField::from(3);
        let lambda_relation = lambda_denominator * lambda + lambda_numerator.to_owned() * minus_one; // degree 2
        transcript_msm_lambda_relation += lambda_relation * is_double.clone(); // degree 4

        let transcript_add_or_dbl_from_msm_output_is_valid =
            (transcript_msm_infinity.to_owned() * minus_one + &P::ScalarField::one())
                * (is_accumulator_empty.to_owned() * minus_one + &P::ScalarField::one()); // degree 2
        transcript_msm_lambda_relation *= transcript_add_or_dbl_from_msm_output_is_valid; // degree 6
        // No group operation because of points at infinity

        let lambda_relation_invalid = transcript_msm_infinity.to_owned()
            + is_accumulator_empty
            + add_result_is_infinity.clone(); // degree 2
        let lambda_relation = lambda_relation_invalid * lambda; // degree 4
        transcript_msm_lambda_relation += lambda_relation; // (still degree 6)

        let mut transcript_lambda_relation = transcript_msm_lambda_relation * msm_transition; // degree 7

        // Valdiate `transcript_add_lambda` is well formed if we are adding base point into accumulator

        let mut transcript_add_lambda_relation = Univariate::<P::ScalarField, SIZE>::default();
        let add_x = transcript_px;
        let add_y = transcript_py;
        // Group operation is point addition

        let lambda_denominator = add_x.to_owned() * minus_one + rhs_x;
        let lambda_numerator = add_y.to_owned() * minus_one + rhs_y;
        let lambda_relation = lambda_denominator * lambda + lambda_numerator.to_owned() * minus_one; // degree 2
        transcript_add_lambda_relation += lambda_relation * is_add; // degree 3

        // Group operation is point doubling

        let lambda_denominator = add_y.to_owned() + add_y;
        let lambda_numerator = add_x.to_owned() * add_x * P::ScalarField::from(3);
        let lambda_relation = lambda_denominator * lambda + lambda_numerator.to_owned() * minus_one; // degree 2
        transcript_add_lambda_relation += lambda_relation * is_double; // degree 4

        let transcript_add_or_dbl_from_add_output_is_valid =
            (transcript_pinfinity.to_owned() * minus_one + &P::ScalarField::one())
                * (is_accumulator_empty.to_owned() * minus_one + &P::ScalarField::one()); // degree 2
        transcript_add_lambda_relation *= transcript_add_or_dbl_from_add_output_is_valid; // degree 6
        // No group operation because of points at infinity

        let lambda_relation_invalid =
            transcript_pinfinity.to_owned() + is_accumulator_empty + add_result_is_infinity; // degree 2
        let lambda_relation = lambda.to_owned() * lambda_relation_invalid; // degree 4
        transcript_add_lambda_relation += lambda_relation; // (still degree 6)

        transcript_lambda_relation += transcript_add_lambda_relation * q_add;
        let tmp = transcript_lambda_relation * scaling_factor; // degree 7
        for i in 0..univariate_accumulator.r14.evaluations.len() {
            univariate_accumulator.r14.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate transcript_accumulator_x_shift / transcript_accumulator_y_shift are well formed.
         *        Conditions (one of the following):
         *        1. The result of a group operation involving transcript_accumulator and msm_output (q_add = 1)
         *        2. The result of a group operation involving transcript_accumulator and transcript_P (msm_transition =
         * 1)
         *        3. Is equal to transcript_accumulator (no group operation, no reset)
         *        4. Is 0 (reset)
         */

        let lambda_sqr = lambda.to_owned().sqr();
        // add relation that validates result_infinity_from_operation * result_is_infinity = 0

        // N.B. these relations rely on the fact that `lambda = 0` if we are not evaluating add/double formula
        // (i.e. one or both outputs are points at infinity, or produce a point at infinity)
        // This should be validated by the lambda_relation
        let mut x3 = (lambda_sqr - &lhs_x) - rhs_x; // degree 2
        x3 += result_is_lhs.clone() * (rhs_x.to_owned() + &lhs_x + &lhs_x); // degree 4
        x3 += result_is_rhs.clone() * (lhs_x.to_owned() + rhs_x + rhs_x); // degree 4
        x3 += (lhs_x.to_owned() + rhs_x) * &result_is_infinity; // degree 4
        let mut y3 = lambda.to_owned() * (lhs_x.clone() - out_x) - &lhs_y; // degree 3
        y3 += result_is_lhs * (lhs_y.clone() + &lhs_y); // degree 4
        y3 += result_is_rhs * (lhs_y.clone() + rhs_y); // degree 4
        y3 += lhs_y.clone() * &result_is_infinity; // degree 4

        let propagate_transcript_accumulator =
            q_add.to_owned() * minus_one - msm_transition - q_reset_accumulator
                + &P::ScalarField::one();
        let mut add_point_x_relation = (x3 - out_x) * &any_add_is_active; // degree 5

        add_point_x_relation += (out_x.to_owned() - transcript_accumulator_x)
            * &propagate_transcript_accumulator
            * &is_not_last_row;

        // validate out_x = 0 if q_reset_accumulator = 1
        add_point_x_relation += out_x.to_owned() * q_reset_accumulator;
        let mut add_point_y_relation = (y3 - out_y) * &any_add_is_active; // degree 5
        add_point_y_relation += propagate_transcript_accumulator
            * is_not_last_row
            * (out_y.to_owned() - transcript_accumulator_y);

        // validate out_y = 0 if q_reset_accumulator = 1
        add_point_y_relation += out_y.to_owned() * q_reset_accumulator;
        let tmp = add_point_x_relation * scaling_factor; // degree 5
        for i in 0..univariate_accumulator.r15.evaluations.len() {
            univariate_accumulator.r15.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = add_point_y_relation * scaling_factor; // degree 5
        for i in 0..univariate_accumulator.r16.evaluations.len() {
            univariate_accumulator.r16.evaluations[i] += tmp.evaluations[i];
        }

        // step 1: subtract offset generator from msm_accumulator
        // this might produce a point at infinity

        let x1 = ox;
        let y1 = -oy;
        let x2 = input.witness.transcript_msm_x();
        let y2 = input.witness.transcript_msm_y();
        let x3 = input.witness.transcript_msm_intermediate_x();
        let y3 = input.witness.transcript_msm_intermediate_y();
        let transcript_msm_infinity = input.witness.transcript_msm_infinity();
        // cases:
        // x2 == x1, y2 == y1
        // x2 != x1
        // (x2 - x1)
        let x_term = (x3.to_owned() + x2 + &x1) * (x2.to_owned() - &x1) * (x2.to_owned() - &x1)
            - (y2.to_owned() - &y1) * (y2.to_owned() - &y1); // degree 3
        let y_term = (x3.to_owned() * minus_one + &x1) * (y2.to_owned() - &y1)
            - (x2.to_owned() - &x1) * (y3.to_owned() + &y1); // degree 2
        // IF msm_infinity = false, transcript_msm_intermediate_x/y is either the result of subtracting offset
        // generator from msm_x/y IF msm_infinity = true, transcript_msm_intermediate_x/y is 0
        let transcript_offset_generator_subtract_x = x_term
            * (transcript_msm_infinity.to_owned() * minus_one + &P::ScalarField::one())
            + transcript_msm_infinity.to_owned() * x3; // degree 4
        let transcript_offset_generator_subtract_y = y_term
            * (transcript_msm_infinity.to_owned() * minus_one + &P::ScalarField::one())
            + transcript_msm_infinity.to_owned() * y3; // degree 3

        let tmp = transcript_offset_generator_subtract_x * msm_transition * scaling_factor; // degree 5
        for i in 0..univariate_accumulator.r17.evaluations.len() {
            univariate_accumulator.r17.evaluations[i] += tmp.evaluations[i];
        }

        let tmp = transcript_offset_generator_subtract_y * msm_transition * scaling_factor; // degree 5
        for i in 0..univariate_accumulator.r18.evaluations.len() {
            univariate_accumulator.r18.evaluations[i] += tmp.evaluations[i];
        }

        // validate transcript_msm_infinity is correct
        // if transcript_msm_infinity = 1, (x2 == x1) and (y2 + y1 == 0)
        let x_diff = x2.to_owned() - &x1;
        let y_sum = y2.to_owned() + &y1;
        let tmp = x_diff.clone() * msm_transition * transcript_msm_infinity * scaling_factor; // degree 3
        for i in 0..univariate_accumulator.r19.evaluations.len() {
            univariate_accumulator.r19.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = y_sum * msm_transition * transcript_msm_infinity * scaling_factor; // degree 3
        for i in 0..univariate_accumulator.r20.evaluations.len() {
            univariate_accumulator.r20.evaluations[i] += tmp.evaluations[i];
        }
        // if transcript_msm_infinity = 1, then x_diff must have an inverse
        let transcript_msm_x_inverse = input.witness.transcript_msm_x_inverse();
        let inverse_term = (transcript_msm_infinity.to_owned() * minus_one
            + &P::ScalarField::one())
            * (x_diff * transcript_msm_x_inverse - 1);
        let tmp = inverse_term * msm_transition * scaling_factor; // degree 3
        for i in 0..univariate_accumulator.r21.evaluations.len() {
            univariate_accumulator.r21.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `is_accumulator_empty` is updated correctly
         * An add operation can produce a point at infinity
         * Resetting the accumulator produces a point at infinity
         * If we are not adding, performing an msm or resetting the accumulator, is_accumulator_empty should not update
         */
        let accumulator_infinity_preserve_flag =
            -(q_add.to_owned() + msm_transition + q_reset_accumulator) + &P::ScalarField::one(); // degree 1
        let accumulator_infinity_preserve = (is_accumulator_empty.to_owned()
            - is_accumulator_empty_shift)
            * accumulator_infinity_preserve_flag
            * is_not_first_or_last_row; // degree 3
        let accumulator_infinity_q_reset = (is_accumulator_empty_shift.to_owned() * minus_one
            + &P::ScalarField::one())
            * q_reset_accumulator; // degree 2
        let accumulator_infinity_from_add =
            (result_is_infinity - is_accumulator_empty_shift) * &any_add_is_active; // degree 3
        let accumulator_infinity_relation = accumulator_infinity_preserve
            + (accumulator_infinity_q_reset + accumulator_infinity_from_add) * is_not_first_row; // degree 4
        let tmp = accumulator_infinity_relation * scaling_factor; // degree 4
        for i in 0..univariate_accumulator.r22.evaluations.len() {
            univariate_accumulator.r22.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `transcript_add_x_equal` is well-formed
         *        If lhs_x == rhs_x, transcript_add_x_equal = 1
         *        If transcript_add_x_equal = 0, a valid inverse must exist for (lhs_x - rhs_x)
         */
        let x_diff = lhs_x - rhs_x; // degree 2
        let x_product = (transcript_add_x_equal.to_owned() * minus_one + &P::ScalarField::one())
            * transcript_px_inverse
            + transcript_add_x_equal; // degree 2
        let x_constant = transcript_add_x_equal.to_owned() - 1; // degree 1
        let transcript_add_x_equal_check_relation =
            (x_diff * x_product + x_constant) * &any_add_is_active; // degree 5
        let tmp = transcript_add_x_equal_check_relation * scaling_factor; // degree 5
        for i in 0..univariate_accumulator.r23.evaluations.len() {
            univariate_accumulator.r23.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief Validate `transcript_add_y_equal` is well-formed
         *        If lhs_y == rhs_y, transcript_add_y_equal = 1
         *        If transcript_add_y_equal = 0, a valid inverse must exist for (lhs_y - rhs_y)
         */
        let y_diff = lhs_y - rhs_y;
        let y_product = (transcript_add_y_equal.to_owned() * minus_one + &P::ScalarField::one())
            * transcript_py_inverse
            + transcript_add_y_equal;
        let y_constant = transcript_add_y_equal.to_owned() - 1;
        let transcript_add_y_equal_check_relation =
            (y_diff * y_product + y_constant) * &any_add_is_active;
        let tmp = transcript_add_y_equal_check_relation * scaling_factor; // degree 5
        for i in 0..univariate_accumulator.r24.evaluations.len() {
            univariate_accumulator.r24.evaluations[i] += tmp.evaluations[i];
        }
    }
}
