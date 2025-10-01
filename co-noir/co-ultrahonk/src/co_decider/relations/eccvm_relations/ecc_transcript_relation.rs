use crate::co_decider::univariates::SharedUnivariate;
use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::prelude::offset_generator_scaled;
use co_builder::{HonkProofResult, flavours::eccvm_flavour::ECCVMFlavour, prelude::HonkCurve};
use common::{mpc::NoirUltraHonkProver, transcript::TranscriptFieldType};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EccTranscriptRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 8>,
    pub(crate) r1: SharedUnivariate<T, P, 8>,
    pub(crate) r2: SharedUnivariate<T, P, 8>,
    pub(crate) r3: SharedUnivariate<T, P, 8>,
    pub(crate) r4: SharedUnivariate<T, P, 8>,
    pub(crate) r5: SharedUnivariate<T, P, 8>,
    pub(crate) r6: SharedUnivariate<T, P, 8>,
    pub(crate) r7: SharedUnivariate<T, P, 8>,
    pub(crate) r8: SharedUnivariate<T, P, 8>,
    pub(crate) r9: SharedUnivariate<T, P, 8>,
    pub(crate) r10: SharedUnivariate<T, P, 8>,
    pub(crate) r11: SharedUnivariate<T, P, 8>,
    pub(crate) r12: SharedUnivariate<T, P, 8>,
    pub(crate) r13: SharedUnivariate<T, P, 8>,
    pub(crate) r14: SharedUnivariate<T, P, 8>,
    pub(crate) r15: SharedUnivariate<T, P, 8>,
    pub(crate) r16: SharedUnivariate<T, P, 8>,
    pub(crate) r17: SharedUnivariate<T, P, 8>,
    pub(crate) r18: SharedUnivariate<T, P, 8>,
    pub(crate) r19: SharedUnivariate<T, P, 8>,
    pub(crate) r20: SharedUnivariate<T, P, 8>,
    pub(crate) r21: SharedUnivariate<T, P, 8>,
    pub(crate) r22: SharedUnivariate<T, P, 8>,
    pub(crate) r23: SharedUnivariate<T, P, 8>,
    pub(crate) r24: SharedUnivariate<T, P, 8>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccTranscriptRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
            r2: SharedUnivariate::default(),
            r3: SharedUnivariate::default(),
            r4: SharedUnivariate::default(),
            r5: SharedUnivariate::default(),
            r6: SharedUnivariate::default(),
            r7: SharedUnivariate::default(),
            r8: SharedUnivariate::default(),
            r9: SharedUnivariate::default(),
            r10: SharedUnivariate::default(),
            r11: SharedUnivariate::default(),
            r12: SharedUnivariate::default(),
            r13: SharedUnivariate::default(),
            r14: SharedUnivariate::default(),
            r15: SharedUnivariate::default(),
            r16: SharedUnivariate::default(),
            r17: SharedUnivariate::default(),
            r18: SharedUnivariate::default(),
            r19: SharedUnivariate::default(),
            r20: SharedUnivariate::default(),
            r21: SharedUnivariate::default(),
            r22: SharedUnivariate::default(),
            r23: SharedUnivariate::default(),
            r24: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct EccTranscriptRelation {}

impl EccTranscriptRelation {
    pub(crate) const NUM_RELATIONS: usize = 25;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 96;
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccTranscriptRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r1.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r2.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r3.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r4.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r5.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r6.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r7.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r8.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r9.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r10.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r11.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r12.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r13.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r14.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r15.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r16.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r17.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r18.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r19.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r20.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r21.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r22.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r23.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r24.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut SharedUnivariate<T, P, SIZE>,
        extended_random_poly: &Univariate<P::ScalarField, SIZE>,
        partial_evaluation_result: &P::ScalarField,
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

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccTranscriptRelation
{
    type Acc = EccTranscriptRelationAcc<T, P>;
    type VerifyAcc = (); // Not need for ECCVM

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_transcript_z1(entity);
        batch.add_transcript_z2(entity);
        batch.add_transcript_z1zero(entity);
        batch.add_transcript_z2zero(entity);
        batch.add_transcript_op(entity);
        batch.add_transcript_add(entity);
        batch.add_transcript_mul(entity);
        batch.add_transcript_mul_shift(entity);
        batch.add_transcript_eq(entity);
        batch.add_transcript_msm_transition(entity);
        batch.add_transcript_msm_count(entity);
        batch.add_transcript_msm_count_shift(entity);
        batch.add_transcript_pc(entity);
        batch.add_transcript_pc_shift(entity);
        batch.add_transcript_accumulator_x_shift(entity);
        batch.add_transcript_accumulator_y_shift(entity);
        batch.add_transcript_accumulator_x(entity);
        batch.add_transcript_accumulator_y(entity);
        batch.add_transcript_msm_intermediate_x(entity);
        batch.add_transcript_msm_intermediate_y(entity);
        batch.add_transcript_px(entity);
        batch.add_transcript_py(entity);
        batch.add_transcript_accumulator_empty(entity);
        batch.add_lagrange_first(entity);
        batch.add_lagrange_last(entity);
        batch.add_transcript_accumulator_empty_shift(entity);
        batch.add_transcript_reset_accumulator(entity);
        batch.add_lagrange_second(entity);
        batch.add_transcript_base_infinity(entity);
        batch.add_transcript_base_x_inverse(entity);
        batch.add_transcript_base_y_inverse(entity);
        batch.add_transcript_add_x_equal(entity);
        batch.add_transcript_add_y_equal(entity);
        batch.add_transcript_add_lambda(entity);
        batch.add_transcript_msm_infinity(entity);
        batch.add_transcript_msm_count_zero_at_transition(entity);
        batch.add_transcript_msm_count_at_transition_inverse(entity);
        batch.add_transcript_msm_x(entity);
        batch.add_transcript_msm_y(entity);
        batch.add_transcript_msm_x_inverse(entity);
    }

    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let id = state.id();
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
        let one = P::ScalarField::one();
        let mut is_not_first_row = lagrange_first.to_owned();
        is_not_first_row.iter_mut().for_each(|x| {
            *x *= minus_one;
            *x += &P::ScalarField::one()
        });
        let mut is_not_last_row = lagrange_last.to_owned();
        is_not_last_row.iter_mut().for_each(|x| *x *= minus_one);
        let is_not_first_or_last_row = is_not_first_row
            .iter()
            .zip_eq(is_not_last_row.iter())
            .map(|(x, y)| *x + y)
            .collect::<Vec<_>>();
        is_not_last_row
            .iter_mut()
            .for_each(|x| *x += &P::ScalarField::one());
        let mut is_not_infinity = transcript_pinfinity.to_owned();
        is_not_infinity.iter_mut().for_each(|x| {
            T::mul_assign_with_public(x, minus_one);
            T::add_assign_public(x, P::ScalarField::one(), id);
        });
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

        let mut lhs = Vec::with_capacity(45 * z1.len());
        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(z1.to_owned());
        rhs.extend(z1_zero.to_owned());

        lhs.extend(z2.to_owned());
        rhs.extend(z2_zero.to_owned());

        /*
         * @brief Validate `op` opcode is well formed.
         * `op` is defined to be q_reset_accumulator + 2 * q_eq + 4 * q_mul + 8 * q_add,
         * where q_reset_accumulator, q_eq, q_mul, q_add are all boolean
         * (AZTEC TODO: bool constrain these efficiently #2223)
         */
        let mut tmp = q_add.to_owned(); //* P::ScalarField::from(2);
        T::scale_many_in_place(&mut tmp, P::ScalarField::from(2));
        T::add_assign_many(&mut tmp, q_mul);
        T::scale_many_in_place(&mut tmp, P::ScalarField::from(2));
        T::add_assign_many(&mut tmp, q_eq);
        T::scale_many_in_place(&mut tmp, P::ScalarField::from(2));
        T::add_assign_many(&mut tmp, q_reset_accumulator);
        T::sub_assign_many(&mut tmp, op);
        tmp.iter_mut()
            .zip_eq(scaling_factors.iter())
            .for_each(|(x, y)| {
                T::mul_assign_with_public(x, *y);
            });
        fold_accumulator!(univariate_accumulator.r2, tmp, SIZE);

        /*
         * @brief Validate `pc` is updated correctly.
         * pc stands for Point Counter. It decrements by 1 for every 128-bit multiplication operation.
         * If q_mul = 1, pc decrements by !z1_zero + !z2_zero, else pc decrements by 0
         * @note pc starts out at its max value and decrements down to 0. This keeps the degree of the pc polynomial smol
         */
        let mut pc_delta = pc_shift.to_owned(); // * minus_one + pc;
        T::scale_many_in_place(&mut pc_delta, minus_one);
        T::add_assign_many(&mut pc_delta, pc);
        let mut num_muls_in_row_factor_1 = z1_zero.to_owned();
        T::scale_many_in_place(&mut num_muls_in_row_factor_1, minus_one);
        T::add_scalar_in_place(&mut num_muls_in_row_factor_1, P::ScalarField::from(2), id);
        T::sub_assign_many(&mut num_muls_in_row_factor_1, z2_zero);
        let mut num_muls_in_row_factor_2 = transcript_pinfinity.to_owned();
        T::scale_many_in_place(&mut num_muls_in_row_factor_2, minus_one);
        T::add_scalar_in_place(&mut num_muls_in_row_factor_2, P::ScalarField::one(), id);

        lhs.extend(num_muls_in_row_factor_1);
        rhs.extend(num_muls_in_row_factor_2); //This result is num_muls_in_row

        /*
         * @brief Validate `msm_transition` is well-formed.
         *
         * If the current row is the last mul instruction in a multiscalar multiplication, msm_transition = 1.
         * i.e. if q_mul == 1 and q_mul_shift == 0, msm_transition = 1, else is 0
         * We also require that `msm_count + [current msm number] > 0`
         */

        let mut msm_transition_check_factor_1 = q_mul_shift.to_owned();
        T::scale_many_in_place(&mut msm_transition_check_factor_1, minus_one);
        T::add_scalar_in_place(
            &mut msm_transition_check_factor_1,
            P::ScalarField::one(),
            id,
        );
        let msm_transition_check_factor_2 = q_mul;
        lhs.extend(msm_transition_check_factor_1);
        rhs.extend(msm_transition_check_factor_2);

        let msm_count_zero_at_transition = input.witness.transcript_msm_count_zero_at_transition();
        let msm_count_at_transition_inverse =
            input.witness.transcript_msm_count_at_transition_inverse();

        // Validate msm_transition_msm_count is correct
        // ensure msm_transition is zero if count is zero

        /*
         * @brief Validate `msm_count` resets when we end a multiscalar multiplication.
         * msm_count tracks the number of scalar muls in the current active multiscalar multiplication.
         * (if no msm active, msm_count == 0)
         * If current row ends an MSM, `msm_count_shift = 0` (msm_count value at next row)
         */

        lhs.extend(msm_transition.to_owned());
        rhs.extend(msm_count_shift.to_owned());

        /*
         * @brief Validate `msm_count` updates correctly for mul operations.
         * msm_count updates by (!z1_zero + !z2_zero) if current op is a mul instruction (and msm is not terminating at next
         * row).
         */
        let mut msm_count_delta = msm_count.to_owned(); // * minus_one + msm_count_shift; // degree 4
        T::scale_many_in_place(&mut msm_count_delta, minus_one);
        T::add_assign_many(&mut msm_count_delta, msm_count_shift);

        /*
         * @brief Opcode exclusion tests. We have the following assertions:
         * 1. If q_mul = 1, (q_add, eq, reset) are zero
         * 2. If q_add = 1, (q_mul, eq, reset) are zero
         * 3. If q_eq =  1, (q_add, q_mul) are zero (is established by previous 2 checks)
         */
        let mut opcode_exclusion_relation_factor = q_add.to_owned(); // + q_eq + q_reset_accumulator) * q_mul;
        T::add_assign_many(&mut opcode_exclusion_relation_factor, q_eq);
        T::add_assign_many(&mut opcode_exclusion_relation_factor, q_reset_accumulator);
        lhs.extend(opcode_exclusion_relation_factor);
        rhs.extend(q_mul.to_owned());

        let mut opcode_exclusion_relation_summand_factor = q_mul.to_owned();
        T::add_assign_many(&mut opcode_exclusion_relation_summand_factor, q_eq);
        T::add_assign_many(
            &mut opcode_exclusion_relation_summand_factor,
            q_reset_accumulator,
        );
        lhs.extend(opcode_exclusion_relation_summand_factor);
        rhs.extend(q_add.to_owned());

        /*
         * @brief `eq` opcode.
         * Let lhs = transcript_P and rhs = transcript_accumulator
         * If eq = 1, we must validate the following cases:
         * IF lhs and rhs are not at infinity THEN lhs == rhs
         * ELSE lhs and rhs are BOTH points at infinity
         **/
        lhs.extend(transcript_pinfinity.to_owned());
        rhs.extend(is_accumulator_empty.to_owned());

        let mut both_not_infinity_factor_1 = transcript_pinfinity.to_owned();
        T::scale_many_in_place(&mut both_not_infinity_factor_1, minus_one);
        T::add_scalar_in_place(&mut both_not_infinity_factor_1, P::ScalarField::one(), id);
        let mut both_not_infinity_factor_2 = is_accumulator_empty.to_owned();
        T::scale_many_in_place(&mut both_not_infinity_factor_2, minus_one);
        T::add_scalar_in_place(&mut both_not_infinity_factor_2, P::ScalarField::one(), id);
        lhs.extend(both_not_infinity_factor_1);
        rhs.extend(both_not_infinity_factor_2);

        let mut eq_x_diff = transcript_accumulator_x.to_owned(); //* minus_one + transcript_px;
        T::scale_many_in_place(&mut eq_x_diff, minus_one);
        T::add_assign_many(&mut eq_x_diff, transcript_px);
        let mut eq_y_diff = transcript_accumulator_y.to_owned(); //* minus_one + transcript_py;
        T::scale_many_in_place(&mut eq_y_diff, minus_one);
        T::add_assign_many(&mut eq_y_diff, transcript_py);

        /*
         * @brief Initial condition check on 1st row.
         * We require the following values are 0 on 1st row:
         * is_accumulator_empty = 1
         * msm_count = 0
         * note...actually second row? bleurgh
         * NOTE: we want pc = 0 at lagrange_last :o
         */
        let mut tmp = is_accumulator_empty.to_owned(); //* minus_one + &P::ScalarField::one())
        T::scale_many_in_place(&mut tmp, minus_one);
        T::add_scalar_in_place(&mut tmp, P::ScalarField::one(), id);
        tmp.iter_mut()
            .zip_eq(scaling_factors.iter())
            .for_each(|(x, y)| {
                T::mul_assign_with_public(x, *y);
            });
        tmp.iter_mut()
            .zip_eq(lagrange_second.iter())
            .for_each(|(x, y)| {
                T::mul_assign_with_public(x, *y);
            });
        fold_accumulator!(univariate_accumulator.r11, tmp, SIZE);

        let mut tmp = msm_count.to_owned(); //* lagrange_second * scaling_factor; // degree 2
        T::mul_assign_with_public_many(&mut tmp, lagrange_second);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r12, tmp, SIZE);

        /*
         * @brief On-curve validation checks.
         * If q_mul = 1 OR q_add = 1 OR q_eq = 1, require (transcript_Px, transcript_Py) is valid ecc point
         * q_mul/q_add/q_eq mutually exclusive, can represent as sum of 3
         */
        let mut validate_on_curve = q_add.to_owned(); // + q_mul + q_eq;
        T::add_assign_many(&mut validate_on_curve, q_mul);
        T::add_assign_many(&mut validate_on_curve, q_eq);

        lhs.extend(transcript_py.to_owned());
        rhs.extend(transcript_py.to_owned());
        lhs.extend(transcript_px.to_owned());
        rhs.extend(transcript_px.to_owned());
        lhs.extend(validate_on_curve);
        rhs.extend(is_not_infinity.to_owned());

        /*
         * @brief Validate relations from ECC Group Operations are well formed
         *
         */

        lhs.extend(transcript_add_x_equal.to_owned());
        rhs.extend(transcript_add_y_equal.to_owned());
        let mut is_add = transcript_add_x_equal.to_owned(); // * minus_one + &P::ScalarField::one();
        T::scale_many_in_place(&mut is_add, minus_one);
        T::add_scalar_in_place(&mut is_add, P::ScalarField::one(), id);

        let mut add_result_is_infinity_factor_1 = transcript_add_y_equal.to_owned();
        T::scale_many_in_place(&mut add_result_is_infinity_factor_1, minus_one);
        T::add_scalar_in_place(
            &mut add_result_is_infinity_factor_1,
            P::ScalarField::one(),
            id,
        );
        let add_result_is_infinity_factor_2 = transcript_add_x_equal;
        lhs.extend(add_result_is_infinity_factor_1);
        rhs.extend(add_result_is_infinity_factor_2.to_owned());
        let rhs_x = transcript_accumulator_x;
        let rhs_y = transcript_accumulator_y;
        let out_x = transcript_accumulator_x_shift;
        let out_y = transcript_accumulator_y_shift;
        let lambda = transcript_add_lambda;

        lhs.extend(transcript_px.to_owned());
        rhs.extend(q_add.to_owned());
        lhs.extend(transcript_msm_x.to_owned());
        rhs.extend(msm_transition.to_owned());

        lhs.extend(transcript_py.to_owned());
        rhs.extend(q_add.to_owned());
        lhs.extend(transcript_msm_y.to_owned());
        rhs.extend(msm_transition.to_owned());

        lhs.extend(transcript_pinfinity.to_owned());
        rhs.extend(q_add.to_owned());
        lhs.extend(transcript_msm_infinity.to_owned());
        rhs.extend(msm_transition.to_owned());
        let rhs_infinity = is_accumulator_empty;

        let mut result_infinity_from_operation_factor_1 = transcript_add_y_equal.to_owned();
        T::scale_many_in_place(&mut result_infinity_from_operation_factor_1, minus_one);
        T::add_scalar_in_place(
            &mut result_infinity_from_operation_factor_1,
            P::ScalarField::one(),
            id,
        );
        let result_infinity_from_operation_factor_2 = transcript_add_x_equal;
        lhs.extend(result_infinity_from_operation_factor_1);
        rhs.extend(result_infinity_from_operation_factor_2.to_owned());
        // infinity_from_inputs and infinity_from_operation mutually exclusive so we can perform an OR by adding
        // (mutually exclusive because if result_infinity_from_inputs then transcript_add_y_equal = 1 (both y are 0)
        // let result_is_infinity = result_infinity_from_inputs + result_infinity_from_operation; // degree 2
        let mut any_add_is_active = q_add.to_owned(); //+ msm_transition;
        T::add_assign_many(&mut any_add_is_active, msm_transition);

        // Valdiate `transcript_add_lambda` is well formed if we are adding msm output into accumulator

        let msm_x = transcript_msm_x;
        let msm_y = transcript_msm_y;

        // Group operation is point addition

        let mut lambda_denominator = msm_x.to_owned(); // * minus_one + rhs_x;
        T::scale_many_in_place(&mut lambda_denominator, minus_one);
        T::add_assign_many(&mut lambda_denominator, rhs_x);
        let mut lambda_numerator_1 = msm_y.to_owned(); // * minus_one + rhs_y;
        T::scale_many_in_place(&mut lambda_numerator_1, minus_one);
        T::add_assign_many(&mut lambda_numerator_1, rhs_y);

        lhs.extend(lambda_denominator);
        rhs.extend(lambda.clone());

        // Group operation is point doubling

        let mut lambda_denominator = msm_y.to_owned(); // + msm_y;
        T::add_assign_many(&mut lambda_denominator, msm_y);

        lhs.extend(msm_x.to_owned());
        rhs.extend(msm_x.to_owned());
        lhs.extend(lambda_denominator);
        rhs.extend(lambda.to_owned());

        let mut transcript_add_or_dbl_from_msm_output_is_valid_factor_1 =
            transcript_msm_infinity.to_owned();
        T::scale_many_in_place(
            &mut transcript_add_or_dbl_from_msm_output_is_valid_factor_1,
            minus_one,
        );
        T::add_scalar_in_place(
            &mut transcript_add_or_dbl_from_msm_output_is_valid_factor_1,
            P::ScalarField::one(),
            id,
        );
        let mut transcript_add_or_dbl_from_msm_output_is_valid_factor_2 =
            is_accumulator_empty.to_owned();
        T::scale_many_in_place(
            &mut transcript_add_or_dbl_from_msm_output_is_valid_factor_2,
            minus_one,
        );
        T::add_scalar_in_place(
            &mut transcript_add_or_dbl_from_msm_output_is_valid_factor_2,
            P::ScalarField::one(),
            id,
        );
        lhs.extend(transcript_add_or_dbl_from_msm_output_is_valid_factor_1);
        rhs.extend(transcript_add_or_dbl_from_msm_output_is_valid_factor_2);
        // transcript_msm_lambda_relation *= transcript_add_or_dbl_from_msm_output_is_valid; // degree 6
        // No group operation because of points at infinity

        let mut lambda_relation_invalid_3 = transcript_msm_infinity.to_owned();

        T::add_assign_many(&mut lambda_relation_invalid_3, is_accumulator_empty);

        // Valdiate `transcript_add_lambda` is well formed if we are adding base point into accumulator

        let add_x = transcript_px;
        let add_y = transcript_py;
        // Group operation is point addition

        let mut lambda_denominator = add_x.to_owned();
        T::scale_many_in_place(&mut lambda_denominator, minus_one);
        T::add_assign_many(&mut lambda_denominator, rhs_x);
        let mut lambda_numerator_4 = add_y.to_owned();
        T::scale_many_in_place(&mut lambda_numerator_4, minus_one);
        T::add_assign_many(&mut lambda_numerator_4, rhs_y);
        lhs.extend(lambda_denominator);
        rhs.extend(lambda.clone());

        // Group operation is point doubling

        let mut lambda_denominator = add_y.to_owned(); // + add_y;
        T::add_assign_many(&mut lambda_denominator, add_y);
        lhs.extend(add_x.to_owned());
        rhs.extend(add_x.to_owned());
        lhs.extend(lambda_denominator);
        rhs.extend(lambda.clone());

        let mut transcript_add_or_dbl_from_add_output_is_valid_factor_1 =
            transcript_pinfinity.to_owned();
        T::scale_many_in_place(
            &mut transcript_add_or_dbl_from_add_output_is_valid_factor_1,
            minus_one,
        );
        T::add_scalar_in_place(
            &mut transcript_add_or_dbl_from_add_output_is_valid_factor_1,
            P::ScalarField::one(),
            id,
        );
        let mut transcript_add_or_dbl_from_add_output_is_valid_factor_2 =
            is_accumulator_empty.to_owned();
        T::scale_many_in_place(
            &mut transcript_add_or_dbl_from_add_output_is_valid_factor_2,
            minus_one,
        );
        T::add_scalar_in_place(
            &mut transcript_add_or_dbl_from_add_output_is_valid_factor_2,
            P::ScalarField::one(),
            id,
        );
        lhs.extend(transcript_add_or_dbl_from_add_output_is_valid_factor_1);
        rhs.extend(transcript_add_or_dbl_from_add_output_is_valid_factor_2);
        // No group operation because of points at infinity

        let mut lambda_relation_invalid_6 = transcript_pinfinity.to_owned(); // + is_accumulator_empty + add_result_is_infinity; // degree 2
        T::add_assign_many(&mut lambda_relation_invalid_6, is_accumulator_empty);

        /*
         * @brief Validate transcript_accumulator_x_shift / transcript_accumulator_y_shift are well formed.
         *        Conditions (one of the following):
         *        1. The result of a group operation involving transcript_accumulator and msm_output (q_add = 1)
         *        2. The result of a group operation involving transcript_accumulator and transcript_P (msm_transition =
         * 1)
         *        3. Is equal to transcript_accumulator (no group operation, no reset)
         *        4. Is 0 (reset)
         */

        // let lambda_sqr = lambda.to_owned().sqr();
        lhs.extend(lambda.clone());
        rhs.extend(lambda.clone());

        // add relation that validates result_infinity_from_operation * result_is_infinity = 0

        // N.B. these relations rely on the fact that `lambda = 0` if we are not evaluating add/double formula
        // (i.e. one or both outputs are points at infinity, or produce a point at infinity)
        // This should be validated by the lambda_relation

        let mut propagate_transcript_accumulator = q_add.to_owned(); // * minus_one - msm_transition - q_reset_accumulator
        // + &P::ScalarField::one();
        T::scale_many_in_place(&mut propagate_transcript_accumulator, minus_one);
        T::sub_assign_many(&mut propagate_transcript_accumulator, msm_transition);
        T::sub_assign_many(&mut propagate_transcript_accumulator, q_reset_accumulator);
        T::add_scalar_in_place(
            &mut propagate_transcript_accumulator,
            P::ScalarField::one(),
            id,
        );

        let mut add_point_x_relation_factor_1 = out_x.to_owned();
        T::sub_assign_many(&mut add_point_x_relation_factor_1, transcript_accumulator_x);
        lhs.extend(add_point_x_relation_factor_1);
        rhs.extend(propagate_transcript_accumulator.to_owned());

        lhs.extend(out_x.to_owned());
        rhs.extend(q_reset_accumulator.to_owned());

        lhs.extend(T::sub_many(out_y, transcript_accumulator_y));
        rhs.extend(propagate_transcript_accumulator.to_owned());

        // validate out_y = 0 if q_reset_accumulator = 1
        lhs.extend(out_y.to_owned());
        rhs.extend(q_reset_accumulator.to_owned());

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

        let mut x_term_11 = x3.to_owned();
        T::add_assign_many(&mut x_term_11, x2);
        T::add_scalar_in_place(&mut x_term_11, x1, id);
        let mut x_term_12 = x2.to_owned();
        T::add_scalar_in_place(&mut x_term_12, -x1, id);
        lhs.extend(x_term_11);
        rhs.extend(x_term_12.to_owned());
        let mut x_term_21 = y2.to_owned();
        T::add_scalar_in_place(&mut x_term_21, -y1, id);
        lhs.extend(x_term_21.to_owned());
        rhs.extend(x_term_21.to_owned());

        let mut y_term_11 = x3.to_owned();
        T::scale_many_in_place(&mut y_term_11, minus_one);
        T::add_scalar_in_place(&mut y_term_11, x1, id);
        let mut y_term_22 = y3.to_owned();
        T::add_scalar_in_place(&mut y_term_22, y1, id);
        lhs.extend(y_term_11);
        rhs.extend(x_term_21.to_owned());
        lhs.extend(x_term_12.to_owned());
        rhs.extend(y_term_22.to_owned());

        // IF msm_infinity = false, transcript_msm_intermediate_x/y is either the result of subtracting offset
        // generator from msm_x/y IF msm_infinity = true, transcript_msm_intermediate_x/y is 0

        // validate transcript_msm_infinity is correct
        // if transcript_msm_infinity = 1, (x2 == x1) and (y2 + y1 == 0)
        let mut x_diff = x2.to_owned(); // - &x1;
        T::add_scalar_in_place(&mut x_diff, -x1, id);
        let mut y_sum = y2.to_owned(); // + &y1;
        T::add_scalar_in_place(&mut y_sum, y1, id);
        lhs.extend(x_diff.to_owned());
        rhs.extend(msm_transition.to_owned());

        lhs.extend(y_sum.to_owned());
        rhs.extend(msm_transition.to_owned());

        // if transcript_msm_infinity = 1, then x_diff must have an inverse
        let transcript_msm_x_inverse = input.witness.transcript_msm_x_inverse();

        lhs.extend(x_diff.to_owned());
        rhs.extend(transcript_msm_x_inverse.to_owned());

        /*
         * @brief Validate `is_accumulator_empty` is updated correctly
         * An add operation can produce a point at infinity
         * Resetting the accumulator produces a point at infinity
         * If we are not adding, performing an msm or resetting the accumulator, is_accumulator_empty should not update
         */

        let mut accumulator_infinity_preserve_flag = q_add.to_owned();
        T::add_assign_many(&mut accumulator_infinity_preserve_flag, msm_transition);
        T::add_assign_many(&mut accumulator_infinity_preserve_flag, q_reset_accumulator);
        T::scale_many_in_place(&mut accumulator_infinity_preserve_flag, minus_one);
        T::add_scalar_in_place(&mut accumulator_infinity_preserve_flag, one, id);

        let mut accumulator_infinity_preserve_factor_1 = is_accumulator_empty.to_owned();
        T::sub_assign_many(
            &mut accumulator_infinity_preserve_factor_1,
            is_accumulator_empty_shift,
        );
        lhs.extend(accumulator_infinity_preserve_factor_1);
        rhs.extend(accumulator_infinity_preserve_flag.to_owned());

        let mut accumulator_infinity_q_reset_factor_1 = is_accumulator_empty_shift.to_owned();
        T::scale_many_in_place(&mut accumulator_infinity_q_reset_factor_1, minus_one);
        T::add_scalar_in_place(&mut accumulator_infinity_q_reset_factor_1, one, id);
        lhs.extend(accumulator_infinity_q_reset_factor_1);
        rhs.extend(q_reset_accumulator.to_owned());

        /*
         * @brief Validate `transcript_add_x_equal` is well-formed
         *        If lhs_x == rhs_x, transcript_add_x_equal = 1
         *        If transcript_add_x_equal = 0, a valid inverse must exist for (lhs_x - rhs_x)
         */

        let mut x_product_factor_1 = transcript_add_x_equal.to_owned();
        T::scale_many_in_place(&mut x_product_factor_1, minus_one);
        T::add_scalar_in_place(&mut x_product_factor_1, P::ScalarField::one(), id);
        lhs.extend(x_product_factor_1);
        rhs.extend(transcript_px_inverse.to_owned());
        let mut x_constant = transcript_add_x_equal.to_owned(); // - 1; // degree 1
        T::add_scalar_in_place(&mut x_constant, -P::ScalarField::one(), id);

        /*
         * @brief Validate `transcript_add_y_equal` is well-formed
         *        If lhs_y == rhs_y, transcript_add_y_equal = 1
         *        If transcript_add_y_equal = 0, a valid inverse must exist for (lhs_y - rhs_y)
         */

        let mut y_product_factor_1 = transcript_add_y_equal.to_owned();
        T::scale_many_in_place(&mut y_product_factor_1, minus_one);
        T::add_scalar_in_place(&mut y_product_factor_1, P::ScalarField::one(), id);
        lhs.extend(y_product_factor_1);
        rhs.extend(transcript_py_inverse.to_owned());
        let mut y_constant = transcript_add_y_equal.to_owned(); //- 1;
        T::add_scalar_in_place(&mut y_constant, -P::ScalarField::one(), id);

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 45).collect_vec();
        debug_assert_eq!(mul.len(), 45);

        let mut lhs2 = Vec::with_capacity(26 * mul[2].len());
        let mut rhs2 = Vec::with_capacity(lhs2.len());

        let mut tmp = mul[0].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        let mut tmp = mul[1].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        let num_muls_in_row = mul[2].to_owned();
        lhs2.extend(num_muls_in_row.clone());
        rhs2.extend(q_mul.to_owned());

        let mut msm_count_total = msm_count.to_owned(); // + num_muls_in_row; // degree 3  
        T::add_assign_many(&mut msm_count_total, &num_muls_in_row);

        lhs2.extend(msm_count_zero_at_transition.to_owned());
        rhs2.extend(msm_count_total.to_owned());

        lhs2.extend(msm_count_at_transition_inverse.to_owned());
        rhs2.extend(msm_count_total.to_owned());

        let msm_transition_check = mul[3].to_owned();

        let mut r5_factor = msm_count_zero_at_transition.to_owned();
        T::scale_many_in_place(&mut r5_factor, minus_one);
        T::add_scalar_in_place(&mut r5_factor, P::ScalarField::one(), id);
        lhs2.extend(r5_factor);
        rhs2.extend(msm_transition_check.to_owned());

        let mut tmp = mul[4].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r6, tmp, SIZE);

        opcode_exclusion_relation_factor = mul[5].to_owned();
        T::add_assign_many(&mut opcode_exclusion_relation_factor, mul[6]);
        T::mul_assign_with_public_many(&mut opcode_exclusion_relation_factor, scaling_factors);
        fold_accumulator!(
            univariate_accumulator.r8,
            opcode_exclusion_relation_factor,
            SIZE
        );

        let both_infinity = mul[7].to_owned();
        let both_not_infinity = mul[8].to_owned();
        let mut infinity_exclusion_check = transcript_pinfinity.to_owned();
        T::add_assign_many(&mut infinity_exclusion_check, is_accumulator_empty);
        T::sub_assign_many(&mut infinity_exclusion_check, &both_infinity);
        T::sub_assign_many(&mut infinity_exclusion_check, &both_infinity);
        lhs2.extend(eq_x_diff);
        rhs2.extend(both_not_infinity.clone());

        lhs2.extend(eq_y_diff);
        rhs2.extend(both_not_infinity);

        let transcript_py_sqr = mul[9].to_owned();
        let transcript_px_sqr = mul[10].to_owned();
        lhs2.extend(transcript_px_sqr.to_owned());
        rhs2.extend(transcript_px.to_owned());

        let validate_on_curve_mul_is_not_infinity = mul[11].to_owned();

        let is_double = mul[12].to_owned();
        let add_result_is_infinity = mul[13].to_owned();

        let mut lhs_x = mul[14].to_owned();
        T::add_assign_many(&mut lhs_x, mul[15]);

        let mut lhs_y = mul[16].to_owned();
        T::add_assign_many(&mut lhs_y, mul[17]);

        let mut lhs_infinity = mul[18].to_owned();
        T::add_assign_many(&mut lhs_infinity, mul[19]);

        let mut result_is_lhs_factor = lhs_infinity.to_owned();
        T::scale_many_in_place(&mut result_is_lhs_factor, minus_one);
        T::add_scalar_in_place(&mut result_is_lhs_factor, P::ScalarField::one(), id);
        lhs2.extend(result_is_lhs_factor);
        rhs2.extend(rhs_infinity.to_owned());

        let mut result_is_rhs_factor = rhs_infinity.to_owned();
        T::scale_many_in_place(&mut result_is_rhs_factor, minus_one);
        T::add_scalar_in_place(&mut result_is_rhs_factor, P::ScalarField::one(), id);
        lhs2.extend(result_is_rhs_factor);
        rhs2.extend(lhs_infinity.to_owned());

        lhs2.extend(lhs_infinity.to_owned());
        rhs2.extend(rhs_infinity.to_owned());

        let result_infinity_from_operation = mul[20].to_owned();

        let mut lambda_relation_1 = mul[21].to_owned();
        T::sub_assign_many(&mut lambda_relation_1, &lambda_numerator_1);
        lhs2.extend(lambda_relation_1.clone());
        rhs2.extend(is_add.to_owned());

        let mut lambda_numerator_2 = mul[22].to_owned();
        T::scale_many_in_place(&mut lambda_numerator_2, P::ScalarField::from(3));
        let mut lambda_relation_2 = mul[23].to_owned();
        T::sub_assign_many(&mut lambda_relation_2, &lambda_numerator_2);
        lhs2.extend(lambda_relation_2.clone());
        rhs2.extend(is_double.to_owned());

        let transcript_add_or_dbl_from_msm_output_is_valid = mul[24].to_owned();

        T::add_assign_many(&mut lambda_relation_invalid_3, &add_result_is_infinity);
        lhs2.extend(lambda_relation_invalid_3);
        rhs2.extend(lambda.clone());

        let mut lambda_relation_4 = mul[25].to_owned();
        T::sub_assign_many(&mut lambda_relation_4, &lambda_numerator_4);
        lhs2.extend(lambda_relation_4);
        rhs2.extend(is_add.to_owned());

        let mut lambda_numerator_5 = mul[26].to_owned();
        T::scale_many_in_place(&mut lambda_numerator_5, P::ScalarField::from(3));
        let mut lambda_relation_5 = mul[27].to_owned();
        T::sub_assign_many(&mut lambda_relation_5, &lambda_numerator_5);
        lhs2.extend(lambda_relation_5);
        rhs2.extend(is_double.to_owned());

        let transcript_add_or_dbl_from_add_output_is_valid = mul[28].to_owned();

        T::add_assign_many(&mut lambda_relation_invalid_6, &add_result_is_infinity);
        lhs2.extend(lambda_relation_invalid_6);
        rhs2.extend(lambda.clone());

        let mut x3_acc = mul[29].to_owned();
        T::sub_assign_many(&mut x3_acc, &lhs_x);
        T::sub_assign_many(&mut x3_acc, rhs_x);

        let mut y3_acc_summand_1_factor = lhs_x.to_owned();
        T::sub_assign_many(&mut y3_acc_summand_1_factor, out_x);
        lhs2.extend(y3_acc_summand_1_factor);
        rhs2.extend(lambda.clone());

        let mut add_point_x_relation_summand_1 = mul[30].to_owned();
        T::mul_assign_with_public_many(&mut add_point_x_relation_summand_1, &is_not_last_row);
        let add_point_x_relation_summand_2 = mul[31].to_owned();
        let mut add_point_y_relation_summand_1 = mul[32].to_owned();
        T::mul_assign_with_public_many(&mut add_point_y_relation_summand_1, &is_not_last_row);
        let add_point_y_relation_summand_2 = mul[33].to_owned();

        let x_term_11_12 = mul[34].to_owned();
        lhs2.extend(x_term_11_12.to_owned());
        rhs2.extend(x_term_12.to_owned());
        lhs2.extend(transcript_msm_infinity.to_owned());
        rhs2.extend(x3.to_owned());
        let x_term_factor_2 = mul[35];

        let y_term = T::sub_many(mul[36], mul[37]);
        lhs2.extend(y_term.to_owned());
        let mut transcript_offset_generator_subtract_y_factor = transcript_msm_infinity.to_owned();
        T::scale_many_in_place(
            &mut transcript_offset_generator_subtract_y_factor,
            minus_one,
        );
        T::add_scalar_in_place(
            &mut transcript_offset_generator_subtract_y_factor,
            P::ScalarField::one(),
            id,
        );
        rhs2.extend(transcript_offset_generator_subtract_y_factor.to_owned());
        lhs2.extend(transcript_msm_infinity.to_owned());
        rhs2.extend(y3.to_owned());

        let r19_factor_1 = mul[38];
        lhs2.extend(r19_factor_1.to_owned());
        rhs2.extend(transcript_msm_infinity.to_owned());

        let r20_factor_1 = mul[39];
        lhs2.extend(r20_factor_1.to_owned());
        rhs2.extend(transcript_msm_infinity.to_owned());

        let mut inverse_term_factor_1 = transcript_msm_infinity.to_owned();
        T::scale_many_in_place(&mut inverse_term_factor_1, minus_one);
        T::add_scalar_in_place(&mut inverse_term_factor_1, P::ScalarField::one(), id);
        let mut inverse_term_factor_2 = mul[40].to_owned();
        T::add_scalar_in_place(&mut inverse_term_factor_2, -P::ScalarField::one(), id);
        lhs2.extend(inverse_term_factor_1);
        rhs2.extend(inverse_term_factor_2.to_owned());

        let mut accumulator_infinity_preserve = mul[41].to_owned();
        T::mul_assign_with_public_many(
            &mut accumulator_infinity_preserve,
            &is_not_first_or_last_row,
        );

        let accumulator_infinity_q_reset = mul[42].to_owned();

        let mut x_product = mul[43].to_owned();
        T::add_assign_many(&mut x_product, transcript_add_x_equal);
        lhs2.extend(x_product.to_owned());
        let mut x_diff = lhs_x.to_owned();
        T::sub_assign_many(&mut x_diff, rhs_x);
        rhs2.extend(x_diff);

        let mut y_product = mul[44].to_owned();
        T::add_assign_many(&mut y_product, transcript_add_y_equal);
        lhs2.extend(y_product.to_owned());
        let mut y_diff = lhs_y.to_owned();
        T::sub_assign_many(&mut y_diff, rhs_y);
        rhs2.extend(y_diff);

        let mul2 = T::mul_many(&lhs2, &rhs2, net, state)?;
        let mul2 = mul2.chunks_exact(mul2.len() / 26).collect_vec();
        debug_assert_eq!(mul2.len(), 26);

        let mut tmp = pc_delta.to_owned();
        T::sub_assign_many(&mut tmp, mul2[0]);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        T::mul_assign_with_public_many(&mut tmp, &is_not_first_row);
        fold_accumulator!(univariate_accumulator.r3, tmp, SIZE);

        let mut q_mul_num_counts = mul2[0].to_owned();
        T::scale_many_in_place(&mut q_mul_num_counts, minus_one);
        T::add_assign_many(&mut q_mul_num_counts, &msm_count_delta);

        let mut msm_count_zero_at_transition_check = mul2[1].to_owned();
        let mut msm_count_zero_at_transition_check_factor_1 = mul2[2].to_owned();
        T::add_scalar_in_place(
            &mut msm_count_zero_at_transition_check_factor_1,
            minus_one,
            id,
        );
        let mut msm_count_zero_at_transition_check_factor_2 =
            msm_count_zero_at_transition.to_owned();
        T::scale_many_in_place(&mut msm_count_zero_at_transition_check_factor_2, minus_one);
        T::add_scalar_in_place(
            &mut msm_count_zero_at_transition_check_factor_2,
            P::ScalarField::one(),
            id,
        );

        let mut lhs3 = Vec::with_capacity(18 * msm_count_zero_at_transition_check_factor_1.len());
        let mut rhs3 = Vec::with_capacity(lhs3.len());
        lhs3.extend(msm_count_zero_at_transition_check_factor_1);
        rhs3.extend(msm_count_zero_at_transition_check_factor_2);

        let mut tmp = msm_transition.to_owned();
        T::sub_assign_many(&mut tmp, mul2[3]);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r5, tmp, SIZE);

        let mut eq_x_diff_relation_factor_1 = mul2[4].to_owned();
        T::add_assign_many(&mut eq_x_diff_relation_factor_1, &infinity_exclusion_check);
        lhs3.extend(eq_x_diff_relation_factor_1);
        rhs3.extend(q_eq.to_owned());

        let mut eq_y_diff_relation_factor_1 = mul2[5].to_owned();
        T::add_assign_many(&mut eq_y_diff_relation_factor_1, &infinity_exclusion_check);
        lhs3.extend(eq_y_diff_relation_factor_1);
        rhs3.extend(q_eq.to_owned());

        let mut on_curve_check = transcript_py_sqr;
        T::sub_assign_many(&mut on_curve_check, mul2[6]);
        T::add_scalar_in_place(&mut on_curve_check, -P::get_curve_b(), id);
        lhs3.extend(on_curve_check.to_owned());
        rhs3.extend(&validate_on_curve_mul_is_not_infinity);

        let result_is_lhs = mul2[7].to_owned();
        let result_is_rhs = mul2[8].to_owned();
        let result_infinity_from_inputs = mul2[9].to_owned();

        let mut result_is_infinity = result_infinity_from_inputs;
        T::add_assign_many(&mut result_is_infinity, &result_infinity_from_operation);

        let mut transcript_msm_lambda_relation = mul2[10].to_owned();
        T::add_assign_many(&mut transcript_msm_lambda_relation, mul2[11]);

        lhs3.extend(transcript_msm_lambda_relation);
        rhs3.extend(transcript_add_or_dbl_from_msm_output_is_valid);

        let lambda_relation_3 = mul2[12].to_owned();
        let mut transcript_add_lambda_relation = mul2[13].to_owned();
        let transcript_add_lambda_relation_summand_1 = mul2[14].to_owned();
        T::add_assign_many(
            &mut transcript_add_lambda_relation,
            &transcript_add_lambda_relation_summand_1,
        );
        lhs3.extend(transcript_add_lambda_relation);
        rhs3.extend(transcript_add_or_dbl_from_add_output_is_valid);

        let lambda_relation_6 = mul2[15];

        let mut x3_acc_summand_1_factor = rhs_x.to_owned();
        T::add_assign_many(&mut x3_acc_summand_1_factor, &lhs_x);
        T::add_assign_many(&mut x3_acc_summand_1_factor, &lhs_x);
        lhs3.extend(x3_acc_summand_1_factor);
        rhs3.extend(result_is_lhs.to_owned());
        let mut x3_acc_summand_2_factor = lhs_x.to_owned();
        T::add_assign_many(&mut x3_acc_summand_2_factor, rhs_x);
        T::add_assign_many(&mut x3_acc_summand_2_factor, rhs_x);
        lhs3.extend(x3_acc_summand_2_factor);
        rhs3.extend(result_is_rhs.to_owned());
        let mut x3_acc_summand_3_factor = lhs_x.to_owned();
        T::add_assign_many(&mut x3_acc_summand_3_factor, rhs_x);
        lhs3.extend(x3_acc_summand_3_factor);
        rhs3.extend(result_is_infinity.clone());

        let mut y3_acc = mul2[16].to_owned();
        T::sub_assign_many(&mut y3_acc, &lhs_y);
        let mut y3_acc_summand_2_factor = lhs_y.to_owned();
        T::scale_many_in_place(&mut y3_acc_summand_2_factor, P::ScalarField::from(2));
        lhs3.extend(y3_acc_summand_2_factor);
        rhs3.extend(result_is_lhs.to_owned());
        let mut y3_acc_summand_3_factor = lhs_y.to_owned();
        T::add_assign_many(&mut y3_acc_summand_3_factor, rhs_y);
        lhs3.extend(y3_acc_summand_3_factor);
        rhs3.extend(result_is_rhs.to_owned());
        lhs3.extend(lhs_y.to_owned());
        rhs3.extend(result_is_infinity.to_owned());

        let x_term = T::sub_many(mul2[17], x_term_factor_2);
        let mut transcript_offset_generator_subtract_x_factor_1 =
            transcript_msm_infinity.to_owned();
        T::scale_many_in_place(
            &mut transcript_offset_generator_subtract_x_factor_1,
            minus_one,
        );
        T::add_scalar_in_place(
            &mut transcript_offset_generator_subtract_x_factor_1,
            P::ScalarField::one(),
            id,
        );
        lhs3.extend(x_term);
        rhs3.extend(transcript_offset_generator_subtract_x_factor_1);

        let transcript_offset_generator_subtract_x_factor_2 = mul2[18];
        let transcript_offset_generator_subtract_y = T::add_many(mul2[19], mul2[20]);

        lhs3.extend(transcript_offset_generator_subtract_y);
        rhs3.extend(msm_transition.to_owned());

        let mut tmp = mul2[21].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r19, tmp, SIZE);

        let mut tmp = mul2[22].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r20, tmp, SIZE);

        let inverse_term = mul2[23];
        lhs3.extend(inverse_term.to_owned());
        rhs3.extend(msm_transition.to_owned());

        let mut accumulator_infinity_from_add_factor_1 = result_is_infinity.to_owned();
        T::sub_assign_many(
            &mut accumulator_infinity_from_add_factor_1,
            is_accumulator_empty_shift,
        );
        lhs3.extend(accumulator_infinity_from_add_factor_1);
        rhs3.extend(any_add_is_active.to_owned());

        let mut transcript_add_x_equal_check_relation_factor = mul2[24].to_owned();
        T::add_assign_many(
            &mut transcript_add_x_equal_check_relation_factor,
            &x_constant,
        );
        lhs3.extend(transcript_add_x_equal_check_relation_factor);
        rhs3.extend(any_add_is_active.to_owned());

        let mut transcript_add_y_equal_check_relation_factor = mul2[25].to_owned();
        T::add_assign_many(
            &mut transcript_add_y_equal_check_relation_factor,
            &y_constant,
        );
        lhs3.extend(transcript_add_y_equal_check_relation_factor);
        rhs3.extend(any_add_is_active.to_owned());

        //for accumulator 7:
        lhs3.extend(q_mul_num_counts.to_owned());
        rhs3.extend(T::add_scalar(
            &T::scale_many(msm_transition, minus_one),
            one,
            id,
        ));

        let mul3 = T::mul_many(&lhs3, &rhs3, net, state)?;
        let mul3 = mul3.chunks_exact(mul3.len() / 19).collect_vec();
        debug_assert_eq!(mul3.len(), 19);

        let mut lhs4 = Vec::with_capacity(6 * msm_count_zero_at_transition_check.len());
        let mut rhs4 = Vec::with_capacity(lhs4.len());

        T::add_assign_many(&mut msm_count_zero_at_transition_check, mul3[0]);
        lhs4.extend(msm_count_zero_at_transition_check);
        rhs4.extend(msm_transition_check.to_owned());

        let mut tmp = mul3[1].to_owned(); //this is eq_x_diff_relation
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r9, tmp, SIZE);

        let mut tmp = mul3[2].to_owned(); // this is eq_y_diff_relation
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r10, tmp, SIZE);

        let mut tmp = mul3[3].to_owned(); // this is validate_on_curve * on_curve_check * is_not_infinity
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r13, tmp, SIZE);

        let mut transcript_msm_lambda_relation = mul3[4].to_owned();
        T::add_assign_many(&mut transcript_msm_lambda_relation, &lambda_relation_3);

        lhs4.extend(transcript_msm_lambda_relation);
        rhs4.extend(msm_transition.to_owned()); // This is then transcript_lambda_relation

        let mut transcript_add_lambda_relation = mul3[5].to_owned();
        T::add_assign_many(&mut transcript_add_lambda_relation, lambda_relation_6);
        lhs4.extend(transcript_add_lambda_relation);
        rhs4.extend(q_add.to_owned());

        T::add_assign_many(&mut x3_acc, mul3[6]);
        T::add_assign_many(&mut x3_acc, mul3[7]);
        T::add_assign_many(&mut x3_acc, mul3[8]);

        T::add_assign_many(&mut y3_acc, mul3[9]);
        T::add_assign_many(&mut y3_acc, mul3[10]);
        T::add_assign_many(&mut y3_acc, mul3[11]);

        let mut add_point_x_relation_factor = x3_acc;
        T::sub_assign_many(&mut add_point_x_relation_factor, out_x);
        lhs4.extend(add_point_x_relation_factor);
        rhs4.extend(any_add_is_active.clone()); // This is then the initial add_point_x_relation

        let mut add_point_y_relation_factor = y3_acc;
        T::sub_assign_many(&mut add_point_y_relation_factor, out_y);
        lhs4.extend(add_point_y_relation_factor);
        rhs4.extend(any_add_is_active); // This is then the initial add_point_y_relation

        let transcript_offset_generator_subtract_x =
            T::add_many(mul3[12], transcript_offset_generator_subtract_x_factor_2);

        lhs4.extend(transcript_offset_generator_subtract_x);
        rhs4.extend(msm_transition.to_owned());

        let mut tmp = mul3[13].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r18, tmp, SIZE);

        let mut tmp = mul3[14].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r21, tmp, SIZE);

        let accumulator_infinity_from_add = mul3[15];

        let mut accumulator_infinity_relation = accumulator_infinity_from_add.to_owned();
        T::add_assign_many(
            &mut accumulator_infinity_relation,
            &accumulator_infinity_q_reset,
        );
        T::mul_assign_with_public_many(&mut accumulator_infinity_relation, &is_not_first_row);
        T::add_assign_many(
            &mut accumulator_infinity_relation,
            &accumulator_infinity_preserve,
        );
        T::mul_assign_with_public_many(&mut accumulator_infinity_relation, scaling_factors);
        fold_accumulator!(
            univariate_accumulator.r22,
            accumulator_infinity_relation,
            SIZE
        );

        let mut tmp = mul3[16].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r23, tmp, SIZE);

        let mut tmp = mul3[17].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r24, tmp, SIZE);

        let mut tmp = mul3[18].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        T::mul_assign_with_public_many(&mut tmp, &is_not_first_row);
        fold_accumulator!(univariate_accumulator.r7, tmp, SIZE);

        let mul4 = T::mul_many(&lhs4, &rhs4, net, state)?;
        let mul4 = mul4.chunks_exact(mul4.len() / 6).collect_vec();
        debug_assert_eq!(mul4.len(), 6);

        let mut tmp = mul4[0].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r4, tmp, SIZE);

        let mut transcript_lambda_relation = mul4[1].to_owned();
        T::add_assign_many(&mut transcript_lambda_relation, mul4[2]);
        T::mul_assign_with_public_many(&mut transcript_lambda_relation, scaling_factors);
        fold_accumulator!(univariate_accumulator.r14, transcript_lambda_relation, SIZE);

        let mut add_point_x_relation = mul4[3].to_owned();
        T::add_assign_many(&mut add_point_x_relation, &add_point_x_relation_summand_1);
        T::add_assign_many(&mut add_point_x_relation, &add_point_x_relation_summand_2);
        T::mul_assign_with_public_many(&mut add_point_x_relation, scaling_factors);
        fold_accumulator!(univariate_accumulator.r15, add_point_x_relation, SIZE);

        let mut add_point_y_relation = mul4[4].to_owned();
        T::add_assign_many(&mut add_point_y_relation, &add_point_y_relation_summand_1);
        T::add_assign_many(&mut add_point_y_relation, &add_point_y_relation_summand_2);
        T::mul_assign_with_public_many(&mut add_point_y_relation, scaling_factors);
        fold_accumulator!(univariate_accumulator.r16, add_point_y_relation, SIZE);

        let mut tmp = mul4[5].to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r17, tmp, SIZE);

        Ok(())
    }
}
