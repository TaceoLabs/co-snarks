use crate::co_decider::univariates::SharedUnivariate;
use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use co_builder::HonkProofResult;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::prelude::{HonkCurve, derive_generators};
use common::mpc::NoirUltraHonkProver;
use common::transcript::TranscriptFieldType;
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EccMsmRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
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
    pub(crate) r25: SharedUnivariate<T, P, 8>,
    pub(crate) r26: SharedUnivariate<T, P, 8>,
    pub(crate) r27: SharedUnivariate<T, P, 8>,
    pub(crate) r28: SharedUnivariate<T, P, 8>,
    pub(crate) r29: SharedUnivariate<T, P, 8>,
    pub(crate) r30: SharedUnivariate<T, P, 8>,
    pub(crate) r31: SharedUnivariate<T, P, 8>,
    pub(crate) r32: SharedUnivariate<T, P, 8>,
    pub(crate) r33: SharedUnivariate<T, P, 8>,
    pub(crate) r34: SharedUnivariate<T, P, 8>,
    pub(crate) r35: SharedUnivariate<T, P, 8>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccMsmRelationAcc<T, P> {
    fn default() -> Self {
        EccMsmRelationAcc {
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
            r25: SharedUnivariate::default(),
            r26: SharedUnivariate::default(),
            r27: SharedUnivariate::default(),
            r28: SharedUnivariate::default(),
            r29: SharedUnivariate::default(),
            r30: SharedUnivariate::default(),
            r31: SharedUnivariate::default(),
            r32: SharedUnivariate::default(),
            r33: SharedUnivariate::default(),
            r34: SharedUnivariate::default(),
            r35: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct EccMsmRelation {}
impl EccMsmRelation {
    pub(crate) const NUM_RELATIONS: usize = 36;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 119;
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccMsmRelationAcc<T, P> {
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
        self.r25.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r26.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r27.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r28.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r29.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r30.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r31.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r32.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r33.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r34.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r35.scale_inplace(*current_scalar);
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
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccMsmRelation
{
    type Acc = EccMsmRelationAcc<T, P>;
    type VerifyAcc = (); // Not need for ECCVM

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_msm_x1(entity);
        batch.add_msm_y1(entity);
        batch.add_msm_x2(entity);
        batch.add_msm_y2(entity);
        batch.add_msm_x3(entity);
        batch.add_msm_y3(entity);
        batch.add_msm_x4(entity);
        batch.add_msm_y4(entity);
        batch.add_msm_collision_x1(entity);
        batch.add_msm_collision_x2(entity);
        batch.add_msm_collision_x3(entity);
        batch.add_msm_collision_x4(entity);
        batch.add_msm_lambda1(entity);
        batch.add_msm_lambda2(entity);
        batch.add_msm_lambda3(entity);
        batch.add_msm_lambda4(entity);
        batch.add_lagrange_first(entity);
        batch.add_msm_add1(entity);
        batch.add_msm_add1_shift(entity);
        batch.add_msm_add2(entity);
        batch.add_msm_add3(entity);
        batch.add_msm_add4(entity);
        batch.add_msm_accumulator_x(entity);
        batch.add_msm_accumulator_y(entity);
        batch.add_msm_accumulator_x_shift(entity);
        batch.add_msm_accumulator_y_shift(entity);
        batch.add_msm_slice1(entity);
        batch.add_msm_slice2(entity);
        batch.add_msm_slice3(entity);
        batch.add_msm_slice4(entity);
        batch.add_msm_transition(entity);
        batch.add_msm_transition_shift(entity);
        batch.add_msm_round(entity);
        batch.add_msm_round_shift(entity);
        batch.add_msm_add(entity);
        batch.add_msm_add_shift(entity);
        batch.add_msm_skew(entity);
        batch.add_msm_skew_shift(entity);
        batch.add_msm_double(entity);
        batch.add_msm_double_shift(entity);
        batch.add_msm_size_of_msm(entity);
        batch.add_msm_pc(entity);
        batch.add_msm_pc_shift(entity);
        batch.add_msm_count(entity);
        batch.add_msm_count_shift(entity);
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

        let minus_one = -P::ScalarField::one();
        let one = P::ScalarField::one();

        let x1 = input.witness.msm_x1();
        let y1 = input.witness.msm_y1();
        let x2 = input.witness.msm_x2();
        let y2 = input.witness.msm_y2();
        let x3 = input.witness.msm_x3();
        let y3 = input.witness.msm_y3();
        let x4 = input.witness.msm_x4();
        let y4 = input.witness.msm_y4();
        let collision_inverse1 = input.witness.msm_collision_x1();
        let collision_inverse2 = input.witness.msm_collision_x2();
        let collision_inverse3 = input.witness.msm_collision_x3();
        let collision_inverse4 = input.witness.msm_collision_x4();
        let lambda1 = input.witness.msm_lambda1();
        let lambda2 = input.witness.msm_lambda2();
        let lambda3 = input.witness.msm_lambda3();
        let lambda4 = input.witness.msm_lambda4();
        let lagrange_first = input.precomputed.lagrange_first();
        let add1 = input.witness.msm_add1();
        let mut add1_scaled = add1.to_owned();
        T::scale_many_in_place(&mut add1_scaled, minus_one);
        T::add_scalar_in_place(&mut add1_scaled, P::ScalarField::one(), id);
        let add1_shift = input.shifted_witness.msm_add1_shift();
        let add2 = input.witness.msm_add2();
        let mut add2_scaled = add2.to_owned();
        T::scale_many_in_place(&mut add2_scaled, minus_one);
        T::add_scalar_in_place(&mut add2_scaled, P::ScalarField::one(), id);
        let add3 = input.witness.msm_add3();
        let mut add3_scaled = add3.to_owned();
        T::scale_many_in_place(&mut add3_scaled, minus_one);
        T::add_scalar_in_place(&mut add3_scaled, P::ScalarField::one(), id);
        let add4 = input.witness.msm_add4();
        let mut add4_scaled = add4.to_owned();
        T::scale_many_in_place(&mut add4_scaled, minus_one);
        T::add_scalar_in_place(&mut add4_scaled, P::ScalarField::one(), id);
        let acc_x = input.witness.msm_accumulator_x();
        let acc_y = input.witness.msm_accumulator_y();
        let acc_x_shift = input.shifted_witness.msm_accumulator_x_shift();
        let acc_y_shift = input.shifted_witness.msm_accumulator_y_shift();
        let slice1 = input.witness.msm_slice1();
        let slice2 = input.witness.msm_slice2();
        let slice3 = input.witness.msm_slice3();
        let slice4 = input.witness.msm_slice4();
        let msm_transition = input.witness.msm_transition();
        let mut msm_transition_scaled = msm_transition.to_owned();
        T::scale_many_in_place(&mut msm_transition_scaled, minus_one);
        T::add_scalar_in_place(&mut msm_transition_scaled, P::ScalarField::one(), id);
        let msm_transition_shift = input.shifted_witness.msm_transition_shift();
        let mut msm_transition_shift_scaled = msm_transition_shift.to_owned();
        T::scale_many_in_place(&mut msm_transition_shift_scaled, minus_one);
        T::add_scalar_in_place(&mut msm_transition_shift_scaled, P::ScalarField::one(), id);
        let round = input.witness.msm_round();
        let round_shift = input.shifted_witness.msm_round_shift();
        let q_add = input.witness.msm_add();
        let q_add_shift = input.shifted_witness.msm_add_shift();
        let mut q_add_shift_scaled = q_add_shift.to_owned();
        T::scale_many_in_place(&mut q_add_shift_scaled, minus_one);
        T::add_scalar_in_place(&mut q_add_shift_scaled, P::ScalarField::one(), id);
        let q_skew = input.witness.msm_skew();
        let q_skew_shift = input.shifted_witness.msm_skew_shift();
        let mut q_skew_shift_scaled = q_skew_shift.to_owned();
        T::scale_many_in_place(&mut q_skew_shift_scaled, minus_one);
        T::add_scalar_in_place(&mut q_skew_shift_scaled, P::ScalarField::one(), id);
        let q_double = input.witness.msm_double();
        let q_double_shift = input.shifted_witness.msm_double_shift();
        let mut q_double_shift_scaled = q_double_shift.to_owned();
        T::scale_many_in_place(&mut q_double_shift_scaled, minus_one);
        T::add_scalar_in_place(&mut q_double_shift_scaled, P::ScalarField::one(), id);
        let msm_size = input.witness.msm_size_of_msm();
        // const auto& msm_size_shift = View(in.msm_size_of_msm_shift);
        let pc = input.witness.msm_pc();
        let pc_shift = input.shifted_witness.msm_pc_shift();
        let count = input.witness.msm_count();
        let count_shift = input.shifted_witness.msm_count_shift();
        let mut round_delta = round_shift.to_owned(); // - round;
        T::sub_assign_many(&mut round_delta, round);
        let mut round_delta_scaled = round_delta.clone();
        T::scale_many_in_place(&mut round_delta_scaled, minus_one);
        T::add_scalar_in_place(&mut round_delta_scaled, one, id);
        let inverse_seven = P::ScalarField::from(7)
            .inverse()
            .expect("Let's hope we are never in F_7");
        let skew1_select = T::scale_many(slice1, inverse_seven);
        let skew2_select = T::scale_many(slice2, inverse_seven);
        let skew3_select = T::scale_many(slice3, inverse_seven);
        let skew4_select = T::scale_many(slice4, inverse_seven);

        let mut is_not_first_row = lagrange_first.to_owned();
        is_not_first_row.iter_mut().for_each(|x| {
            *x *= minus_one;
            *x += &P::ScalarField::one()
        });

        /*
         * @brief Evaluating ADDITION rounds
         *
         * This comment describes the algorithm we want the Prover to perform.
         * The relations we constrain are supposed to make an honest Prover compute witnesses consistent with the following:
         *
         * For an MSM of size-k...
         *
         * Algorithm to determine if round at shifted row is an ADDITION round:
         *     1. count_shift < msm_size
         *     2. round != 32
         *
         * Algorithm to process MSM ADDITION round:
         * 1. If `round == 0` set `count = 0`
         * 2. For j = pc + count, perform the following:
         * 2a.      If j + 3 < k: [P_{j + 3}] = T_{j+ 3}[slice_{j + 3}]
         * 2b.      If j + 2 < k: [P_{j + 2}] = T_{j+ 2}[slice_{j + 2}]
         * 2c.      If j + 1 < k: [P_{j + 1}] = T_{j+ 1}[slice_{j + 1}]
         * 2d.                    [P_{j}]     = T_{j}[slice_{j}]
         * 2e.      If j + 3 < k: [Acc_shift] = [Acc] + [P_j] + [P_{j+1}] + [P_{j+2}] + [P_{j+3}]
         * 2f. Else If j + 2 < k: [Acc_shift] = [Acc] + [P_j] + [P_{j+1}] + [P_{j+2}]
         * 2g. Else IF j + 1 < k: [Acc_shift] = [Acc] + [P_j] + [P_{j+1}]
         * 2h. Else             : [Acc_shift] = [Acc] + [P_j]
         * 3. `count_shift = count + 1 + (j + 1 < k) + (j + 2 < k) + (j + 3 < k)`
         */

        /*
         * @brief Constraining addition rounds
         *
         * The boolean column q_add describes whether a round is an ADDITION round.
         * The values of q_add are Prover-defined. We need to ensure they set q_add correctly.
         * We rely on the following statements that we assume are constrained to be true (from other relations):
         *      1. The set of reads into (pc, round, wnaf_slice) is constructed when q_add = 1
         *      2. The set of reads into (pc, round, wnaf_slice) must match the set of writes from the point_table columns
         *      3. The set of writes into (pc, round, wnaf_slice) from the point table columns is correct
         *      4. `round` only updates when `q_add = 1` at current row and `q_add = 0` at next row
         * If a Prover sets `q_add = 0` when an honest Prover would set `q_add = 1`,
         * this will produce an inequality in the set of reads / writes into the (pc, round, wnaf_slice) table.
         *
         * The addition algorithm has several IF/ELSE statements based on comparing `count` with `msm_size`.
         * Instead of directly constraining these, we define 4 boolean columns `q_add1, q_add2, q_add3, q_add4`.
         * Like `q_add`, their values are Prover-defined. We need to ensure they are set correctly.
         * We update the above conditions on reads into (pc, round, wnaf_slice) to the following:
         *      1. The set of reads into (pc_{count}, round, wnaf_slice_{count}) is constructed when q_add = 1 AND q_add1 =
         * 1
         *      2. The set of reads into (pc_{count + 1}, round, wnaf_slice_{count + 1}) is constructed when q_add = 1 AND
         * q_add2 = 1
         *      3. The set of reads into (pc_{count + 2}, round, wnaf_slice_{count + 2}) is constructed when q_add = 1 AND
         * q_add3 = 1
         *      4. The set of reads into (pc_{count + 3}, round, wnaf_slice_{count + 3}) is constructed when q_add = 1 AND
         * q_add4 = 1
         *
         * To ensure that all q_addi values are correctly set we apply consistency checks to q_add1/q_add2/q_add3/q_add4:
         * 1. If q_add2 = 1, require q_add1 = 1
         * 2. If q_add3 = 1, require q_add2 = 1
         * 3. If q_add4 = 1, require q_add3 = 1
         * 4. If q_add1_shift = 1 AND round does not update between rows, require q_add4 = 1
         *
         * We want to use all of the above to reason about the set of reads into (pc, round, wnaf_slice).
         * The goal is to conclude that any case where the Prover incorrectly sets q_add/q_add1/q_add2/q_add3/q_add4 will
         * produce a set inequality between the reads/writes into (pc, round, wnaf_slice)
         */

        /*
         * @brief Addition relation
         *
         * All addition operations in ECCVMMSMRelationImpl are conditional additions!
         * This method returns two Accumulators that represent x/y coord of output.
         * Output is either an addition of inputs, or xa/ya dpeending on value of `selector`.
         * Additionally, we require `lambda = 0` if `selector = 0`.
         * The `collision_relation` accumulator tracks a subrelation that validates xb != xa.
         * Repeated calls to this method will increase the max degree of the Accumulator output
         * Degree of x_out, y_out = max degree of x_a/x_b + 1
         * 4 Iterations will produce an output degree of 6
         */
        // let add = |xb: &Univariate<P::ScalarField, SIZE>,
        //            yb: &Univariate<P::ScalarField, SIZE>,
        //            xa: &Univariate<P::ScalarField, SIZE>,
        //            ya: &Univariate<P::ScalarField, SIZE>,
        //            lambda: &Univariate<P::ScalarField, SIZE>,
        //            selector: &Univariate<P::ScalarField, SIZE>,
        //            relation: &mut Univariate<P::ScalarField, SIZE>,
        //            collision_relation: &mut Univariate<P::ScalarField, SIZE>| {
        //     // L * (1 - s) = 0
        //     // (combine) (L * (xb - xa - 1) - yb - ya) * s + L = 0
        //     *relation += selector.to_owned()
        //         * (lambda.to_owned() * (xb.to_owned() - xa - &one) - yb + ya)
        //         + lambda;
        //     *collision_relation += selector.to_owned() * (xb.to_owned() - xa);

        //     // x3 = L.L + (-xb - xa) * q + (1 - q) xa
        //     let x_out = lambda_sqr + (xb.to_owned() * minus_one - xa - xa) * selector + xa;

        //     // y3 = L . (xa - x3) - ya * q + (1 - q) ya
        //     let y_out = lambda.to_owned() * (xa.to_owned() - &x_out)
        //         + (ya.to_owned() * minus_one - ya) * selector
        //         + ya;

        //     (x_out, y_out)
        // };

        /*
         * @brief First Addition relation
         *
         * The first add operation per row is treated differently.
         * Normally we add the point xa/ya with an accumulator xb/yb,
         * BUT, if this row STARTS a multiscalar multiplication,
         * We need to add the point xa/ya with the "offset generator point" xo/yo
         * The offset generator point's purpose is to ensure that no intermediate computations in the MSM will produce
         * points at infinity, for an honest Prover.
         * (we ensure soundness by validating the x-coordinates of xa/xb are not the same i.e. incomplete addition formula
         * edge cases have not been hit)
         * Note: this technique is only statistically complete, as there is a chance of an honest Prover creating a
         * collision, but this probability is equivalent to solving the discrete logarithm problem
         */

        // N.B. this is brittle - should be curve agnostic but we don't propagate the curve parameter into relations!
        let domain_separator = "ECCVM_OFFSET_GENERATOR";
        let mut domain_bytes = Vec::with_capacity(domain_separator.len());
        for i in domain_separator.chars() {
            domain_bytes.push(i as u8);
        }
        let offset_generator = derive_generators::<P::CycleGroup>(&domain_bytes, 1, 0)[0]; // we need CycleGroup here because all this happens in Grumpkin, thus offset_generator is a BN254 Curve point and therefore oxu and oyu are BN254 BaseField elements = Grumpkin ScalarField elements
        let oxu = offset_generator
            .x()
            .expect("Offset generator x coordinate should not be None");
        let oyu = offset_generator
            .y()
            .expect("Offset generator y coordinate should not be None");

        let mut x_summand = msm_transition.to_owned(); //* oxu + acc_x.to_owned() * (msm_transition_scaled);
        T::scale_many_in_place(&mut x_summand, oxu);
        let mut y_summand = msm_transition.to_owned(); //* oyu + acc_y.to_owned() * (msm_transition_scaled);
        T::scale_many_in_place(&mut y_summand, oyu);

        let mut lhs = Vec::with_capacity(msm_transition_scaled.len() * 39);
        let mut rhs = Vec::with_capacity(msm_transition_scaled.len() * 39);
        lhs.extend(msm_transition_scaled.clone());
        lhs.extend(msm_transition_scaled);
        rhs.extend(acc_x.to_owned());
        rhs.extend(acc_y.to_owned());

        // let mut add_relation = lambda1.to_owned() * (x.clone() - x1) - (y - y1); // degree 3
        // let y_t1 = lambda1.to_owned() * (x1.to_owned() - x_t1.to_owned()) - y1;]

        // Do the lambda_i squares:
        lhs.extend(lambda1.to_owned());
        rhs.extend(lambda1.to_owned());
        lhs.extend(lambda2.to_owned());
        rhs.extend(lambda2.to_owned());
        lhs.extend(lambda3.to_owned());
        rhs.extend(lambda3.to_owned());
        lhs.extend(lambda4.to_owned());
        rhs.extend(lambda4.to_owned());

        lhs.extend(lambda1.to_owned());
        rhs.extend(T::scale_many(acc_y, P::ScalarField::from(2u64))); // This is for the double relation

        lhs.extend(acc_x.to_owned());
        rhs.extend(T::scale_many(acc_x, P::ScalarField::from(3u64))); // This is for the double relation

        lhs.extend(lambda1.to_owned());
        rhs.extend(T::sub_many(x1, &T::add_scalar(acc_x, one, id))); //skew_relation_1_term

        lhs.extend(skew1_select.clone());
        rhs.extend(T::sub_many(x1, acc_x));

        lhs.extend(skew1_select.clone());
        rhs.extend(T::sub_many(
            &T::scale_many(x1, minus_one),
            &T::scale_many(acc_x, P::ScalarField::from(2u64)),
        ));

        lhs.extend(add1);
        rhs.extend(q_add);
        lhs.extend(q_skew);
        rhs.extend(skew1_select.clone());
        lhs.extend(add2);
        rhs.extend(q_add);
        lhs.extend(q_skew);
        rhs.extend(skew2_select.clone());
        lhs.extend(add3);
        rhs.extend(q_add);
        lhs.extend(q_skew);
        rhs.extend(skew3_select.clone());
        lhs.extend(add4);
        rhs.extend(q_add);
        lhs.extend(q_skew);
        rhs.extend(skew4_select.clone());
        lhs.extend(add1_scaled.clone());
        rhs.extend(slice1);
        lhs.extend(add2_scaled.clone());
        rhs.extend(slice2);
        lhs.extend(add3_scaled.clone());
        rhs.extend(slice3);
        lhs.extend(add4_scaled.clone());
        rhs.extend(slice4);
        lhs.extend(q_add);
        rhs.extend(q_double);
        lhs.extend(q_add);
        rhs.extend(q_skew);
        lhs.extend(q_double);
        rhs.extend(q_skew);
        lhs.extend(round_delta.clone());
        rhs.extend(msm_transition_shift_scaled.clone());
        lhs.extend(q_double_shift_scaled);
        rhs.extend(q_skew_shift_scaled);
        lhs.extend(q_double);
        rhs.extend(q_double_shift);
        lhs.extend(q_double);
        rhs.extend(q_add_shift_scaled);
        lhs.extend(msm_transition_shift_scaled);
        rhs.extend(round_delta_scaled);
        lhs.extend(msm_transition_shift);
        rhs.extend(count_shift);
        lhs.extend(msm_transition_shift);
        rhs.extend(T::add_many(pc_shift, &T::sub_many(msm_size, pc)));
        lhs.extend(add2);
        rhs.extend(add1_scaled);
        lhs.extend(add3);
        rhs.extend(add2_scaled);
        lhs.extend(add4);
        rhs.extend(add3_scaled);
        lhs.extend(q_add);
        rhs.extend(q_add_shift);
        lhs.extend(q_skew);
        rhs.extend(q_skew_shift);
        lhs.extend(add4_scaled);
        rhs.extend(add1_shift);

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 39).collect_vec();
        debug_assert_eq!(mul.len(), 39);

        let x = T::add_many(mul[0], &x_summand);
        let y = T::add_many(mul[1], &y_summand);
        let mut lhs2 = Vec::with_capacity(lambda1.len() * 26);
        let mut rhs2 = Vec::with_capacity(lhs2.len());
        lhs2.extend(lambda1.to_owned());
        rhs2.extend(T::sub_many(&x, x1)); // this gives us add_relation
        let mut x_t1 = mul[2].to_owned();
        T::sub_assign_many(&mut x_t1, x1);
        T::sub_assign_many(&mut x_t1, &x);
        lhs2.extend(lambda2.to_owned());
        rhs2.extend(&T::sub_many(x2, &T::add_scalar(&x_t1, one, id))); //This gives us the first multiplication in the first addition to add_relation
        lhs2.extend(lambda1.to_owned());
        rhs2.extend(T::sub_many(x1, &x_t1));
        let x1_collision_relation = T::sub_many(x1, &x);
        let lambda1_sqr = mul[2];
        let lambda2_sqr = mul[3];
        let lambda3_sqr = mul[4];
        let lambda4_sqr = mul[5];
        let lambda1_mul_2acc_y = mul[6];
        let acc_x_mul_3_acc_x = mul[7];
        let skew_relation_1_term = mul[8];
        let x1_skew_collision_relation = mul[9];
        let x_out_21_factor = mul[10];
        let add1_mul_q_add = mul[11];
        let q_skew_mul_skew1_select = mul[12];
        let add2_mul_q_add = mul[13];
        let q_skew_mul_skew2_select = mul[14];
        let add3_mul_q_add = mul[15];
        let q_skew_mul_skew3_select = mul[16];
        let add4_mul_q_add = mul[17];
        let q_skew_mul_skew4_select = mul[18];
        let add1_scaled_mul_slice1 = mul[19];
        let add2_scaled_mul_slice2 = mul[20];
        let add3_scaled_mul_slice3 = mul[21];
        let add4_scaled_mul_slice4 = mul[22];
        let q_add_mul_q_double = mul[23];
        let q_add_mul_q_skew = mul[24];
        let q_double_mul_q_skew = mul[25];
        let round_transition = mul[26];
        let q_double_shift_scaled_mul_q_skew_shift_scaled = mul[27];
        let q_double_mul_q_double_shift = mul[28];
        let q_double_mul_q_add_shift_scaled = mul[29];
        let msm_transition_shift_scaled_mul_round_delta_scaled = mul[30];
        let msm_transition_shift_mul_count_shift = mul[31];
        let msm_transition_shift_mul_pc_shift_msm_size_pc = mul[32];
        let add2_mul_add1_scaled = mul[33];
        let add3_mul_add2_scaled = mul[34];
        let add4_mul_add3_scaled = mul[35];
        let q_add_mul_q_add_shift = mul[36];
        let q_skew_mul_q_skew_shift = mul[37];
        let add4_scaled_mul_add1_shift = mul[38];
        lhs2.extend(add2);
        rhs2.extend(T::sub_many(x2, &x_t1));
        let mut x_out_1_factor = x2.to_owned();
        T::scale_many_in_place(&mut x_out_1_factor, minus_one);
        T::sub_assign_many(&mut x_out_1_factor, &x_t1);
        T::sub_assign_many(&mut x_out_1_factor, &x_t1);
        lhs2.extend(add2);
        rhs2.extend(x_out_1_factor);

        //THIS IS THE DOUBLE STUFF:
        let mut double_relation = T::sub_many(lambda1_mul_2acc_y, acc_x_mul_3_acc_x);

        let x_out_dbl_1 = T::sub_many(
            lambda1_sqr,
            &T::scale_many(acc_x, P::ScalarField::from(2u64)),
        );
        lhs2.extend(lambda1);
        rhs2.extend(T::sub_many(acc_x, &x_out_dbl_1)); // this gives us y_out_dbl_1 (still need to do "-acc_y")

        lhs2.extend(T::scale_many(&x_out_dbl_1, P::ScalarField::from(3u64))); //this us the second term in the second summand which gets subtracted from double_relation
        rhs2.extend(x_out_dbl_1.clone());
        let x_out_dbl_2 = T::sub_many(
            lambda2_sqr,
            &T::scale_many(&x_out_dbl_1, P::ScalarField::from(2u64)),
        );
        lhs2.extend(lambda2);
        rhs2.extend(T::sub_many(&x_out_dbl_1, &x_out_dbl_2)); // this gives us y_out_dbl_2 (still need to do "-y_d1")

        lhs2.extend(T::scale_many(&x_out_dbl_2, P::ScalarField::from(3u64))); //this us the second term in the third summand which gets subtracted from double_relation
        rhs2.extend(x_out_dbl_2.clone());
        let x_out_dbl_3 = T::sub_many(
            lambda3_sqr,
            &T::scale_many(&x_out_dbl_2, P::ScalarField::from(2u64)),
        );
        lhs2.extend(lambda3);
        rhs2.extend(T::sub_many(&x_out_dbl_2, &x_out_dbl_3)); // this gives us y_out_dbl_3 (still need to do "-y_d2")

        lhs2.extend(T::scale_many(&x_out_dbl_3, P::ScalarField::from(3u64))); //this us the second term in the fourth summand which gets subtracted from double_relation
        rhs2.extend(x_out_dbl_3.clone());
        let x_out_dbl_4 = T::sub_many(
            lambda4_sqr,
            &T::scale_many(&x_out_dbl_3, P::ScalarField::from(2u64)),
        );
        lhs2.extend(lambda4);
        rhs2.extend(T::sub_many(&x_out_dbl_3, &x_out_dbl_4)); // this gives us y_out_dbl_4 (still need to do "-y_d3")

        lhs2.extend(q_double);
        rhs2.extend(T::sub_many(acc_x_shift, &x_out_dbl_4)); // this gives us the unscaled r10 accumulator term

        lhs2.extend(skew1_select.clone());
        rhs2.extend(T::add_many(&T::sub_many(skew_relation_1_term, y1), acc_y)); // this gives us the mul of skew_relation_1
        let mut x_out_21 = T::add_many(lambda1_sqr, x_out_21_factor);
        T::add_assign_many(&mut x_out_21, acc_x);
        lhs2.extend(lambda1);
        rhs2.extend(T::sub_many(acc_x, &x_out_21)); // this gives us the first summand of y_out_21
        lhs2.extend(skew1_select);
        rhs2.extend(T::scale_many(acc_y, P::ScalarField::from(-2))); // this gives us the second summand of y_out_21 

        lhs2.extend(lambda2.to_owned());
        rhs2.extend(T::sub_many(x2, &T::add_scalar(&x_out_21, one, id))); // this gives us one term of skew_relation_2
        lhs2.extend(skew2_select.clone());
        rhs2.extend(T::sub_many(x2, &x_out_21)); // this gives us x2_skew_collision_relation
        lhs2.extend(skew2_select.clone());
        rhs2.extend(T::sub_many(
            &T::scale_many(x2, minus_one),
            &T::scale_many(&x_out_21, P::ScalarField::from(2u64)),
        )); //this gives us the mul of x_out_22

        // Starting from // ROUND TRANSITION LOGIC
        lhs2.extend(round_transition);
        rhs2.extend(T::add_scalar(&round_delta, minus_one, id)); // leading to r18

        lhs2.extend(round_transition);
        rhs2.extend(q_skew_shift); // leading to r19

        lhs2.extend(round_transition);
        rhs2.extend(T::add_many(
            q_skew_shift,
            &T::add_scalar(q_double_shift, minus_one, id),
        )); // leading to r20

        lhs2.extend(round_transition);
        rhs2.extend(q_double_shift_scaled_mul_q_skew_shift_scaled); // leading to r21

        lhs2.extend(msm_transition_shift_scaled_mul_round_delta_scaled);
        let mut r24_factor = count_shift.to_owned();
        T::sub_assign_many(&mut r24_factor, count);
        T::sub_assign_many(&mut r24_factor, add1);
        T::sub_assign_many(&mut r24_factor, add2);
        T::sub_assign_many(&mut r24_factor, add3);
        T::sub_assign_many(&mut r24_factor, add4);
        rhs2.extend(r24_factor); // leading to r24

        lhs2.extend(round_transition);
        rhs2.extend(count_shift); // leading to r25

        lhs2.extend(T::add_many(q_add_mul_q_add_shift, q_skew_mul_q_skew_shift));
        rhs2.extend(add4_scaled_mul_add1_shift); // leading to r31

        let mul2 = T::mul_many(&lhs2, &rhs2, net, state)?;
        let mul2 = mul2.chunks_exact(mul2.len() / 26).collect_vec();
        debug_assert_eq!(mul2.len(), 26);

        let mut add_relation = mul2[0].to_owned();
        T::sub_assign_many(&mut add_relation, &T::sub_many(&y, y1));
        let add_relation_1_mul = mul2[1];
        let y_t1 = T::sub_many(mul2[2], y1);
        let x2_collision_relation = mul2[3];

        let mut x_out_1 = lambda2_sqr.to_owned();
        T::add_assign_many(&mut x_out_1, mul2[4]);
        T::add_assign_many(&mut x_out_1, &x_t1);

        let mut y_out_dbl_1 = mul2[5].to_owned();
        T::sub_assign_many(&mut y_out_dbl_1, acc_y);

        T::sub_assign_many(&mut double_relation, mul2[6]); // this is the "-" term in the first double relation accumulation

        let mut y_out_dbl_2 = mul2[7].to_owned();
        T::sub_assign_many(&mut y_out_dbl_2, &y_out_dbl_1);

        T::sub_assign_many(&mut double_relation, mul2[8]); // this is the "-" term in the second double relation accumulation

        let mut y_out_dbl_3 = mul2[9].to_owned();
        T::sub_assign_many(&mut y_out_dbl_3, &y_out_dbl_2);

        T::sub_assign_many(&mut double_relation, mul2[10]); // this is the "-" term in the third double relation accumulation

        let mut y_out_dbl_4 = mul2[11].to_owned();
        T::sub_assign_many(&mut y_out_dbl_4, &y_out_dbl_3);

        let tmp_r10 = mul2[12];

        let mut skew_relation = mul2[13].to_owned();
        T::add_assign_many(&mut skew_relation, lambda1); // This is the first summand of skew_relation

        let mut y_out_21 = T::add_many(mul2[14], mul2[15]);
        T::add_assign_many(&mut y_out_21, acc_y);

        let skew_relation_2_term = mul2[16].to_owned();

        let x2_skew_collision_relation = mul2[17];
        let mut x_out_22 = T::add_many(mul2[18], lambda2_sqr);
        T::add_assign_many(&mut x_out_22, &x_out_21);

        let tmp_r18 = mul2[19];

        let round_transition_mul_q_skew_shift = mul2[20]; // This is needed for r19 (need to multiply with last factor)

        let tmp_r20 = mul2[21];
        let tmp_r21 = mul2[22];

        let tmp_r24 = mul2[23];
        let tmp_r25 = mul2[24];
        let tmp_r31 = mul2[25];

        // ADD Operations (3rd Mul round)
        let mut lhs3 = Vec::with_capacity(16 * add2.len());
        let mut rhs3 = Vec::with_capacity(lhs3.len());

        lhs3.extend(add2.to_owned());
        rhs3.extend(T::sub_many(&T::add_many(add_relation_1_mul, &y_t1), y2)); // This gives us the first summand of add_relation (BUT need to add also lambda2)

        lhs3.extend(lambda2.to_owned());
        rhs3.extend(T::sub_many(&x_t1, &x_out_1)); // This gives us the first summand of y_out_1
        lhs3.extend(add2.to_owned());
        rhs3.extend(T::scale_many(&y_t1, P::ScalarField::from(-2))); // This gives us the second summand of y_out_1

        lhs3.extend(lambda3.to_owned());
        rhs3.extend(&T::sub_many(x3, &T::add_scalar(&x_out_1, one, id))); //This gives us the first multiplication in the second addition to add_relation
        lhs3.extend(add3.to_owned());
        rhs3.extend(T::sub_many(x3, &x_out_1)); // This gives us x3_collision_relation
        lhs3.extend(add3.to_owned());
        rhs3.extend(&T::sub_many(
            &T::scale_many(x3, minus_one),
            &T::scale_many(&x_out_1, P::ScalarField::from(2u64)),
        )); // This gives us the mul in x_out_2

        // DBL STUFF:
        lhs3.extend(lambda2.to_owned());
        rhs3.extend(T::scale_many(&y_out_dbl_1, P::ScalarField::from(2u64))); // missing part of first contribution to double_relation
        lhs3.extend(lambda3.to_owned());
        rhs3.extend(T::scale_many(&y_out_dbl_2, P::ScalarField::from(2u64))); // missing part of second contribution to double_relation
        lhs3.extend(lambda4.to_owned());
        rhs3.extend(T::scale_many(&y_out_dbl_3, P::ScalarField::from(2u64))); // missing part of third contribution

        lhs3.extend(q_double.to_owned());
        rhs3.extend(T::sub_many(acc_y_shift, &y_out_dbl_4)); // This gives us the unscaled r11 accumulator term

        lhs3.extend(skew2_select.to_owned());
        rhs3.extend(T::add_many(
            &T::sub_many(&skew_relation_2_term, y2),
            &y_out_21,
        )); // This gives us the mul of skew_relation_2 (Still need to add lambda2)

        lhs3.extend(lambda2);
        rhs3.extend(T::sub_many(&x_out_21, &x_out_22)); // this gives us the first summand of y_out_22
        lhs3.extend(skew2_select);
        rhs3.extend(T::scale_many(&y_out_21, P::ScalarField::from(-2))); // this gives us the second summand of y_out_22 
        lhs3.extend(lambda3.to_owned());
        rhs3.extend(T::sub_many(x3, &T::add_scalar(&x_out_22, one, id))); // this gives us one term of skew_relation_3
        lhs3.extend(skew3_select.clone());
        rhs3.extend(T::sub_many(x3, &x_out_22)); // this gives us x3_skew_collision_relation
        lhs3.extend(skew3_select.clone());
        rhs3.extend(T::sub_many(
            &T::scale_many(x3, minus_one),
            &T::scale_many(&x_out_22, P::ScalarField::from(2u64)),
        )); //this gives us the mul of x_out_23

        let mul3 = T::mul_many(&lhs3, &rhs3, net, state)?;
        let mul3 = mul3.chunks_exact(mul3.len() / 16).collect_vec();
        debug_assert_eq!(mul3.len(), 16);

        T::add_assign_many(&mut add_relation, mul3[0]);
        T::add_assign_many(&mut add_relation, lambda2); // This is the first summand of add_relation done

        let mut y_out_1 = T::add_many(mul3[1], mul3[2]);
        T::add_assign_many(&mut y_out_1, &y_t1);

        let add_relation_2_mul = mul3[3];
        let x3_collision_relation = mul3[4];

        let mut x_out_2 = T::add_many(mul3[5], lambda3_sqr);
        T::add_assign_many(&mut x_out_2, &x_out_1);

        T::add_assign_many(&mut double_relation, mul3[6]); // This is the "+" term in the first double relation accumulation
        T::add_assign_many(&mut double_relation, mul3[7]); // This is the "+" term in the second double relation accumulation
        T::add_assign_many(&mut double_relation, mul3[8]); // This is the "+" term in the third double relation accumulation
        let tmp_r11 = mul3[9].to_owned();

        T::add_assign_many(&mut skew_relation, mul3[10]);
        T::add_assign_many(&mut skew_relation, lambda2); // This is the second summand of skew_relation done

        let mut y_out_22 = T::add_many(mul3[11], mul3[12]);
        T::add_assign_many(&mut y_out_22, &y_out_21);

        let skew_relation_3_term = mul3[13].to_owned();
        let x3_skew_collision_relation = mul3[14];
        let mut x_out_23 = T::add_many(mul3[15], lambda3_sqr);
        T::add_assign_many(&mut x_out_23, &x_out_22);

        let mut lhs4 = Vec::with_capacity(13 * add3.len());
        let mut rhs4 = Vec::with_capacity(lhs4.len());

        lhs4.extend(add3.to_owned());
        rhs4.extend(T::sub_many(&T::add_many(add_relation_2_mul, &y_out_1), y3)); // This gives us the second summand of add_relation (BUT need to add also lambda3)
        lhs4.extend(lambda3.to_owned());
        rhs4.extend(T::sub_many(&x_out_1, &x_out_2)); // This gives us the first summand of y_out_2
        lhs4.extend(add3.to_owned());
        rhs4.extend(T::scale_many(&y_out_1, P::ScalarField::from(-2))); // This gives us the second summand of y_out_2

        lhs4.extend(lambda4.to_owned());
        rhs4.extend(&T::sub_many(x4, &T::add_scalar(&x_out_2, one, id))); //This gives us the first multiplication in the third addition to add_relation
        lhs4.extend(add4.to_owned());
        rhs4.extend(T::sub_many(x4, &x_out_2)); // This gives us x4_collision_relation
        lhs4.extend(add4.to_owned());
        rhs4.extend(&T::sub_many(
            &T::scale_many(x4, minus_one),
            &T::scale_many(&x_out_2, P::ScalarField::from(2u64)),
        )); // This gives us the mul in x_out_3

        lhs4.extend(q_double.to_owned());
        rhs4.extend(double_relation.to_owned()); // This gives us the (unscaled) r12 accumulator term

        lhs4.extend(skew3_select.to_owned());
        rhs4.extend(T::add_many(
            &T::sub_many(&skew_relation_3_term, y3),
            &y_out_22,
        )); // This gives us the mul of skew_relation_3 (Still need to add lambda3)

        lhs4.extend(lambda3);
        rhs4.extend(T::sub_many(&x_out_22, &x_out_23)); // this gives us the first summand of y_out_23
        lhs4.extend(skew3_select);
        rhs4.extend(T::scale_many(&y_out_22, P::ScalarField::from(-2))); // this gives us the second summand of y_out_23
        lhs4.extend(lambda4.to_owned());
        rhs4.extend(T::sub_many(x4, &T::add_scalar(&x_out_23, one, id))); // this gives us one term of skew_relation_4
        lhs4.extend(skew4_select.clone());
        rhs4.extend(T::sub_many(x4, &x_out_23)); // this gives us x3_skew_collision_relation
        lhs4.extend(skew4_select.clone());
        rhs4.extend(T::sub_many(
            &T::scale_many(x4, minus_one),
            &T::scale_many(&x_out_23, P::ScalarField::from(2u64)),
        )); //this gives us the mul of x_out_24

        let mul4 = T::mul_many(&lhs4, &rhs4, net, state)?;
        let mul4 = mul4.chunks_exact(mul4.len() / 13).collect_vec();
        debug_assert_eq!(mul4.len(), 13);

        T::add_assign_many(&mut add_relation, mul4[0]);
        T::add_assign_many(&mut add_relation, lambda3); //second contribution to add_relation done

        let mut y_out_2 = T::add_many(mul4[1], mul4[2]);
        T::add_assign_many(&mut y_out_2, &y_out_1);

        let add_relation_3_mul = mul4[3];
        let x4_collision_relation = mul4[4];

        let mut x_out_3 = T::add_many(mul4[5], lambda4_sqr);
        T::add_assign_many(&mut x_out_3, &x_out_2);

        let tmp_r12 = mul4[6];

        T::add_assign_many(&mut skew_relation, mul4[7]);
        T::add_assign_many(&mut skew_relation, lambda3); // This is the third summand of skew_relation done
        let mut y_out_23 = T::add_many(mul4[8], mul4[9]);
        T::add_assign_many(&mut y_out_23, &y_out_22);

        let skew_relation_4_term = mul4[10].to_owned();

        let x4_skew_collision_relation = mul4[11];
        let mut x_out_24 = T::add_many(mul4[12], lambda4_sqr);
        T::add_assign_many(&mut x_out_24, &x_out_23);

        let mut lhs5 = Vec::with_capacity(15 * add4.len());
        let mut rhs5 = Vec::with_capacity(lhs5.len());

        lhs5.extend(add4.to_owned());
        rhs5.extend(T::sub_many(&T::add_many(add_relation_3_mul, &y_out_2), y4)); // This gives us the third summand of add_relation
        lhs5.extend(lambda4.to_owned());
        rhs5.extend(T::sub_many(&x_out_2, &x_out_3)); // This gives us the first summand of y_out_3
        lhs5.extend(add4.to_owned());
        rhs5.extend(T::scale_many(&y_out_2, P::ScalarField::from(-2))); // This gives us the second summand of y_out_3

        lhs5.extend(skew4_select.to_owned());
        rhs5.extend(T::add_many(
            &T::sub_many(&skew_relation_4_term, y4),
            &y_out_23,
        )); // This gives us the mul of skew_relation_4 (Still need to add lambda4)
        lhs5.extend(lambda4);
        rhs5.extend(T::sub_many(&x_out_23, &x_out_24)); // this gives us the first summand of y_out_24
        lhs5.extend(skew4_select);
        rhs5.extend(T::scale_many(&y_out_23, P::ScalarField::from(-2))); // this gives us the second summand of y_out_24

        // This is for the x_i_deltas:
        lhs5.extend(q_skew.to_owned());
        rhs5.extend(x1_skew_collision_relation.to_owned());
        lhs5.extend(q_add.to_owned());
        rhs5.extend(x1_collision_relation.to_owned());
        lhs5.extend(q_add.to_owned());
        rhs5.extend(x2_collision_relation.to_owned());
        lhs5.extend(q_skew.to_owned());
        rhs5.extend(x2_skew_collision_relation.to_owned());
        lhs5.extend(q_skew.to_owned());
        rhs5.extend(x3_skew_collision_relation.to_owned());
        lhs5.extend(q_add.to_owned());
        rhs5.extend(x3_collision_relation.to_owned());
        lhs5.extend(q_skew.to_owned());
        rhs5.extend(x4_skew_collision_relation.to_owned());
        lhs5.extend(q_add.to_owned());
        rhs5.extend(x4_collision_relation.to_owned());

        //Final mul for r19:
        lhs5.extend(round_transition_mul_q_skew_shift);
        rhs5.extend(T::add_scalar(round, P::ScalarField::from(-31), id)); // leading to r19

        let mul5 = T::mul_many(&lhs5, &rhs5, net, state)?;
        let mul5 = mul5.chunks_exact(mul5.len() / 15).collect_vec();
        debug_assert_eq!(mul5.len(), 15);

        T::add_assign_many(&mut add_relation, mul5[0]);
        T::add_assign_many(&mut add_relation, lambda4); // third contribution to add_relation done
        let mut y_out_3 = T::add_many(mul5[1], mul5[2]);
        T::add_assign_many(&mut y_out_3, &y_out_2);

        T::add_assign_many(&mut skew_relation, mul5[3]);
        T::add_assign_many(&mut skew_relation, lambda4); // This is the fourth summand of skew_relation done
        let mut y_out_24 = T::add_many(mul5[4], mul5[5]);
        T::add_assign_many(&mut y_out_24, &y_out_23);
        let x1_delta = T::add_many(mul5[6], mul5[7]);
        let x2_delta = T::add_many(mul5[8], mul5[9]);
        let x3_delta = T::add_many(mul5[10], mul5[11]);
        let x4_delta = T::add_many(mul5[12], mul5[13]);
        let tmp_r19 = mul5[14].to_owned();

        let mut lhs6 = Vec::with_capacity(10 * q_add.len());
        let mut rhs6 = Vec::with_capacity(lhs6.len());

        lhs6.extend(q_add.to_owned());
        rhs6.extend(T::sub_many(acc_x_shift, &x_out_3)); // this is for r0

        lhs6.extend(q_add.to_owned());
        rhs6.extend(T::sub_many(acc_y_shift, &y_out_3)); // this is for r1

        lhs6.extend(q_add.to_owned());
        rhs6.extend(add_relation); // this is for r2

        lhs6.extend(q_skew.to_owned());
        rhs6.extend(T::sub_many(acc_x_shift, &x_out_24)); // this is for r3

        lhs6.extend(q_skew.to_owned());
        rhs6.extend(T::sub_many(acc_y_shift, &y_out_24)); // this is for r4

        lhs6.extend(q_skew.to_owned());
        rhs6.extend(skew_relation); // this is for r5

        lhs6.extend(x1_delta.to_owned());
        rhs6.extend(collision_inverse1); // this is for r6

        lhs6.extend(x2_delta.to_owned());
        rhs6.extend(collision_inverse2); // this is for r7

        lhs6.extend(x3_delta.to_owned());
        rhs6.extend(collision_inverse3); // this is for r8

        lhs6.extend(x4_delta.to_owned());
        rhs6.extend(collision_inverse4); // this is for r9

        let mul6 = T::mul_many(&lhs6, &rhs6, net, state)?;
        let mul6 = mul6.chunks_exact(mul6.len() / 10).collect_vec();
        debug_assert_eq!(mul6.len(), 10);

        let tmp_r0 = mul6[0];
        let tmp_r1 = mul6[1];
        let tmp_r2 = mul6[2];
        let tmp_r3 = mul6[3];
        let tmp_r4 = mul6[4];
        let tmp_r5 = mul6[5];
        let tmp_r6 = mul6[6];
        let tmp_r7 = mul6[7];
        let tmp_r8 = mul6[8];
        let tmp_r9 = mul6[9];

        // ADD operations (if row represents ADD round, not SKEW or DOUBLE)

        // Validate accumulator output matches ADD output if q_add = 1
        // (this is a degree-6 relation)
        let mut tmp = tmp_r0.to_owned(); //q_add.to_owned() * (acc_x_shift.to_owned() - x_out_3) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        let mut tmp = tmp_r1.to_owned(); //q_add.to_owned() * (acc_y_shift.to_owned() - y_out_3) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        let mut tmp = tmp_r2.to_owned(); // q_add.to_owned() * add_relation * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r2, tmp, SIZE);

        /*
         * @brief doubles a point.
         *
         * Degree of x_out = 2
         * Degree of y_out = 3
         * Degree of relation = 4
         */
        // let dbl = |x: &Univariate<P::ScalarField, SIZE>,
        //            y: &Univariate<P::ScalarField, SIZE>,
        //            lambda: &Univariate<P::ScalarField, SIZE>,
        //            relation: &mut Univariate<P::ScalarField, SIZE>| {
        //     let two_x = x.to_owned();
        // T::scale_many(&mut two_x, P::ScalarField::from(2));
        //     *relation += lambda.to_owned() * (y.to_owned() + y) - (two_x.to_owned() + x) * x;
        //     let x_out = lambda.to_owned() * lambda - two_x;
        //     let y_out = lambda.to_owned() * (x.to_owned() - &x_out) - y;
        //     (x_out, y_out)
        // };

        /*
         * @brief
         *
         * Algorithm to determine if round is a DOUBLE round:
         *    1. count_shift >= msm_size
         *    2. round != 32
         *
         * Algorithm to process MSM DOUBLE round:
         * [Acc_shift] = (([Acc].double()).double()).double()
         *
         * As with additions, the column q_double describes whether row is a double round. It is Prover-defined.
         * The value of `msm_round` can only update when `q_double = 1` and we use this to ensure Prover correctly sets
         * `q_double`. (see round transition relations further down)
         */

        let mut tmp = tmp_r10.to_owned(); //q_double.to_owned() * (acc_x_shift.to_owned() - x_out_dbl_4) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r10, tmp, SIZE);

        let mut tmp = tmp_r11.to_owned(); // q_double.to_owned() * (acc_y_shift.to_owned() - y_out_dbl_4) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r11, tmp, SIZE);

        let mut tmp = tmp_r12.to_owned(); // q_double.to_owned() * double_relation * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r12, tmp, SIZE);
        /*
         * @brief SKEW operations
         * When computing x * [P], if x is even we must subtract [P] from accumulator
         * (this is because our windowed non-adjacent-form can only represent odd numbers)
         * Round 32 represents "skew" round.
         * If scalar slice == 7, we add into accumulator (point_table[7] maps to -[P])
         * If scalar slice == 0, we do not add into accumulator
         * i.e. for the skew round we can use the slice values as our "selector" when doing conditional point adds
         */

        // Validate accumulator output matches SKEW output if q_skew = 1
        // (this is a degree-6 relation)
        let mut tmp = tmp_r3.to_owned(); // q_skew.to_owned() * (acc_x_shift.to_owned() - x_out_24) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r3, tmp, SIZE);

        let mut tmp = tmp_r4.to_owned(); // q_skew.to_owned() * (acc_y_shift.to_owned() - y_out_24) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r4, tmp, SIZE);

        let mut tmp = tmp_r5.to_owned(); // q_skew.to_owned() * skew_relation * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r5, tmp, SIZE);

        // Check x-coordinates do not collide if row is an ADD row or a SKEW row
        // if either q_add or q_skew = 1, an inverse should exist for each computed relation
        // Step 1: construct boolean selectors that describe whether we added a point at the current row
        let add_first_point = T::add_many(add1_mul_q_add, q_skew_mul_skew1_select);
        let add_second_point = T::add_many(add2_mul_q_add, q_skew_mul_skew2_select);
        let add_third_point = T::add_many(add3_mul_q_add, q_skew_mul_skew3_select);
        let add_fourth_point = T::add_many(add4_mul_q_add, q_skew_mul_skew4_select);
        // Step 2: construct the delta between x-coordinates for each point add (depending on if row is ADD or SKEW)

        // Step 3: x_delta * inverse - 1 = 0 if we performed a point addition (else x_delta * inverse = 0)
        let mut tmp = tmp_r6.to_owned(); // (x1_delta * collision_inverse1 - add_first_point) * scaling_factors;
        T::sub_assign_many(&mut tmp, &add_first_point);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r6, tmp, SIZE);

        let mut tmp = tmp_r7.to_owned(); // (x2_delta * collision_inverse2 - add_second_point) * scaling_factors;
        T::sub_assign_many(&mut tmp, &add_second_point);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r7, tmp, SIZE);

        let mut tmp = tmp_r8.to_owned(); // (x3_delta * collision_inverse3 - add_third_point) * scaling_factors;
        T::sub_assign_many(&mut tmp, &add_third_point);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r8, tmp, SIZE);

        let mut tmp = tmp_r9.to_owned(); // (x4_delta * collision_inverse4 - add_fourth_point) * scaling_factors;
        T::sub_assign_many(&mut tmp, &add_fourth_point);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r9, tmp, SIZE);

        // Validate that if q_add = 1 or q_skew = 1, add1 also is 1
        // AZTEC TODO(@zac-williamson) Once we have a stable base to work off of, remove q_add1 and replace with q_msm_add +
        // q_msm_skew (issue ?)
        let mut tmp = add1.to_owned(); // - q_add - q_skew) * scaling_factors;
        T::sub_assign_many(&mut tmp, q_add);
        T::sub_assign_many(&mut tmp, q_skew);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r32, tmp, SIZE);

        // If add_i = 0, slice_i = 0
        // When add_i = 0, force slice_i to ALSO be 0
        let mut tmp = add1_scaled_mul_slice1.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r13, tmp, SIZE);

        let mut tmp = add2_scaled_mul_slice2.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r14, tmp, SIZE);

        let mut tmp = add3_scaled_mul_slice3.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r15, tmp, SIZE);

        let mut tmp = add4_scaled_mul_slice4.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r16, tmp, SIZE);

        // only one of q_skew, q_double, q_add can be nonzero
        let mut tmp = q_add_mul_q_double.to_owned();
        T::add_assign_many(&mut tmp, q_add_mul_q_skew);
        T::add_assign_many(&mut tmp, q_double_mul_q_skew);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r17, tmp, SIZE);

        // We look up wnaf slices by mapping round + pc -> slice
        // We use an exact set membership check to validate that
        // wnafs written in wnaf_relation == wnafs read in msm relation
        // We use `add1/add2/add3/add4` to flag whether we are performing a wnaf read op
        // We can set these to be Prover-defined as the set membership check implicitly ensures that the correct reads
        // have occurred.
        // if msm_transition = 0, round_shift - round = 0 or 1

        // ROUND TRANSITION LOGIC (when round does not change)
        // If msm_transition = 0 (next row) then round_delta = 0 or 1
        // let round_transition = round_delta.clone() * (msm_transition_shift_scaled);

        let mut tmp = tmp_r18.to_owned(); //round_transition.clone() * (round_delta.clone() - 1) * scaling_factors; 
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r18, tmp, SIZE);

        // ROUND TRANSITION LOGIC (when round DOES change)
        // round_transition describes whether we are transitioning between rounds of an MSM
        // If round_transition = 1, the next row is either a double (if round != 31) or we are adding skew (if round ==
        // 31) round_transition * skew * (round - 31) = 0 (if round tx and skew, round == 31) round_transition * (skew +
        // double - 1) = 0 (if round tx, skew XOR double = 1) i.e. if round tx and round != 31, double = 1
        let mut tmp = tmp_r19.to_owned();
        // round_transition.clone()
        //     * q_skew_shift
        //     * (round.to_owned() + &P::ScalarField::from(-31))
        //     * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r19, tmp, SIZE);

        let mut tmp = tmp_r20.to_owned(); // round_transition.clone()
        // *(q_skew_shift.to_owned() + q_double_shift - &one) * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r20, tmp, SIZE);

        // if no double or no skew, round_delta = 0
        let mut tmp = tmp_r21.to_owned(); // round_transition.clone()
        // * q_double_shift_scaled_mul_q_skew_shift_scaled
        // * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r21, tmp, SIZE);

        // if double, next double != 1
        let mut tmp = q_double_mul_q_double_shift.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r22, tmp, SIZE);

        // if double, next add = 1
        let mut tmp = q_double_mul_q_add_shift_scaled.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r23, tmp, SIZE);

        // updating count
        // if msm_transition = 0 and round_transition = 0, count_shift = count + add1 + add2 + add3 + add4
        // todo: we need this?
        let mut tmp = tmp_r24.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r24, tmp, SIZE);

        let mut tmp = tmp_r25.to_owned(); // is_not_first_row.clone() * round_transition * count_shift * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        T::mul_assign_with_public_many(&mut tmp, &is_not_first_row);
        fold_accumulator!(univariate_accumulator.r25, tmp, SIZE);

        // if msm_transition = 1, count_shift = 0
        let mut tmp = msm_transition_shift_mul_count_shift.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        T::mul_assign_with_public_many(&mut tmp, &is_not_first_row);
        fold_accumulator!(univariate_accumulator.r26, tmp, SIZE);

        // if msm_transition = 1, pc = pc_shift + msm_size
        // `ecc_set_relation` ensures `msm_size` maps to `transcript.msm_count` for the current value of `pc`
        let mut tmp = msm_transition_shift_mul_pc_shift_msm_size_pc.to_owned();
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        T::mul_assign_with_public_many(&mut tmp, &is_not_first_row);
        fold_accumulator!(univariate_accumulator.r27, tmp, SIZE);

        // Addition continuity checks
        // We want to RULE OUT the following scenarios:
        // Case 1: add2 = 1, add1 = 0
        // Case 2: add3 = 1, add2 = 0
        // Case 3: add4 = 1, add3 = 0
        // These checks ensure that the current row does not skip points (for both ADD and SKEW ops)
        // This is part of a wider set of checks we use to ensure that all point data is used in the assigned
        // multiscalar multiplication operation.
        // (and not in a different MSM operation)
        let mut tmp = add2_mul_add1_scaled.to_owned(); // * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r28, tmp, SIZE);

        let mut tmp = add3_mul_add2_scaled.to_owned(); // * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r29, tmp, SIZE);

        let mut tmp = add4_mul_add3_scaled.to_owned(); // * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r30, tmp, SIZE);

        // Final continuity check.
        // If an addition spans two rows, we need to make sure that the following scenario is RULED OUT:
        //   add4 = 0 on the CURRENT row, add1 = 1 on the NEXT row
        // We must apply the above for the two cases:
        // Case 1: q_add = 1 on the CURRENT row, q_add = 1 on the NEXT row
        // Case 2: q_skew = 1 on the CURRENT row, q_skew = 1 on the NEXT row
        // (i.e. if q_skew = 1, q_add_shift = 1 this implies an MSM transition so we skip this continuity check)
        let mut tmp = tmp_r31.to_owned();
        // (q_add_mul_q_add_shift + q_skew_mul_q_skew_shift)
        //     * add4_scaled_mul_add1_shift
        //     * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r31, tmp, SIZE);

        // remaining checks (done in ecc_set_relation.hpp, ecc_lookup_relation.hpp)
        // when transition occurs, perform set membership lookup on (accumulator / pc / msm_size)
        // perform set membership lookups on add_i * (pc / round / slice_i)
        // perform lookups on (pc / slice_i / x / y)
        Ok(())
    }
}
