use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;
#[derive(Clone, Debug)]
pub(crate) struct EccBoolsRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 3>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
    pub(crate) r2: SharedUnivariate<T, P, 3>,
    pub(crate) r3: SharedUnivariate<T, P, 3>,
    pub(crate) r4: SharedUnivariate<T, P, 3>,
    pub(crate) r5: SharedUnivariate<T, P, 3>,
    pub(crate) r6: SharedUnivariate<T, P, 3>,
    pub(crate) r7: SharedUnivariate<T, P, 3>,
    pub(crate) r8: SharedUnivariate<T, P, 3>,
    pub(crate) r9: SharedUnivariate<T, P, 3>,
    pub(crate) r10: SharedUnivariate<T, P, 3>,
    pub(crate) r11: SharedUnivariate<T, P, 3>,
    pub(crate) r12: SharedUnivariate<T, P, 3>,
    pub(crate) r13: SharedUnivariate<T, P, 3>,
    pub(crate) r14: SharedUnivariate<T, P, 3>,
    pub(crate) r15: SharedUnivariate<T, P, 3>,
    pub(crate) r16: SharedUnivariate<T, P, 3>,
    pub(crate) r17: SharedUnivariate<T, P, 3>,
    pub(crate) r18: SharedUnivariate<T, P, 3>,
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccBoolsRelationAcc<T, P> {
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
        }
    }
}

pub(crate) struct EccBoolsRelation {}
impl EccBoolsRelation {
    pub(crate) const NUM_RELATIONS: usize = 19;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 19;
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccBoolsRelationAcc<T, P> {
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
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccBoolsRelation
{
    type Acc = EccBoolsRelationAcc<T, P>;
    type VerifyAcc = (); // Not need for ECCVM

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_transcript_z1zero(entity);
        batch.add_transcript_z2zero(entity);
        batch.add_transcript_msm_count_zero_at_transition(entity);
        batch.add_transcript_add(entity);
        batch.add_transcript_mul(entity);
        batch.add_transcript_eq(entity);
        batch.add_transcript_msm_transition(entity);
        batch.add_transcript_accumulator_empty(entity);
        batch.add_transcript_reset_accumulator(entity);
        batch.add_transcript_base_infinity(entity);
        batch.add_transcript_msm_infinity(entity);
        batch.add_transcript_add_x_equal(entity);
        batch.add_transcript_add_y_equal(entity);
        batch.add_precompute_point_transition(entity);
        batch.add_msm_transition(entity);
        batch.add_msm_add(entity);
        batch.add_msm_double(entity);
        batch.add_msm_skew(entity);
        batch.add_precompute_select(entity);
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
        let z1_zero = input.witness.transcript_z1zero();
        let z2_zero = input.witness.transcript_z2zero();
        let msm_count_zero_at_transition = input.witness.transcript_msm_count_zero_at_transition();
        let q_add = input.witness.transcript_add();
        let q_mul = input.witness.transcript_mul();
        let q_eq = input.witness.transcript_eq();
        let transcript_msm_transition = input.witness.transcript_msm_transition();
        let is_accumulator_empty = input.witness.transcript_accumulator_empty();
        let q_reset_accumulator = input.witness.transcript_reset_accumulator();
        let transcript_pinfinity = input.witness.transcript_base_infinity();
        let transcript_msm_infinity = input.witness.transcript_msm_infinity();
        let transcript_add_x_equal = input.witness.transcript_add_x_equal();
        let transcript_add_y_equal = input.witness.transcript_add_y_equal();
        let precompute_point_transition = input.witness.precompute_point_transition();
        let msm_transition = input.witness.msm_transition();
        let msm_add = input.witness.msm_add();
        let msm_double = input.witness.msm_double();
        let msm_skew = input.witness.msm_skew();
        let precompute_select = input.witness.precompute_select();

        let mut lhs = Vec::with_capacity(
            q_eq.len()
                + q_add.len()
                + q_mul.len()
                + q_reset_accumulator.len()
                + transcript_msm_transition.len()
                + is_accumulator_empty.len()
                + z1_zero.len()
                + z2_zero.len()
                + transcript_add_x_equal.len()
                + transcript_add_y_equal.len()
                + transcript_pinfinity.len()
                + transcript_msm_infinity.len()
                + msm_count_zero_at_transition.len()
                + msm_transition.len()
                + precompute_point_transition.len()
                + msm_add.len()
                + msm_double.len()
                + msm_skew.len()
                + precompute_select.len(),
        );

        lhs.extend(q_eq.clone());
        lhs.extend(q_add.clone());
        lhs.extend(q_mul.clone());
        lhs.extend(q_reset_accumulator.clone());
        lhs.extend(transcript_msm_transition.clone());
        lhs.extend(is_accumulator_empty.clone());
        lhs.extend(z1_zero.clone());
        lhs.extend(z2_zero.clone());
        lhs.extend(transcript_add_x_equal.clone());
        lhs.extend(transcript_add_y_equal.clone());
        lhs.extend(transcript_pinfinity.clone());
        lhs.extend(transcript_msm_infinity.clone());
        lhs.extend(msm_count_zero_at_transition.clone());
        lhs.extend(msm_transition.clone());
        lhs.extend(precompute_point_transition.clone());
        lhs.extend(msm_add.clone());
        lhs.extend(msm_double.clone());
        lhs.extend(msm_skew.clone());
        lhs.extend(precompute_select.clone());

        T::add_scalar_in_place(&mut lhs, P::ScalarField::from(-1), id);

        let mut rhs = Vec::with_capacity(lhs.len());
        rhs.extend(q_eq.clone());
        rhs.extend(q_add.clone());
        rhs.extend(q_mul.clone());
        rhs.extend(q_reset_accumulator.clone());
        rhs.extend(transcript_msm_transition.clone());
        rhs.extend(is_accumulator_empty.clone());
        rhs.extend(z1_zero.clone());
        rhs.extend(z2_zero.clone());
        rhs.extend(transcript_add_x_equal.clone());
        rhs.extend(transcript_add_y_equal.clone());
        rhs.extend(transcript_pinfinity.clone());
        rhs.extend(transcript_msm_infinity.clone());
        rhs.extend(msm_count_zero_at_transition.clone());
        rhs.extend(msm_transition.clone());
        rhs.extend(precompute_point_transition.clone());
        rhs.extend(msm_add.clone());
        rhs.extend(msm_double.clone());
        rhs.extend(msm_skew.clone());
        rhs.extend(precompute_select.clone());

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 19).collect_vec();
        debug_assert_eq!(mul.len(), 19);

        let q_eq_result = mul[0]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();

        fold_accumulator!(univariate_accumulator.r0, q_eq_result, SIZE);

        let q_add_result = mul[1]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();

        fold_accumulator!(univariate_accumulator.r1, q_add_result, SIZE);

        let q_mul_result = mul[2]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();

        fold_accumulator!(univariate_accumulator.r2, q_mul_result, SIZE);

        let q_reset_accumulator_result = mul[3]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();

        fold_accumulator!(univariate_accumulator.r3, q_reset_accumulator_result, SIZE);

        let transcript_msm_transition_result = mul[4]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();

        fold_accumulator!(
            univariate_accumulator.r4,
            transcript_msm_transition_result,
            SIZE
        );

        let is_accumulator_empty_result = mul[5]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r5, is_accumulator_empty_result, SIZE);

        let z1_zero_result = mul[6]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r6, z1_zero_result, SIZE);

        let z2_zero_result = mul[7]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r7, z2_zero_result, SIZE);

        let transcript_add_x_equal_result = mul[8]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(
            univariate_accumulator.r8,
            transcript_add_x_equal_result,
            SIZE
        );

        let transcript_add_y_equal_result = mul[9]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(
            univariate_accumulator.r9,
            transcript_add_y_equal_result,
            SIZE
        );

        let transcript_pinfinity_result = mul[10]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(
            univariate_accumulator.r10,
            transcript_pinfinity_result,
            SIZE
        );

        let transcript_msm_infinity_result = mul[11]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(
            univariate_accumulator.r11,
            transcript_msm_infinity_result,
            SIZE
        );

        let msm_count_zero_at_transition_result = mul[12]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(
            univariate_accumulator.r12,
            msm_count_zero_at_transition_result,
            SIZE
        );

        let msm_transition_result = mul[13]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r13, msm_transition_result, SIZE);

        let precompute_point_transition_result = mul[14]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(
            univariate_accumulator.r14,
            precompute_point_transition_result,
            SIZE
        );

        let msm_add_result = mul[15]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r15, msm_add_result, SIZE);

        let msm_double_result = mul[16]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r16, msm_double_result, SIZE);

        let msm_skew_result = mul[17]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r17, msm_skew_result, SIZE);

        let precompute_select_result = mul[18]
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        fold_accumulator!(univariate_accumulator.r18, precompute_select_result, SIZE);

        Ok(())
    }
}
