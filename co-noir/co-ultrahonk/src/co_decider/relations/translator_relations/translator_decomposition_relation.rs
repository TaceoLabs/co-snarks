use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use mpc_net::Network;
use num_bigint::BigUint;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorDecompositionRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
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
    pub(crate) r19: SharedUnivariate<T, P, 3>,
    pub(crate) r20: SharedUnivariate<T, P, 3>,
    pub(crate) r21: SharedUnivariate<T, P, 3>,
    pub(crate) r22: SharedUnivariate<T, P, 3>,
    pub(crate) r23: SharedUnivariate<T, P, 3>,
    pub(crate) r24: SharedUnivariate<T, P, 3>,
    pub(crate) r25: SharedUnivariate<T, P, 3>,
    pub(crate) r26: SharedUnivariate<T, P, 3>,
    pub(crate) r27: SharedUnivariate<T, P, 3>,
    pub(crate) r28: SharedUnivariate<T, P, 3>,
    pub(crate) r29: SharedUnivariate<T, P, 3>,
    pub(crate) r30: SharedUnivariate<T, P, 3>,
    pub(crate) r31: SharedUnivariate<T, P, 3>,
    pub(crate) r32: SharedUnivariate<T, P, 3>,
    pub(crate) r33: SharedUnivariate<T, P, 3>,
    pub(crate) r34: SharedUnivariate<T, P, 3>,
    pub(crate) r35: SharedUnivariate<T, P, 3>,
    pub(crate) r36: SharedUnivariate<T, P, 3>,
    pub(crate) r37: SharedUnivariate<T, P, 3>,
    pub(crate) r38: SharedUnivariate<T, P, 3>,
    pub(crate) r39: SharedUnivariate<T, P, 3>,
    pub(crate) r40: SharedUnivariate<T, P, 3>,
    pub(crate) r41: SharedUnivariate<T, P, 3>,
    pub(crate) r42: SharedUnivariate<T, P, 3>,
    pub(crate) r43: SharedUnivariate<T, P, 3>,
    pub(crate) r44: SharedUnivariate<T, P, 3>,
    pub(crate) r45: SharedUnivariate<T, P, 3>,
    pub(crate) r46: SharedUnivariate<T, P, 3>,
    pub(crate) r47: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorDecompositionRelationAcc<T, P> {
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
        self.r36.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r37.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r38.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r39.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r40.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r41.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r42.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r43.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r44.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r45.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r46.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r47.scale_inplace(*current_scalar);
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
    }
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default
    for TranslatorDecompositionRelationAcc<T, P>
{
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
            r36: SharedUnivariate::default(),
            r37: SharedUnivariate::default(),
            r38: SharedUnivariate::default(),
            r39: SharedUnivariate::default(),
            r40: SharedUnivariate::default(),
            r41: SharedUnivariate::default(),
            r42: SharedUnivariate::default(),
            r43: SharedUnivariate::default(),
            r44: SharedUnivariate::default(),
            r45: SharedUnivariate::default(),
            r46: SharedUnivariate::default(),
            r47: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct TranslatorDecompositionRelation {}

impl TranslatorDecompositionRelation {
    pub(crate) const NUM_RELATIONS: usize = 48;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorDecompositionRelation
{
    type Acc = TranslatorDecompositionRelationAcc<T, P>;

    type VerifyAcc = ();

    fn can_skip(
        _entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
    ) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, TranslatorFlavour>,
    ) {
        batch.add_lagrange_even_in_minicircuit(entity);
        batch.add_p_x_low_limbs(entity);
        batch.add_p_x_low_limbs_range_constraint_0(entity);
        batch.add_p_x_low_limbs_range_constraint_1(entity);
        batch.add_p_x_low_limbs_range_constraint_2(entity);
        batch.add_p_x_low_limbs_range_constraint_3(entity);
        batch.add_p_x_low_limbs_range_constraint_4(entity);
        batch.add_p_x_high_limbs(entity);
        batch.add_p_x_high_limbs_range_constraint_0(entity);
        batch.add_p_x_high_limbs_range_constraint_1(entity);
        batch.add_p_x_high_limbs_range_constraint_2(entity);
        batch.add_p_x_high_limbs_range_constraint_3(entity);
        batch.add_p_x_high_limbs_range_constraint_4(entity);
        batch.add_p_y_low_limbs(entity);
        batch.add_p_y_low_limbs_range_constraint_0(entity);
        batch.add_p_y_low_limbs_range_constraint_1(entity);
        batch.add_p_y_low_limbs_range_constraint_2(entity);
        batch.add_p_y_low_limbs_range_constraint_3(entity);
        batch.add_p_y_low_limbs_range_constraint_4(entity);
        batch.add_p_y_high_limbs(entity);
        batch.add_p_y_high_limbs_range_constraint_0(entity);
        batch.add_p_y_high_limbs_range_constraint_1(entity);
        batch.add_p_y_high_limbs_range_constraint_2(entity);
        batch.add_p_y_high_limbs_range_constraint_3(entity);
        batch.add_p_y_high_limbs_range_constraint_4(entity);
        batch.add_z_low_limbs(entity);
        batch.add_z_low_limbs_range_constraint_0(entity);
        batch.add_z_low_limbs_range_constraint_1(entity);
        batch.add_z_low_limbs_range_constraint_2(entity);
        batch.add_z_low_limbs_range_constraint_3(entity);
        batch.add_z_low_limbs_range_constraint_4(entity);
        batch.add_z_high_limbs(entity);
        batch.add_z_high_limbs_range_constraint_0(entity);
        batch.add_z_high_limbs_range_constraint_1(entity);
        batch.add_z_high_limbs_range_constraint_2(entity);
        batch.add_z_high_limbs_range_constraint_3(entity);
        batch.add_z_high_limbs_range_constraint_4(entity);
        batch.add_accumulators_binary_limbs_0(entity);
        batch.add_accumulators_binary_limbs_1(entity);
        batch.add_accumulators_binary_limbs_2(entity);
        batch.add_accumulators_binary_limbs_3(entity);
        batch.add_accumulator_low_limbs_range_constraint_0(entity);
        batch.add_accumulator_low_limbs_range_constraint_1(entity);
        batch.add_accumulator_low_limbs_range_constraint_2(entity);
        batch.add_accumulator_low_limbs_range_constraint_3(entity);
        batch.add_accumulator_low_limbs_range_constraint_4(entity);
        batch.add_accumulator_high_limbs_range_constraint_0(entity);
        batch.add_accumulator_high_limbs_range_constraint_1(entity);
        batch.add_accumulator_high_limbs_range_constraint_2(entity);
        batch.add_accumulator_high_limbs_range_constraint_3(entity);
        batch.add_accumulator_high_limbs_range_constraint_4(entity);
        batch.add_quotient_low_binary_limbs(entity);
        batch.add_quotient_low_limbs_range_constraint_0(entity);
        batch.add_quotient_low_limbs_range_constraint_1(entity);
        batch.add_quotient_low_limbs_range_constraint_2(entity);
        batch.add_quotient_low_limbs_range_constraint_3(entity);
        batch.add_quotient_low_limbs_range_constraint_4(entity);
        batch.add_quotient_high_binary_limbs(entity);
        batch.add_quotient_high_limbs_range_constraint_0(entity);
        batch.add_quotient_high_limbs_range_constraint_1(entity);
        batch.add_quotient_high_limbs_range_constraint_2(entity);
        batch.add_quotient_high_limbs_range_constraint_3(entity);
        batch.add_quotient_high_limbs_range_constraint_4(entity);
        batch.add_relation_wide_limbs(entity);
        batch.add_relation_wide_limbs_range_constraint_0(entity);
        batch.add_relation_wide_limbs_range_constraint_1(entity);
        batch.add_relation_wide_limbs_range_constraint_2(entity);
        batch.add_relation_wide_limbs_range_constraint_3(entity);
        batch.add_p_x_low_limbs_range_constraint_tail(entity);
        batch.add_p_x_high_limbs_range_constraint_tail(entity);
        batch.add_p_y_low_limbs_range_constraint_tail(entity);
        batch.add_p_y_high_limbs_range_constraint_tail(entity);
        batch.add_z_low_limbs_range_constraint_tail(entity);
        batch.add_z_high_limbs_range_constraint_tail(entity);
        batch.add_accumulator_low_limbs_range_constraint_tail(entity);
        batch.add_accumulator_high_limbs_range_constraint_tail(entity);
        batch.add_quotient_low_limbs_range_constraint_tail(entity);
        batch.add_quotient_high_limbs_range_constraint_tail(entity);
        batch.add_x_lo_y_hi(entity);
        batch.add_x_hi_z_1(entity);
        batch.add_y_lo_z_2(entity);
        batch.add_p_x_low_limbs_shift(entity);
        batch.add_p_x_low_limbs_range_constraint_0_shift(entity);
        batch.add_p_x_low_limbs_range_constraint_1_shift(entity);
        batch.add_p_x_low_limbs_range_constraint_2_shift(entity);
        batch.add_p_x_low_limbs_range_constraint_3_shift(entity);
        batch.add_p_x_low_limbs_range_constraint_4_shift(entity);
        batch.add_p_x_high_limbs_shift(entity);
        batch.add_p_x_high_limbs_range_constraint_0_shift(entity);
        batch.add_p_x_high_limbs_range_constraint_1_shift(entity);
        batch.add_p_x_high_limbs_range_constraint_2_shift(entity);
        batch.add_p_x_high_limbs_range_constraint_3_shift(entity);
        batch.add_p_y_low_limbs_shift(entity);
        batch.add_p_y_low_limbs_range_constraint_0_shift(entity);
        batch.add_p_y_low_limbs_range_constraint_1_shift(entity);
        batch.add_p_y_low_limbs_range_constraint_2_shift(entity);
        batch.add_p_y_low_limbs_range_constraint_3_shift(entity);
        batch.add_p_y_low_limbs_range_constraint_4_shift(entity);
        batch.add_p_y_high_limbs_shift(entity);
        batch.add_p_y_high_limbs_range_constraint_0_shift(entity);
        batch.add_p_y_high_limbs_range_constraint_1_shift(entity);
        batch.add_p_y_high_limbs_range_constraint_2_shift(entity);
        batch.add_p_y_high_limbs_range_constraint_3_shift(entity);
        batch.add_z_low_limbs_shift(entity);
        batch.add_z_low_limbs_range_constraint_0_shift(entity);
        batch.add_z_low_limbs_range_constraint_1_shift(entity);
        batch.add_z_low_limbs_range_constraint_2_shift(entity);
        batch.add_z_low_limbs_range_constraint_3_shift(entity);
        batch.add_z_low_limbs_range_constraint_4_shift(entity);
        batch.add_z_high_limbs_shift(entity);
        batch.add_z_high_limbs_range_constraint_0_shift(entity);
        batch.add_z_high_limbs_range_constraint_1_shift(entity);
        batch.add_z_high_limbs_range_constraint_2_shift(entity);
        batch.add_z_high_limbs_range_constraint_3_shift(entity);
        batch.add_z_high_limbs_range_constraint_4_shift(entity);
        batch.add_accumulator_low_limbs_range_constraint_0_shift(entity);
        batch.add_accumulator_low_limbs_range_constraint_1_shift(entity);
        batch.add_accumulator_low_limbs_range_constraint_2_shift(entity);
        batch.add_accumulator_low_limbs_range_constraint_3_shift(entity);
        batch.add_accumulator_low_limbs_range_constraint_4_shift(entity);
        batch.add_accumulator_high_limbs_range_constraint_0_shift(entity);
        batch.add_accumulator_high_limbs_range_constraint_1_shift(entity);
        batch.add_accumulator_high_limbs_range_constraint_2_shift(entity);
        batch.add_accumulator_high_limbs_range_constraint_3_shift(entity);
        batch.add_quotient_low_binary_limbs_shift(entity);
        batch.add_quotient_low_limbs_range_constraint_0_shift(entity);
        batch.add_quotient_low_limbs_range_constraint_1_shift(entity);
        batch.add_quotient_low_limbs_range_constraint_2_shift(entity);
        batch.add_quotient_low_limbs_range_constraint_3_shift(entity);
        batch.add_quotient_low_limbs_range_constraint_4_shift(entity);
        batch.add_quotient_high_binary_limbs_shift(entity);
        batch.add_quotient_high_limbs_range_constraint_0_shift(entity);
        batch.add_quotient_high_limbs_range_constraint_1_shift(entity);
        batch.add_quotient_high_limbs_range_constraint_2_shift(entity);
        batch.add_quotient_high_limbs_range_constraint_3_shift(entity);
        batch.add_p_x_high_limbs_range_constraint_tail_shift(entity);
        batch.add_accumulator_high_limbs_range_constraint_tail_shift(entity);
        batch.add_relation_wide_limbs_shift(entity);
        batch.add_relation_wide_limbs_range_constraint_0_shift(entity);
        batch.add_relation_wide_limbs_range_constraint_1_shift(entity);
        batch.add_relation_wide_limbs_range_constraint_2_shift(entity);
        batch.add_relation_wide_limbs_range_constraint_3_shift(entity);
        batch.add_p_y_high_limbs_range_constraint_tail_shift(entity);
        batch.add_quotient_high_limbs_range_constraint_tail_shift(entity);
        batch.add_p_x_low_limbs_range_constraint_tail_shift(entity);
        batch.add_p_x_high_limbs_range_constraint_4_shift(entity);
        batch.add_p_y_low_limbs_range_constraint_tail_shift(entity);
        batch.add_p_y_high_limbs_range_constraint_4_shift(entity);
        batch.add_z_low_limbs_range_constraint_tail_shift(entity);
        batch.add_z_high_limbs_range_constraint_tail_shift(entity);
        batch.add_accumulator_low_limbs_range_constraint_tail_shift(entity);
        batch.add_accumulator_high_limbs_range_constraint_4_shift(entity);
        batch.add_quotient_low_limbs_range_constraint_tail_shift(entity);
        batch.add_quotient_high_limbs_range_constraint_4_shift(entity);
        batch.add_x_lo_y_hi_shift(entity);
        batch.add_x_hi_z_1_shift(entity);
        batch.add_y_lo_z_2_shift(entity);
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
    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        _state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate TranslatorDecompositionRelation");

        const NUM_LIMB_BITS: usize = 68; // Number of bits in a standard limb used for bigfield operations
        const NUM_MICRO_LIMB_BITS: usize = 14; // Number of bits in a standard limb used for bigfield operations

        // Value to multiply an element by to perform an appropriate shift
        let limb_shift: P::ScalarField = (BigUint::one() << NUM_LIMB_BITS).into();

        // Values to multiply an element by to perform an appropriate shift
        let micro_limb_shift: P::ScalarField = (BigUint::one() << NUM_MICRO_LIMB_BITS).into();
        let micro_limb_shiftx2 = micro_limb_shift * micro_limb_shift;
        let micro_limb_shiftx3 = micro_limb_shiftx2 * micro_limb_shift;
        let micro_limb_shiftx4 = micro_limb_shiftx3 * micro_limb_shift;
        let micro_limb_shiftx5 = micro_limb_shiftx4 * micro_limb_shift;

        // Shifts used to constrain ranges further
        let shift_12_to_14 = P::ScalarField::from(4); // Shift used to range constrain the last microlimb of 68-bit limbs (standard limbs)
        let shift_10_to_14 = P::ScalarField::from(16); // Shift used to range constrain the last microlimb of 52-bit limb (top quotient limb)
        let shift_8_to_14 = P::ScalarField::from(64); // Shift used to range constrain the last microlimb of 50-bit
        // limbs (top limb of standard 254-bit value)
        let shift_4_to_14 = P::ScalarField::from(1024); // Shift used to range constrain the last mircrolimb of 60-bit limbs from z scalars

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
        let mut tmp_1 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(p_x_low_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(p_x_low_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(p_x_low_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(p_x_low_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(p_x_low_limbs_range_constraint_0, p_x_low_limbs),
        );
        T::mul_assign_with_public_many(&mut tmp_1, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_1, scaling_factors);
        fold_accumulator!(univariate_accumulator.r0, tmp_1, SIZE);

        // Contribution 2 , P_x second lowest limb decomposition
        let mut tmp_2 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(p_x_low_limbs_range_constraint_1_shift, micro_limb_shift),
                    &T::scale_many(p_x_low_limbs_range_constraint_2_shift, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(p_x_low_limbs_range_constraint_3_shift, micro_limb_shiftx3),
                    &T::scale_many(p_x_low_limbs_range_constraint_4_shift, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(p_x_low_limbs_range_constraint_0_shift, p_x_low_limbs_shift),
        );
        T::mul_assign_with_public_many(&mut tmp_2, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_2, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp_2, SIZE);

        // Contribution 3 , P_x third limb decomposition
        let mut tmp_3 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(p_x_high_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(p_x_high_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(p_x_high_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(p_x_high_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(p_x_high_limbs_range_constraint_0, p_x_high_limbs),
        );
        T::mul_assign_with_public_many(&mut tmp_3, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_3, scaling_factors);
        fold_accumulator!(univariate_accumulator.r2, tmp_3, SIZE);

        // Contribution 4 , P_x highest limb decomposition
        let mut tmp_4 = T::add_many(
            &T::add_many(
                &T::scale_many(p_x_high_limbs_range_constraint_1_shift, micro_limb_shift),
                &T::scale_many(p_x_high_limbs_range_constraint_2_shift, micro_limb_shiftx2),
            ),
            &T::add_many(
                &T::scale_many(p_x_high_limbs_range_constraint_3_shift, micro_limb_shiftx3),
                &T::sub_many(
                    p_x_high_limbs_range_constraint_0_shift,
                    p_x_high_limbs_shift,
                ),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_4, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_4, scaling_factors);
        fold_accumulator!(univariate_accumulator.r3, tmp_4, SIZE);

        // Contribution 5 , P_y lowest limb decomposition
        let mut tmp_5 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(p_y_low_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(p_y_low_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(p_y_low_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(p_y_low_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(p_y_low_limbs_range_constraint_0, p_y_low_limbs),
        );
        T::mul_assign_with_public_many(&mut tmp_5, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_5, scaling_factors);
        fold_accumulator!(univariate_accumulator.r4, tmp_5, SIZE);

        // Contribution 6 , P_y second lowest limb decomposition
        let mut tmp_6 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(p_y_low_limbs_range_constraint_1_shift, micro_limb_shift),
                    &T::scale_many(p_y_low_limbs_range_constraint_2_shift, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(p_y_low_limbs_range_constraint_3_shift, micro_limb_shiftx3),
                    &T::scale_many(p_y_low_limbs_range_constraint_4_shift, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(p_y_low_limbs_range_constraint_0_shift, p_y_low_limbs_shift),
        );
        T::mul_assign_with_public_many(&mut tmp_6, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_6, scaling_factors);
        fold_accumulator!(univariate_accumulator.r5, tmp_6, SIZE);

        // Contribution 7 , P_y third limb decomposition
        let mut tmp_7 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(p_y_high_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(p_y_high_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(p_y_high_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(p_y_high_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(p_y_high_limbs_range_constraint_0, p_y_high_limbs),
        );
        T::mul_assign_with_public_many(&mut tmp_7, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_7, scaling_factors);
        fold_accumulator!(univariate_accumulator.r6, tmp_7, SIZE);

        // Contribution 8 , P_y highest limb decomposition
        let mut tmp_8 = T::add_many(
            &T::add_many(
                &T::scale_many(p_y_high_limbs_range_constraint_1_shift, micro_limb_shift),
                &T::scale_many(p_y_high_limbs_range_constraint_2_shift, micro_limb_shiftx2),
            ),
            &T::add_many(
                &T::scale_many(p_y_high_limbs_range_constraint_3_shift, micro_limb_shiftx3),
                &T::sub_many(
                    p_y_high_limbs_range_constraint_0_shift,
                    p_y_high_limbs_shift,
                ),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_8, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_8, scaling_factors);
        fold_accumulator!(univariate_accumulator.r7, tmp_8, SIZE);

        // Contribution 9 , z_1 low limb decomposition
        let mut tmp_9 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(z_low_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(z_low_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(z_low_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(z_low_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(z_low_limbs_range_constraint_0, z_low_limbs),
        );
        T::mul_assign_with_public_many(&mut tmp_9, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_9, scaling_factors);
        fold_accumulator!(univariate_accumulator.r8, tmp_9, SIZE);

        // Contribution 10 , z_2 low limb decomposition
        let mut tmp_10 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(z_low_limbs_range_constraint_1_shift, micro_limb_shift),
                    &T::scale_many(z_low_limbs_range_constraint_2_shift, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(z_low_limbs_range_constraint_3_shift, micro_limb_shiftx3),
                    &T::scale_many(z_low_limbs_range_constraint_4_shift, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(z_low_limbs_range_constraint_0_shift, z_low_limbs_shift),
        );
        T::mul_assign_with_public_many(&mut tmp_10, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_10, scaling_factors);
        fold_accumulator!(univariate_accumulator.r9, tmp_10, SIZE);

        // Contribution 11 , z_1 high limb decomposition
        let mut tmp_11 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(z_high_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(z_high_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(z_high_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(z_high_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(z_high_limbs_range_constraint_0, z_high_limbs),
        );
        T::mul_assign_with_public_many(&mut tmp_11, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_11, scaling_factors);
        fold_accumulator!(univariate_accumulator.r10, tmp_11, SIZE);

        // Contribution 12 , z_2 high limb decomposition
        let mut tmp_12 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(z_high_limbs_range_constraint_1_shift, micro_limb_shift),
                    &T::scale_many(z_high_limbs_range_constraint_2_shift, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(z_high_limbs_range_constraint_3_shift, micro_limb_shiftx3),
                    &T::scale_many(z_high_limbs_range_constraint_4_shift, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(z_high_limbs_range_constraint_0_shift, z_high_limbs_shift),
        );
        T::mul_assign_with_public_many(&mut tmp_12, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_12, scaling_factors);
        fold_accumulator!(univariate_accumulator.r11, tmp_12, SIZE);

        // Contribution 13 , accumulator lowest limb decomposition
        let mut tmp_13 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(accumulator_low_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(accumulator_low_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(accumulator_low_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(accumulator_low_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(
                accumulator_low_limbs_range_constraint_0,
                accumulators_binary_limbs_0,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_13, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_13, scaling_factors);
        fold_accumulator!(univariate_accumulator.r12, tmp_13, SIZE);

        // Contribution 14 , accumulator second limb decomposition
        let mut tmp_14 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(
                        accumulator_low_limbs_range_constraint_1_shift,
                        micro_limb_shift,
                    ),
                    &T::scale_many(
                        accumulator_low_limbs_range_constraint_2_shift,
                        micro_limb_shiftx2,
                    ),
                ),
                &T::add_many(
                    &T::scale_many(
                        accumulator_low_limbs_range_constraint_3_shift,
                        micro_limb_shiftx3,
                    ),
                    &T::scale_many(
                        accumulator_low_limbs_range_constraint_4_shift,
                        micro_limb_shiftx4,
                    ),
                ),
            ),
            &T::sub_many(
                accumulator_low_limbs_range_constraint_0_shift,
                accumulators_binary_limbs_1,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_14, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_14, scaling_factors);
        fold_accumulator!(univariate_accumulator.r13, tmp_14, SIZE);

        // Contribution 15 , accumulator second highest limb decomposition
        let mut tmp_15 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(accumulator_high_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(
                        accumulator_high_limbs_range_constraint_2,
                        micro_limb_shiftx2,
                    ),
                ),
                &T::add_many(
                    &T::scale_many(
                        accumulator_high_limbs_range_constraint_3,
                        micro_limb_shiftx3,
                    ),
                    &T::scale_many(
                        accumulator_high_limbs_range_constraint_4,
                        micro_limb_shiftx4,
                    ),
                ),
            ),
            &T::sub_many(
                accumulator_high_limbs_range_constraint_0,
                accumulators_binary_limbs_2,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_15, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_15, scaling_factors);
        fold_accumulator!(univariate_accumulator.r14, tmp_15, SIZE);

        // Contribution 16 , accumulator highest limb decomposition
        let mut tmp_16 = T::add_many(
            &T::add_many(
                &T::scale_many(
                    accumulator_high_limbs_range_constraint_1_shift,
                    micro_limb_shift,
                ),
                &T::scale_many(
                    accumulator_high_limbs_range_constraint_2_shift,
                    micro_limb_shiftx2,
                ),
            ),
            &T::add_many(
                &T::scale_many(
                    accumulator_high_limbs_range_constraint_3_shift,
                    micro_limb_shiftx3,
                ),
                &T::sub_many(
                    accumulator_high_limbs_range_constraint_0_shift,
                    accumulators_binary_limbs_3,
                ),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_16, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_16, scaling_factors);
        fold_accumulator!(univariate_accumulator.r15, tmp_16, SIZE);

        // Contribution 17 , quotient lowest limb decomposition
        let mut tmp_17 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(quotient_low_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(quotient_low_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(quotient_low_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(quotient_low_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(
                quotient_low_limbs_range_constraint_0,
                quotient_low_binary_limbs,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_17, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_17, scaling_factors);
        fold_accumulator!(univariate_accumulator.r15, tmp_17, SIZE);

        // Contribution 18 , quotient second lowest limb decomposition
        let mut tmp_18 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(
                        quotient_low_limbs_range_constraint_1_shift,
                        micro_limb_shift,
                    ),
                    &T::scale_many(
                        quotient_low_limbs_range_constraint_2_shift,
                        micro_limb_shiftx2,
                    ),
                ),
                &T::add_many(
                    &T::scale_many(
                        quotient_low_limbs_range_constraint_3_shift,
                        micro_limb_shiftx3,
                    ),
                    &T::scale_many(
                        quotient_low_limbs_range_constraint_4_shift,
                        micro_limb_shiftx4,
                    ),
                ),
            ),
            &T::sub_many(
                quotient_low_limbs_range_constraint_0_shift,
                quotient_low_binary_limbs_shift,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_18, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_18, scaling_factors);
        fold_accumulator!(univariate_accumulator.r17, tmp_18, SIZE);

        // Contribution 19 , quotient second highest limb decomposition
        let mut tmp_19 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::scale_many(quotient_high_limbs_range_constraint_1, micro_limb_shift),
                    &T::scale_many(quotient_high_limbs_range_constraint_2, micro_limb_shiftx2),
                ),
                &T::add_many(
                    &T::scale_many(quotient_high_limbs_range_constraint_3, micro_limb_shiftx3),
                    &T::scale_many(quotient_high_limbs_range_constraint_4, micro_limb_shiftx4),
                ),
            ),
            &T::sub_many(
                quotient_high_limbs_range_constraint_0,
                quotient_high_binary_limbs,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_19, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_19, scaling_factors);
        fold_accumulator!(univariate_accumulator.r18, tmp_19, SIZE);

        // Contribution 20 , quotient highest limb decomposition
        let mut tmp_20 = T::add_many(
            &T::add_many(
                &T::scale_many(
                    quotient_high_limbs_range_constraint_1_shift,
                    micro_limb_shift,
                ),
                &T::scale_many(
                    quotient_high_limbs_range_constraint_2_shift,
                    micro_limb_shiftx2,
                ),
            ),
            &T::add_many(
                &T::scale_many(
                    quotient_high_limbs_range_constraint_3_shift,
                    micro_limb_shiftx3,
                ),
                &T::sub_many(
                    quotient_high_limbs_range_constraint_0_shift,
                    quotient_high_binary_limbs_shift,
                ),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_20, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_20, scaling_factors);
        fold_accumulator!(univariate_accumulator.r19, tmp_20, SIZE);

        // Contribution 21 , decomposition of the low wide relation limb used for the bigfield relation.
        // N.B. top microlimbs of relation wide limbs are stored in microlimbs for range constraints of P_x, P_y,
        // accumulator and quotient. This is to save space and because these microlimbs are not used by their namesakes,
        // since top limbs in 254/6-bit values use one less microlimb for the top 50/52-bit limb
        let mut tmp_21 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::add_many(
                        &T::scale_many(relation_wide_limbs_range_constraint_1, micro_limb_shift),
                        &T::scale_many(relation_wide_limbs_range_constraint_2, micro_limb_shiftx2),
                    ),
                    &T::add_many(
                        &T::scale_many(relation_wide_limbs_range_constraint_3, micro_limb_shiftx3),
                        &T::scale_many(
                            p_x_high_limbs_range_constraint_tail_shift,
                            micro_limb_shiftx4,
                        ),
                    ),
                ),
                &T::sub_many(relation_wide_limbs_range_constraint_0, relation_wide_limbs),
            ),
            &T::scale_many(
                accumulator_high_limbs_range_constraint_tail_shift,
                micro_limb_shiftx5,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_21, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_21, scaling_factors);
        fold_accumulator!(univariate_accumulator.r20, tmp_21, SIZE);

        // Contribution 22 , decomposition of high relation limb
        let mut tmp_22 = T::add_many(
            &T::add_many(
                &T::add_many(
                    &T::add_many(
                        &T::scale_many(
                            relation_wide_limbs_range_constraint_1_shift,
                            micro_limb_shift,
                        ),
                        &T::scale_many(
                            relation_wide_limbs_range_constraint_2_shift,
                            micro_limb_shiftx2,
                        ),
                    ),
                    &T::add_many(
                        &T::scale_many(
                            relation_wide_limbs_range_constraint_3_shift,
                            micro_limb_shiftx3,
                        ),
                        &T::scale_many(
                            p_y_high_limbs_range_constraint_tail_shift,
                            micro_limb_shiftx4,
                        ),
                    ),
                ),
                &T::sub_many(
                    relation_wide_limbs_range_constraint_0_shift,
                    relation_wide_limbs_shift,
                ),
            ),
            &T::scale_many(
                quotient_high_limbs_range_constraint_tail_shift,
                micro_limb_shiftx5,
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_22, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_22, scaling_factors);
        fold_accumulator!(univariate_accumulator.r21, tmp_22, SIZE);

        // Contributions enfocing a reduced range constraint on high limbs (these relation force the last microlimb in
        // each limb to be more severely range constrained)

        // Contribution 23, range constrain the highest microlimb of lowest P.x limb to be 12 bits (68 % 14 = 12)
        let mut tmp_23 = T::sub_many(
            &T::scale_many(p_x_low_limbs_range_constraint_4, shift_12_to_14),
            p_x_low_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_23, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_23, scaling_factors);
        fold_accumulator!(univariate_accumulator.r22, tmp_23, SIZE);

        // Contribution 24, range constrain the highest microlimb of second lowest P.x limb to be 12 bits
        let mut tmp_24 = T::sub_many(
            &T::scale_many(p_x_low_limbs_range_constraint_4_shift, shift_12_to_14),
            p_x_low_limbs_range_constraint_tail_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_24, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_24, scaling_factors);
        fold_accumulator!(univariate_accumulator.r23, tmp_24, SIZE);

        // Contribution 25, range constrain the highest microlimb of second highest P.x limb to be 12 bits
        let mut tmp_25 = T::sub_many(
            &T::scale_many(p_x_high_limbs_range_constraint_4, shift_12_to_14),
            p_x_high_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_25, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_25, scaling_factors);
        fold_accumulator!(univariate_accumulator.r24, tmp_25, SIZE);

        // Contribution 26, range constrain the highest microilmb of highest P.x limb to be 8 bits (50 % 14 = 8)
        let mut tmp_26 = T::sub_many(
            &T::scale_many(p_x_high_limbs_range_constraint_3_shift, shift_8_to_14),
            p_x_high_limbs_range_constraint_4_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_26, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_26, scaling_factors);
        fold_accumulator!(univariate_accumulator.r25, tmp_26, SIZE);

        // Contribution 27, range constrain the highest microlimb of lowest P.y limb to be 12 bits (68 % 14 = 12)
        let mut tmp_27 = T::sub_many(
            &T::scale_many(p_y_low_limbs_range_constraint_4, shift_12_to_14),
            p_y_low_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_27, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_27, scaling_factors);
        fold_accumulator!(univariate_accumulator.r26, tmp_27, SIZE);

        // Contribution 28, range constrain the highest microlimb of second lowest P.y limb to be 12 bits (68 % 14 = 12)
        let mut tmp_28 = T::sub_many(
            &T::scale_many(p_y_low_limbs_range_constraint_4_shift, shift_12_to_14),
            p_y_low_limbs_range_constraint_tail_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_28, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_28, scaling_factors);
        fold_accumulator!(univariate_accumulator.r27, tmp_28, SIZE);

        // Contribution 29, range constrain the highest microlimb of second highest P.y limb to be 12 bits (68 % 14 =
        // 12)
        let mut tmp_29 = T::sub_many(
            &T::scale_many(p_y_high_limbs_range_constraint_4, shift_12_to_14),
            p_y_high_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_29, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_29, scaling_factors);
        fold_accumulator!(univariate_accumulator.r28, tmp_29, SIZE);

        // Contribution 30, range constrain the highest microlimb of highest P.y limb to be 8 bits (50 % 14 = 8)
        let mut tmp_30 = T::sub_many(
            &T::scale_many(p_y_high_limbs_range_constraint_3_shift, shift_8_to_14),
            p_y_high_limbs_range_constraint_4_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_30, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_30, scaling_factors);
        fold_accumulator!(univariate_accumulator.r29, tmp_30, SIZE);

        // Contribution 31, range constrain the highest microlimb of low z1 limb to be 12 bits (68 % 14 = 12)
        let mut tmp_31 = T::sub_many(
            &T::scale_many(z_low_limbs_range_constraint_4, shift_12_to_14),
            z_low_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_31, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_31, scaling_factors);
        fold_accumulator!(univariate_accumulator.r30, tmp_31, SIZE);

        // Contribution 32, range constrain the highest microlimb of low z2 limb to be 12 bits (68 % 14 = 12)
        let mut tmp_32 = T::sub_many(
            &T::scale_many(z_low_limbs_range_constraint_4_shift, shift_12_to_14),
            z_low_limbs_range_constraint_tail_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_32, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_32, scaling_factors);
        fold_accumulator!(univariate_accumulator.r31, tmp_32, SIZE);

        // Contribution 33, range constrain the highest microlimb of high z1 limb to be 4 bits (60 % 14 = 12)
        let mut tmp_33 = T::sub_many(
            &T::scale_many(z_high_limbs_range_constraint_4, shift_4_to_14),
            z_high_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_33, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_33, scaling_factors);
        fold_accumulator!(univariate_accumulator.r32, tmp_33, SIZE);

        // Contribution 34, range constrain the highest microlimb of high z2 limb to be 4 bits (60 % 14 = 12)
        let mut tmp_34 = T::sub_many(
            &T::scale_many(z_high_limbs_range_constraint_4_shift, shift_4_to_14),
            z_high_limbs_range_constraint_tail_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_34, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_34, scaling_factors);
        fold_accumulator!(univariate_accumulator.r33, tmp_34, SIZE);

        // Contribution 35, range constrain the highest microlimb of lowest current accumulator limb to be 12 bits (68 %
        // 14 = 12)
        let mut tmp_35 = T::sub_many(
            &T::scale_many(accumulator_low_limbs_range_constraint_4, shift_12_to_14),
            accumulator_low_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_35, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_35, scaling_factors);
        fold_accumulator!(univariate_accumulator.r34, tmp_35, SIZE);

        // Contribution 36, range constrain the highest microlimb of second lowest current accumulator limb to be 12
        // bits (68 % 14 = 12)
        let mut tmp_36 = T::sub_many(
            &T::scale_many(
                accumulator_low_limbs_range_constraint_4_shift,
                shift_12_to_14,
            ),
            accumulator_low_limbs_range_constraint_tail_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_36, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_36, scaling_factors);
        fold_accumulator!(univariate_accumulator.r35, tmp_36, SIZE);

        // Contribution 37, range constrain the highest microlimb of second highest current accumulator limb to be 12
        // bits (68 % 14 = 12)
        let mut tmp_37 = T::sub_many(
            &T::scale_many(accumulator_high_limbs_range_constraint_4, shift_12_to_14),
            accumulator_high_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_37, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_37, scaling_factors);
        fold_accumulator!(univariate_accumulator.r36, tmp_37, SIZE);

        // Contribution 38, range constrain the highest microlimb of highest current accumulator limb to be 8 bits (50 %
        // 14 = 12)
        let mut tmp_38 = T::sub_many(
            &T::scale_many(
                accumulator_high_limbs_range_constraint_3_shift,
                shift_8_to_14,
            ),
            accumulator_high_limbs_range_constraint_4_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_38, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_38, scaling_factors);
        fold_accumulator!(univariate_accumulator.r37, tmp_38, SIZE);

        // Contribution 39, range constrain the highest microlimb of lowest quotient limb to be 12 bits (68 % 14 = 12)
        let mut tmp_39 = T::sub_many(
            &T::scale_many(quotient_low_limbs_range_constraint_4, shift_12_to_14),
            quotient_low_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_39, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_39, scaling_factors);
        fold_accumulator!(univariate_accumulator.r38, tmp_39, SIZE);

        // Contribution 40, range constrain the highest microlimb of second lowest quotient limb to be 12 bits (68 % 14
        // = 12)
        let mut tmp_40 = T::sub_many(
            &T::scale_many(quotient_low_limbs_range_constraint_4_shift, shift_12_to_14),
            quotient_low_limbs_range_constraint_tail_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_40, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_40, scaling_factors);
        fold_accumulator!(univariate_accumulator.r39, tmp_40, SIZE);

        // Contribution 41, range constrain the highest microlimb of second highest quotient limb to be 12 bits (68 % 14
        // = 12)
        let mut tmp_41 = T::sub_many(
            &T::scale_many(quotient_high_limbs_range_constraint_4, shift_12_to_14),
            quotient_high_limbs_range_constraint_tail,
        );
        T::mul_assign_with_public_many(&mut tmp_41, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_41, scaling_factors);
        fold_accumulator!(univariate_accumulator.r40, tmp_41, SIZE);

        // Contribution 42, range constrain the highest microlimb of highest quotient limb to be 10 bits (52 % 14 = 12)
        let mut tmp_42 = T::sub_many(
            &T::scale_many(quotient_high_limbs_range_constraint_3_shift, shift_10_to_14),
            quotient_high_limbs_range_constraint_4_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_42, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_42, scaling_factors);
        fold_accumulator!(univariate_accumulator.r41, tmp_42, SIZE);

        // Contributions where we decompose initial EccOpQueue values into 68-bit limbs

        // Contribution 43, decompose x_lo
        let mut tmp_43 = T::sub_many(
            &T::add_many(
                &T::scale_many(p_x_low_limbs_shift, limb_shift),
                p_x_low_limbs,
            ),
            x_lo_y_hi,
        );
        T::mul_assign_with_public_many(&mut tmp_43, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_43, scaling_factors);
        fold_accumulator!(univariate_accumulator.r42, tmp_43, SIZE);

        // Contribution 44, decompose x_hi
        let mut tmp_44 = T::sub_many(
            &T::add_many(
                &T::scale_many(p_x_high_limbs_shift, limb_shift),
                p_x_high_limbs,
            ),
            x_hi_z_1,
        );
        T::mul_assign_with_public_many(&mut tmp_44, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_44, scaling_factors);
        fold_accumulator!(univariate_accumulator.r43, tmp_44, SIZE);

        // Contribution 45, decompose y_lo
        let mut tmp_45 = T::sub_many(
            &T::add_many(
                &T::scale_many(p_y_low_limbs_shift, limb_shift),
                p_y_low_limbs,
            ),
            y_lo_z_2,
        );
        T::mul_assign_with_public_many(&mut tmp_45, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_45, scaling_factors);
        fold_accumulator!(univariate_accumulator.r44, tmp_45, SIZE);

        // Contribution 46, decompose y_hi
        let mut tmp_46 = T::sub_many(
            &T::add_many(
                &T::scale_many(p_y_high_limbs_shift, limb_shift),
                p_y_high_limbs,
            ),
            x_lo_y_hi_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_46, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_46, scaling_factors);
        fold_accumulator!(univariate_accumulator.r45, tmp_46, SIZE);

        // Contribution 47, decompose z1
        let mut tmp_47 = T::sub_many(
            &T::add_many(&T::scale_many(z_high_limbs, limb_shift), z_low_limbs),
            x_hi_z_1_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_47, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_47, scaling_factors);
        fold_accumulator!(univariate_accumulator.r46, tmp_47, SIZE);

        // Contribution 48, decompose z2
        let mut tmp_48 = T::sub_many(
            &T::add_many(
                &T::scale_many(z_high_limbs_shift, limb_shift),
                z_low_limbs_shift,
            ),
            y_lo_z_2_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_48, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_48, scaling_factors);
        fold_accumulator!(univariate_accumulator.r47, tmp_48, SIZE);
        Ok(())
    }
}
