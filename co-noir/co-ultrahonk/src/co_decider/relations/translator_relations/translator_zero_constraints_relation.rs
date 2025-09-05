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
use itertools::Itertools;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorZeroConstraintsRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
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
    pub(crate) r48: SharedUnivariate<T, P, 3>,
    pub(crate) r49: SharedUnivariate<T, P, 3>,
    pub(crate) r50: SharedUnivariate<T, P, 3>,
    pub(crate) r51: SharedUnivariate<T, P, 3>,
    pub(crate) r52: SharedUnivariate<T, P, 3>,
    pub(crate) r53: SharedUnivariate<T, P, 3>,
    pub(crate) r54: SharedUnivariate<T, P, 3>,
    pub(crate) r55: SharedUnivariate<T, P, 3>,
    pub(crate) r56: SharedUnivariate<T, P, 3>,
    pub(crate) r57: SharedUnivariate<T, P, 3>,
    pub(crate) r58: SharedUnivariate<T, P, 3>,
    pub(crate) r59: SharedUnivariate<T, P, 3>,
    pub(crate) r60: SharedUnivariate<T, P, 3>,
    pub(crate) r61: SharedUnivariate<T, P, 3>,
    pub(crate) r62: SharedUnivariate<T, P, 3>,
    pub(crate) r63: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default
    for TranslatorZeroConstraintsRelationAcc<T, P>
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
            r48: SharedUnivariate::default(),
            r49: SharedUnivariate::default(),
            r50: SharedUnivariate::default(),
            r51: SharedUnivariate::default(),
            r52: SharedUnivariate::default(),
            r53: SharedUnivariate::default(),
            r54: SharedUnivariate::default(),
            r55: SharedUnivariate::default(),
            r56: SharedUnivariate::default(),
            r57: SharedUnivariate::default(),
            r58: SharedUnivariate::default(),
            r59: SharedUnivariate::default(),
            r60: SharedUnivariate::default(),
            r61: SharedUnivariate::default(),
            r62: SharedUnivariate::default(),
            r63: SharedUnivariate::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorZeroConstraintsRelationAcc<T, P> {
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
        self.r48.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r49.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r50.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r51.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r52.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r53.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r54.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r55.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r56.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r57.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r58.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r59.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r60.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r61.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r62.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r63.scale_inplace(*current_scalar);
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

pub(crate) struct TranslatorZeroConstraintsRelation {}

impl TranslatorZeroConstraintsRelation {
    pub(crate) const NUM_RELATIONS: usize = 64;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorZeroConstraintsRelation
{
    type Acc = TranslatorZeroConstraintsRelationAcc<T, P>;
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
        batch.add_lagrange_odd_in_minicircuit(entity);

        batch.add_p_x_low_limbs_range_constraint_0(entity);
        batch.add_p_x_low_limbs_range_constraint_1(entity);
        batch.add_p_x_low_limbs_range_constraint_2(entity);
        batch.add_p_x_low_limbs_range_constraint_3(entity);
        batch.add_p_x_low_limbs_range_constraint_4(entity);
        batch.add_p_x_high_limbs_range_constraint_0(entity);
        batch.add_p_x_high_limbs_range_constraint_1(entity);
        batch.add_p_x_high_limbs_range_constraint_2(entity);
        batch.add_p_x_high_limbs_range_constraint_3(entity);
        batch.add_p_x_high_limbs_range_constraint_4(entity);
        batch.add_p_y_low_limbs_range_constraint_0(entity);
        batch.add_p_y_low_limbs_range_constraint_1(entity);
        batch.add_p_y_low_limbs_range_constraint_2(entity);
        batch.add_p_y_low_limbs_range_constraint_3(entity);
        batch.add_p_y_low_limbs_range_constraint_4(entity);
        batch.add_p_y_high_limbs_range_constraint_0(entity);
        batch.add_p_y_high_limbs_range_constraint_1(entity);
        batch.add_p_y_high_limbs_range_constraint_2(entity);
        batch.add_p_y_high_limbs_range_constraint_3(entity);
        batch.add_p_y_high_limbs_range_constraint_4(entity);
        batch.add_z_low_limbs_range_constraint_0(entity);
        batch.add_z_low_limbs_range_constraint_1(entity);
        batch.add_z_low_limbs_range_constraint_2(entity);
        batch.add_z_low_limbs_range_constraint_3(entity);
        batch.add_z_low_limbs_range_constraint_4(entity);
        batch.add_z_high_limbs_range_constraint_0(entity);
        batch.add_z_high_limbs_range_constraint_1(entity);
        batch.add_z_high_limbs_range_constraint_2(entity);
        batch.add_z_high_limbs_range_constraint_3(entity);
        batch.add_z_high_limbs_range_constraint_4(entity);
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
        batch.add_quotient_low_limbs_range_constraint_0(entity);
        batch.add_quotient_low_limbs_range_constraint_1(entity);
        batch.add_quotient_low_limbs_range_constraint_2(entity);
        batch.add_quotient_low_limbs_range_constraint_3(entity);
        batch.add_quotient_low_limbs_range_constraint_4(entity);
        batch.add_quotient_high_limbs_range_constraint_0(entity);
        batch.add_quotient_high_limbs_range_constraint_1(entity);
        batch.add_quotient_high_limbs_range_constraint_2(entity);
        batch.add_quotient_high_limbs_range_constraint_3(entity);
        batch.add_quotient_high_limbs_range_constraint_4(entity);
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
    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        _state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        let minus_one = -P::ScalarField::one();

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
        let mut not_in_minicircuit_by_scaling = lagrange_odd_in_minicircuit
            .iter()
            .zip(lagrange_even_in_minicircuit.iter())
            .map(|(odd, even)| *even + odd + minus_one)
            .collect::<Vec<P::ScalarField>>();
        not_in_minicircuit_by_scaling
            .iter_mut()
            .zip_eq(scaling_factors.iter())
            .for_each(|(v, scaling)| *v *= scaling);

        // Contribution 0, ensure p_x_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_low_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        // Contribution 1, ensure p_x_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_low_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        // Contribution 2, ensure p_x_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_low_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r2, tmp, SIZE);

        // Contribution 3, ensure p_x_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_low_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r3, tmp, SIZE);

        // Contribution 4, ensure p_x_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_low_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r4, tmp, SIZE);

        // Contribution 5, ensure p_x_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_high_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r5, tmp, SIZE);

        // Contribution 6, ensure p_x_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_high_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r6, tmp, SIZE);

        // Contribution 7, ensure p_x_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_high_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r7, tmp, SIZE);

        // Contribution 8, ensure p_x_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_high_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r8, tmp, SIZE);

        // Contribution 9, ensure p_x_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_high_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r9, tmp, SIZE);

        // Contribution 10, ensure p_y_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_low_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r10, tmp, SIZE);

        // Contribution 11, ensure p_y_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_low_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r11, tmp, SIZE);

        // Contribution 12, ensure p_y_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_low_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r12, tmp, SIZE);

        // Contribution 13, ensure p_y_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_low_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r13, tmp, SIZE);

        // Contribution 14, ensure p_y_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_low_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r14, tmp, SIZE);

        // Contribution 15, ensure p_y_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_high_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r15, tmp, SIZE);

        // Contribution 16, ensure p_y_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_high_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r16, tmp, SIZE);

        // Contribution 17, ensure p_y_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_high_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r17, tmp, SIZE);

        // Contribution 18, ensure p_y_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_high_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r18, tmp, SIZE);

        // Contribution 19, ensure p_y_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_high_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r19, tmp, SIZE);

        // Contribution 20, ensure z_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_low_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r20, tmp, SIZE);

        // Contribution 21, ensure z_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_low_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r21, tmp, SIZE);

        // Contribution 22, ensure z_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_low_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r22, tmp, SIZE);

        // Contribution 23, ensure z_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_low_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r23, tmp, SIZE);

        // Contribution 24, ensure z_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_low_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r24, tmp, SIZE);

        // Contribution 25, ensure z_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_high_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r25, tmp, SIZE);

        // Contribution 26, ensure z_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_high_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r26, tmp, SIZE);

        // Contribution 27, ensure z_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_high_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r27, tmp, SIZE);

        // Contribution 28, ensure z_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_high_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r28, tmp, SIZE);

        // Contribution 29, ensure z_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_high_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r29, tmp, SIZE);

        // Contribution 30, ensure accumulator_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_low_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r30, tmp, SIZE);

        // Contribution 31, ensure accumulator_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_low_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r31, tmp, SIZE);

        // Contribution 32, ensure accumulator_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_low_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r32, tmp, SIZE);

        // Contribution 33, ensure accumulator_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_low_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r33, tmp, SIZE);

        // Contribution 34, ensure accumulator_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_low_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r34, tmp, SIZE);

        // Contribution 35, ensure accumulator_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_high_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r35, tmp, SIZE);

        // Contribution 36, ensure accumulator_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_high_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r36, tmp, SIZE);

        // Contribution 37, ensure accumulator_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_high_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r37, tmp, SIZE);

        // Contribution 38, ensure accumulator_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_high_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r38, tmp, SIZE);

        // Contribution 39, ensure accumulator_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_high_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r39, tmp, SIZE);

        // Contribution 40, ensure quotient_low_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_low_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r40, tmp, SIZE);

        // Contribution 41, ensure quotient_low_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_low_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r41, tmp, SIZE);

        // Contribution 42, ensure quotient_low_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_low_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r42, tmp, SIZE);

        // Contribution 43, ensure quotient_low_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_low_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r43, tmp, SIZE);

        // Contribution 44, ensure quotient_low_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_low_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r44, tmp, SIZE);

        // Contribution 45, ensure quotient_high_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_high_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r45, tmp, SIZE);

        // Contribution 46, ensure quotient_high_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_high_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r46, tmp, SIZE);

        // Contribution 47, ensure quotient_high_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_high_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r47, tmp, SIZE);

        // Contribution 48, ensure quotient_high_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_high_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r48, tmp, SIZE);

        // Contribution 49, ensure quotient_high_limbs_range_constraint_4 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_high_limbs_range_constraint_4,
        );
        fold_accumulator!(univariate_accumulator.r49, tmp, SIZE);

        // Contribution 50, ensure relation_wide_limbs_range_constraint_0 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            relation_wide_limbs_range_constraint_0,
        );
        fold_accumulator!(univariate_accumulator.r50, tmp, SIZE);

        // Contribution 51, ensure relation_wide_limbs_range_constraint_1 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            relation_wide_limbs_range_constraint_1,
        );
        fold_accumulator!(univariate_accumulator.r51, tmp, SIZE);

        // Contribution 52, ensure relation_wide_limbs_range_constraint_2 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            relation_wide_limbs_range_constraint_2,
        );
        fold_accumulator!(univariate_accumulator.r52, tmp, SIZE);

        // Contribution 53, ensure relation_wide_limbs_range_constraint_3 is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            relation_wide_limbs_range_constraint_3,
        );
        fold_accumulator!(univariate_accumulator.r53, tmp, SIZE);

        // Contribution 54, ensure p_x_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_low_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r54, tmp, SIZE);

        // Contribution 55, ensure p_x_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_x_high_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r55, tmp, SIZE);

        // Contribution 56, ensure p_y_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_low_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r56, tmp, SIZE);

        // Contribution 57, ensure p_y_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            p_y_high_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r57, tmp, SIZE);

        // Contribution 58, ensure z_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_low_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r58, tmp, SIZE);

        // Contribution 59, ensure z_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            z_high_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r59, tmp, SIZE);

        // Contribution 60, ensure accumulator_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_low_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r60, tmp, SIZE);

        // Contribution 61, ensure accumulator_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            accumulator_high_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r61, tmp, SIZE);

        // Contribution 62, ensure quotient_low_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_low_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r62, tmp, SIZE);

        // Contribution 63, ensure quotient_high_limbs_range_constraint_tail is 0 outside of minicircuit
        let tmp = T::mul_with_public_many(
            &not_in_minicircuit_by_scaling,
            quotient_high_limbs_range_constraint_tail,
        );
        fold_accumulator!(univariate_accumulator.r63, tmp, SIZE);

        Ok(())
    }
}
