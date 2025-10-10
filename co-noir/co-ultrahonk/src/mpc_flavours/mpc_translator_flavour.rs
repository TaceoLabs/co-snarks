use crate::{
    co_decider::{
        co_sumcheck::co_sumcheck_round::SumcheckRound,
        relations::{
            Relation,
            translator_relations::{
                translator_accumulator_transfer_relation::{
                    TranslatorAccumulatorTransferRelation, TranslatorAccumulatorTransferRelationAcc,
                },
                translator_decomposition_relation::{
                    TranslatorDecompositionRelation, TranslatorDecompositionRelationAcc,
                },
                translator_delta_range_constraint_relation::{
                    TranslatorDeltaRangeConstraintRelation,
                    TranslatorDeltaRangeConstraintRelationAcc,
                },
                translator_non_native_field_relation::{
                    TranslatorNonNativeFieldRelation, TranslatorNonNativeFieldRelationAcc,
                },
                translator_op_code_constraint_relation::{
                    TranslatorOpCodeConstraintRelation, TranslatorOpCodeConstraintRelationAcc,
                },
                translator_permutation_relation::{
                    TranslatorPermutationRelation, TranslatorPermutationRelationAcc,
                },
                translator_zero_constraints_relation::{
                    TranslatorZeroConstraintsRelation, TranslatorZeroConstraintsRelationAcc,
                },
            },
        },
        univariates::SharedUnivariate,
    },
    prelude::MPCProverFlavour,
    types_batch::{AllEntitiesBatchRelationsTrait, Public, Shared, SumCheckDataForRelation},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::{flavours::translator_flavour::TranslatorFlavour, prover_flavour::ProverFlavour};
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::transcript_mpc::TranscriptRef;
use co_noir_common::{honk_curve::HonkCurve, mpc::NoirUltraHonkProver};
use mpc_net::Network;
use ultrahonk::prelude::{TranscriptHasher, Univariate};

pub struct AllRelationAccTranslator<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r_translator_perm: TranslatorPermutationRelationAcc<T, P>,
    pub(crate) r_translator_delta: TranslatorDeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_translator_opcode: TranslatorOpCodeConstraintRelationAcc<T, P>,
    pub(crate) r_translator_acc: TranslatorAccumulatorTransferRelationAcc<T, P>,
    pub(crate) r_translator_decomp: TranslatorDecompositionRelationAcc<T, P>,
    pub(crate) r_translator_non_native: TranslatorNonNativeFieldRelationAcc<T, P>,
    pub(crate) r_translator_zero: TranslatorZeroConstraintsRelationAcc<T, P>,
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for AllRelationAccTranslator<T, P> {
    fn default() -> Self {
        Self {
            r_translator_perm: TranslatorPermutationRelationAcc::default(),
            r_translator_delta: TranslatorDeltaRangeConstraintRelationAcc::default(),
            r_translator_opcode: TranslatorOpCodeConstraintRelationAcc::default(),
            r_translator_acc: TranslatorAccumulatorTransferRelationAcc::default(),
            r_translator_decomp: TranslatorDecompositionRelationAcc::default(),
            r_translator_non_native: TranslatorNonNativeFieldRelationAcc::default(),
            r_translator_zero: TranslatorZeroConstraintsRelationAcc::default(),
        }
    }
}

fn extend_and_batch_univariates_template<
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    const SIZE: usize,
>(
    acc: &AllRelationAccTranslator<T, P>,
    result: &mut SharedUnivariate<T, P, SIZE>,
    extended_random_poly: &Univariate<P::ScalarField, SIZE>,
    partial_evaluation_result: &P::ScalarField,
) {
    tracing::trace!("Prove::Extend and batch univariates");
    acc.r_translator_perm.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_translator_delta.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_translator_opcode.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_translator_acc.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_translator_decomp.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_translator_non_native.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_translator_zero.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
}

pub struct AllEntitiesBatchRelationsTranslator<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) translator_perm: SumCheckDataForRelation<T, P, TranslatorFlavour>,
    pub(crate) translator_delta: SumCheckDataForRelation<T, P, TranslatorFlavour>,
    pub(crate) translator_opcode: SumCheckDataForRelation<T, P, TranslatorFlavour>,
    pub(crate) translator_acc: SumCheckDataForRelation<T, P, TranslatorFlavour>,
    pub(crate) translator_decomp: SumCheckDataForRelation<T, P, TranslatorFlavour>,
    pub(crate) translator_non_native: SumCheckDataForRelation<T, P, TranslatorFlavour>,
    pub(crate) translator_zero: SumCheckDataForRelation<T, P, TranslatorFlavour>,
}

impl MPCProverFlavour for TranslatorFlavour {
    type AllRelationAcc<T: NoirUltraHonkProver<P>, P: ark_ec::CurveGroup> =
        AllRelationAccTranslator<T, P>;
    type AllRelationEvaluations<T: NoirUltraHonkProver<P>, P: CurveGroup> = ();

    type AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: ark_ec::CurveGroup> =
        AllRelationAccTranslator<T, P>;

    type SumcheckRoundOutput<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZK<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type SumcheckRoundOutputPublic<F: PrimeField> =
        Univariate<F, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZKPublic<F: PrimeField> =
        Univariate<F, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type ProverUnivariateShared<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { TranslatorFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    type ProverUnivariatePublic<P: CurveGroup> =
        Univariate<P::ScalarField, { TranslatorFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    type AllEntitiesBatchRelations<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> =
        AllEntitiesBatchRelationsTranslator<T, P>;

    const NUM_SUBRELATIONS: usize = TranslatorPermutationRelation::NUM_RELATIONS
        + TranslatorDeltaRangeConstraintRelation::NUM_RELATIONS
        + TranslatorOpCodeConstraintRelation::NUM_RELATIONS
        + TranslatorAccumulatorTransferRelation::NUM_RELATIONS
        + TranslatorDecompositionRelation::NUM_RELATIONS
        + TranslatorNonNativeFieldRelation::NUM_RELATIONS
        + TranslatorZeroConstraintsRelation::NUM_RELATIONS;

    const CRAND_PAIRS_FACTOR: usize = 0; // TACEO TODO: This is relevant for Shamir, if we ever use it we need to set it properly

    fn scale<T: NoirUltraHonkProver<P>, P: ark_ec::CurveGroup>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &[P::ScalarField],
    ) {
        let mut current_scalar = first_scalar;
        let alpha = elements[0];
        acc.r_translator_perm.scale(&mut current_scalar, &alpha);
        acc.r_translator_delta.scale(&mut current_scalar, &alpha);
        acc.r_translator_opcode.scale(&mut current_scalar, &alpha);
        acc.r_translator_acc.scale(&mut current_scalar, &alpha);
        acc.r_translator_decomp.scale(&mut current_scalar, &alpha);
        acc.r_translator_non_native
            .scale(&mut current_scalar, &alpha);
        acc.r_translator_zero.scale(&mut current_scalar, &alpha);
    }

    fn extend_and_batch_univariates<T: NoirUltraHonkProver<P>, P: ark_ec::CurveGroup>(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutput<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn extend_and_batch_univariates_zk<T: NoirUltraHonkProver<P>, P: ark_ec::CurveGroup>(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutputZK<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputZKPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn accumulate_relation_univariates_batch<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirUltraHonkProver<P>,
        N: mpc_net::Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &Self::AllEntitiesBatchRelations<T, P>,
        relation_parameters: &crate::co_decider::types::RelationParameters<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate relations");
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorPermutationRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_perm,
            relation_parameters,
            &sum_check_data.translator_perm,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorDeltaRangeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_delta,
            relation_parameters,
            &sum_check_data.translator_delta,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorOpCodeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_opcode,
            relation_parameters,
            &sum_check_data.translator_opcode,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorAccumulatorTransferRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_acc,
            relation_parameters,
            &sum_check_data.translator_acc,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorDecompositionRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_decomp,
            relation_parameters,
            &sum_check_data.translator_decomp,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorNonNativeFieldRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_non_native,
            relation_parameters,
            &sum_check_data.translator_non_native,
        )?;
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            TranslatorZeroConstraintsRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_translator_zero,
            relation_parameters,
            &sum_check_data.translator_zero,
        )?;
        Ok(())
    }

    fn get_alpha_challenges<
        T: NoirUltraHonkProver<P>,
        H: TranscriptHasher<TranscriptFieldType, T, P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        _transcript: &mut TranscriptRef<TranscriptFieldType, T, P, H>,
        _alphas: &mut Vec<P::ScalarField>,
        _net: &N,
        _state: &mut T::State,
    ) -> eyre::Result<()> {
        panic!(
            "This is used in the Oink Prover and thus should not be called with the Translator flavour"
        );
    }

    fn reshare<T: NoirUltraHonkProver<P>, P: ark_ec::CurveGroup, N: mpc_net::Network>(
        acc: Self::AllRelationAccHalfShared<T, P>,
        _net: &N,
        _state: &mut T::State,
    ) -> HonkProofResult<Self::AllRelationAcc<T, P>> {
        Ok(AllRelationAccTranslator {
            r_translator_perm: acc.r_translator_perm,
            r_translator_delta: acc.r_translator_delta,
            r_translator_opcode: acc.r_translator_opcode,
            r_translator_acc: acc.r_translator_acc,
            r_translator_decomp: acc.r_translator_decomp,
            r_translator_non_native: acc.r_translator_non_native,
            r_translator_zero: acc.r_translator_zero,
        })
    }
}

impl<T, P> AllEntitiesBatchRelationsTrait<T, P, TranslatorFlavour>
    for AllEntitiesBatchRelationsTranslator<T, P>
where
    P: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<P>,
{
    fn new() -> Self {
        Self {
            translator_perm: SumCheckDataForRelation::new(),
            translator_delta: SumCheckDataForRelation::new(),
            translator_opcode: SumCheckDataForRelation::new(),
            translator_acc: SumCheckDataForRelation::new(),
            translator_decomp: SumCheckDataForRelation::new(),
            translator_non_native: SumCheckDataForRelation::new(),
            translator_zero: SumCheckDataForRelation::new(),
        }
    }

    fn fold_and_filter(
        &mut self,
        entity: crate::types::AllEntities<
            Shared<T, P, TranslatorFlavour>,
            Public<P, TranslatorFlavour>,
            TranslatorFlavour,
        >,
        scaling_factor: P::ScalarField,
    ) {
        // 0xThemis TODO - for all (?) accumulator we don't need all 7 elements. Can we remove
        // somehow skip those to decrease work even further?
        // e.g. UltraArith only has
        //
        // pub(crate) r0: SharedUnivariate<T, P, 6>,
        // pub(crate) r1: SharedUnivariate<T, P, 5>,
        //
        // Can we somehow only add 5/6 elements?

        TranslatorPermutationRelation::add_edge(&entity, scaling_factor, &mut self.translator_perm);
        TranslatorDeltaRangeConstraintRelation::add_edge(
            &entity,
            scaling_factor,
            &mut self.translator_delta,
        );
        TranslatorOpCodeConstraintRelation::add_edge(
            &entity,
            scaling_factor,
            &mut self.translator_opcode,
        );
        TranslatorAccumulatorTransferRelation::add_edge(
            &entity,
            scaling_factor,
            &mut self.translator_acc,
        );
        TranslatorDecompositionRelation::add_edge(
            &entity,
            scaling_factor,
            &mut self.translator_decomp,
        );
        TranslatorNonNativeFieldRelation::add_edge(
            &entity,
            scaling_factor,
            &mut self.translator_non_native,
        );
        TranslatorZeroConstraintsRelation::add_edge(
            &entity,
            scaling_factor,
            &mut self.translator_zero,
        );
    }
}
