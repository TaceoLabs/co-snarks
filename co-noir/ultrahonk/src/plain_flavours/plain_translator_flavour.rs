#![expect(unused)]
use crate::decider::types::ClaimedEvaluations;
use crate::decider::types::{ProverUnivariates, RelationParameters};
use crate::decider::{
    relations::translator_relations::{
        translator_accumulator_transfer_relation::{
            TranslatorAccumulatorTransferRelation, TranslatorAccumulatorTransferRelationAcc,
            TranslatorAccumulatorTransferRelationEvals,
        },
        translator_decomposition_relation::{
            TranslatorDecompositionRelation, TranslatorDecompositionRelationAcc,
            TranslatorDecompositionRelationEvals,
        },
        translator_delta_range_constraint_relation::{
            TranslatorDeltaRangeConstraintRelation, TranslatorDeltaRangeConstraintRelationAcc,
            TranslatorDeltaRangeConstraintRelationEvals,
        },
        translator_non_native_field_relation::{
            TranslatorNonNativeFieldRelation, TranslatorNonNativeFieldRelationAcc,
            TranslatorNonNativeFieldRelationEvals,
        },
        translator_op_code_constraint_relation::{
            TranslatorOpCodeConstraintRelation, TranslatorOpCodeConstraintRelationAcc,
            TranslatorOpCodeConstraintRelationEvals,
        },
        translator_permutation_relation::{
            TranslatorPermutationRelation, TranslatorPermutationRelationAcc,
            TranslatorPermutationRelationEvals,
        },
        translator_zero_constraints_relation::{
            TranslatorZeroConstraintsRelation, TranslatorZeroConstraintsRelationAcc,
            TranslatorZeroConstraintsRelationEvals,
        },
    },
    sumcheck::sumcheck_round_prover::SumcheckProverRound,
};
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::prelude::{Transcript, TranscriptHasher, Univariate};
use ark_ff::PrimeField;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::prover_flavour::ProverFlavour;
use common::transcript::TranscriptFieldType;

#[derive(Default)]
pub struct AllRelationAccTranslator<F: PrimeField> {
    pub(crate) r_translator_perm: TranslatorPermutationRelationAcc<F>,
    pub(crate) r_translator_delta: TranslatorDeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_translator_opcode: TranslatorOpCodeConstraintRelationAcc<F>,
    pub(crate) r_translator_acc: TranslatorAccumulatorTransferRelationAcc<F>,
    pub(crate) r_translator_decomp: TranslatorDecompositionRelationAcc<F>,
    pub(crate) r_translator_non_native: TranslatorNonNativeFieldRelationAcc<F>,
    pub(crate) r_translator_zero: TranslatorZeroConstraintsRelationAcc<F>,
}

#[derive(Default)]
#[expect(dead_code)]
pub struct AllRelationEvaluationsTranslator<F: PrimeField> {
    pub(crate) r_translator_perm: TranslatorPermutationRelationEvals<F>,
    pub(crate) r_translator_delta: TranslatorDeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_translator_opcode: TranslatorOpCodeConstraintRelationEvals<F>,
    pub(crate) r_translator_acc: TranslatorAccumulatorTransferRelationEvals<F>,
    pub(crate) r_translator_decomp: TranslatorDecompositionRelationEvals<F>,
    pub(crate) r_translator_non_native: TranslatorNonNativeFieldRelationEvals<F>,
    pub(crate) r_translator_zero: TranslatorZeroConstraintsRelationEvals<F>,
}

fn extend_and_batch_univariates_template<F: PrimeField, const SIZE: usize>(
    acc: &AllRelationAccTranslator<F>,
    result: &mut Univariate<F, SIZE>,
    extended_random_poly: &Univariate<F, SIZE>,
    partial_evaluation_result: &F,
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

impl PlainProverFlavour for TranslatorFlavour {
    type AllRelationAcc<F: PrimeField> = AllRelationAccTranslator<F>;

    type AllRelationEvaluations<F: PrimeField> = AllRelationEvaluationsTranslator<F>;

    type SumcheckRoundOutput<F: PrimeField> =
        Univariate<F, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZK<F: PrimeField> =
        Univariate<F, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type ProverUnivariate<F: PrimeField> =
        Univariate<F, { TranslatorFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    const NUM_SUBRELATIONS: usize = TranslatorPermutationRelation::NUM_RELATIONS
        + TranslatorDeltaRangeConstraintRelation::NUM_RELATIONS
        + TranslatorOpCodeConstraintRelation::NUM_RELATIONS
        + TranslatorAccumulatorTransferRelation::NUM_RELATIONS
        + TranslatorDecompositionRelation::NUM_RELATIONS
        + TranslatorNonNativeFieldRelation::NUM_RELATIONS
        + TranslatorZeroConstraintsRelation::NUM_RELATIONS;

    fn scale<F: PrimeField>(acc: &mut Self::AllRelationAcc<F>, first_scalar: F, elements: &[F]) {
        tracing::trace!("Prove::Scale");
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

    fn extend_and_batch_univariates<F: PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutput<F>,
        extended_random_poly: &Self::SumcheckRoundOutput<F>,
        partial_evaluation_result: &F,
    ) {
        tracing::trace!("TranslatorProve::Extend and batch univariates");
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn extend_and_batch_univariates_zk<F: PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutputZK<F>,
        extended_random_poly: &Self::SumcheckRoundOutputZK<F>,
        partial_evaluation_result: &F,
    ) {
        tracing::trace!("TranslatorProve::Extend and batch univariates");
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn accumulate_relation_univariates<P: co_builder::prelude::HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorPermutationRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorDeltaRangeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorOpCodeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_opcode,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorAccumulatorTransferRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_acc,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorDecompositionRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_decomp,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorNonNativeFieldRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_non_native,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            TranslatorZeroConstraintsRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_translator_zero,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_relation_evaluations<P: co_builder::prelude::HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }

    fn scale_and_batch_elements<F: PrimeField>(
        _all_rel_evals: &Self::AllRelationEvaluations<F>,
        _first_scalar: F,
        _elements: &[F],
    ) -> F {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }

    fn receive_round_univariate_from_prover<
        F: PrimeField,
        H: TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        _transcript: &mut Transcript<F, H>,
        _label: String,
    ) -> co_builder::HonkProofResult<Self::SumcheckRoundOutput<P::ScalarField>> {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }

    fn receive_round_univariate_from_prover_zk<
        F: PrimeField,
        H: TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        _transcript: &mut Transcript<F, H>,
        _label: String,
    ) -> co_builder::HonkProofResult<Self::SumcheckRoundOutputZK<P::ScalarField>> {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }

    fn get_alpha_challenges<
        F: PrimeField,
        H: TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        _transcript: &mut Transcript<F, H>,
        _alphas: &mut Vec<P::ScalarField>,
    ) {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }
}
