#![expect(unused)]
use crate::decider::relations::eccvm_relations::ecc_bools_relation::{
    EccBoolsRelation, EccBoolsRelationAcc, EccBoolsRelationEvals,
};
use crate::decider::relations::eccvm_relations::ecc_lookup_relation::{
    EccLookupRelation, EccLookupRelationAcc, EccLookupRelationEvals,
};
use crate::decider::relations::eccvm_relations::ecc_msm_relation::{
    EccMsmRelation, EccMsmRelationAcc, EccMsmRelationEvals,
};
use crate::decider::relations::eccvm_relations::ecc_point_table_relation::{
    EccPointTableRelation, EccPointTableRelationAcc, EccPointTableRelationEvals,
};
use crate::decider::relations::eccvm_relations::ecc_set_relation::{
    EccSetRelation, EccSetRelationAcc, EccSetRelationEvals,
};
use crate::decider::relations::eccvm_relations::ecc_transcript_relation::{
    EccTranscriptRelation, EccTranscriptRelationAcc, EccTranscriptRelationEvals,
};
use crate::decider::relations::eccvm_relations::ecc_wnaf_relation::{
    EccWnafRelation, EccWnafRelationAcc, EccWnafRelationEvals,
};
use crate::decider::sumcheck::sumcheck_round_prover::SumcheckProverRound;
use crate::decider::types::ClaimedEvaluations;
use crate::decider::types::{ProverUnivariates, RelationParameters};
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::prelude::{Transcript, TranscriptHasher, Univariate};
use crate::transcript::TranscriptFieldType;
use ark_ff::PrimeField;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::prover_flavour::ProverFlavour;
#[derive(Default)]
pub struct AllRelationAccECCVM<F: PrimeField> {
    pub(crate) r_ecc_transcript: EccTranscriptRelationAcc<F>,
    pub(crate) r_ecc_point_table: EccPointTableRelationAcc<F>,
    pub(crate) r_ecc_wnaf: EccWnafRelationAcc<F>,
    pub(crate) r_ecc_msm: EccMsmRelationAcc<F>,
    pub(crate) r_ecc_set: EccSetRelationAcc<F>,
    pub(crate) r_ecc_lookup: EccLookupRelationAcc<F>,
    pub(crate) r_ecc_bools: EccBoolsRelationAcc<F>,
}

#[derive(Default)]
pub struct AllRelationEvaluationsECCVM<F: PrimeField> {
    pub(crate) r_ecc_transcript: EccTranscriptRelationEvals<F>,
    pub(crate) r_ecc_point_table: EccPointTableRelationEvals<F>,
    pub(crate) r_ecc_wnaf: EccWnafRelationEvals<F>,
    pub(crate) r_ecc_msm: EccMsmRelationEvals<F>,
    pub(crate) r_ecc_set: EccSetRelationEvals<F>,
    pub(crate) r_ecc_lookup: EccLookupRelationEvals<F>,
    pub(crate) r_ecc_bools: EccBoolsRelationEvals<F>,
}

fn extend_and_batch_univariates_template<F: PrimeField, const SIZE: usize>(
    acc: &AllRelationAccECCVM<F>,
    result: &mut Univariate<F, SIZE>,
    extended_random_poly: &Univariate<F, SIZE>,
    partial_evaluation_result: &F,
) {
    tracing::trace!("Prove::Extend and batch univariates");
    acc.r_ecc_transcript.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_point_table.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_wnaf.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_msm.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_set.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_lookup.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_bools.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
}

impl PlainProverFlavour for ECCVMFlavour {
    type AllRelationAcc<F: ark_ff::PrimeField> = AllRelationAccECCVM<F>;

    type AllRelationEvaluations<F: ark_ff::PrimeField> = AllRelationEvaluationsECCVM<F>;

    type Alphas<F: ark_ff::PrimeField> = F;

    type SumcheckRoundOutput<F: ark_ff::PrimeField> =
        Univariate<F, { ECCVMFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZK<F: ark_ff::PrimeField> =
        Univariate<F, { ECCVMFlavour::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type ProverUnivariate<F: ark_ff::PrimeField> =
        Univariate<F, { ECCVMFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    const NUM_SUBRELATIONS: usize = EccBoolsRelation::NUM_RELATIONS
        + EccLookupRelation::NUM_RELATIONS
        + EccMsmRelation::NUM_RELATIONS
        + EccSetRelation::NUM_RELATIONS
        + EccWnafRelation::NUM_RELATIONS
        + EccPointTableRelation::NUM_RELATIONS
        + EccTranscriptRelation::NUM_RELATIONS;

    fn scale<F: ark_ff::PrimeField>(
        acc: &mut Self::AllRelationAcc<F>,
        first_scalar: F,
        elements: &Self::Alphas<F>,
    ) {
        tracing::trace!("Prove::Scale");
        let mut current_scalar = first_scalar;
        acc.r_ecc_transcript.scale(&mut current_scalar, elements);
        acc.r_ecc_point_table.scale(&mut current_scalar, elements);
        acc.r_ecc_wnaf.scale(&mut current_scalar, elements);
        acc.r_ecc_msm.scale(&mut current_scalar, elements);
        acc.r_ecc_set.scale(&mut current_scalar, elements);
        acc.r_ecc_lookup.scale(&mut current_scalar, elements);
        acc.r_ecc_bools.scale(&mut current_scalar, elements);
    }

    fn extend_and_batch_univariates<F: ark_ff::PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutput<F>,
        extended_random_poly: &Self::SumcheckRoundOutput<F>,
        partial_evaluation_result: &F,
    ) {
        tracing::trace!("Prove::Extend and batch univariates");
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn extend_and_batch_univariates_zk<F: ark_ff::PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutputZK<F>,
        extended_random_poly: &Self::SumcheckRoundOutputZK<F>,
        partial_evaluation_result: &F,
    ) {
        tracing::trace!("Prove::Extend and batch univariates");
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
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
        scaling_factor: &P::ScalarField,
    ) {
        SumcheckProverRound::<<P as ark_ec::PrimeGroup>::ScalarField, ECCVMFlavour>::accumulate_ecc_transcript_relation::<P, { Self::MAX_PARTIAL_RELATION_LENGTH }>(
            &mut univariate_accumulators.r_ecc_transcript,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            EccPointTableRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_ecc_point_table,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            EccWnafRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_ecc_wnaf,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::<<P as ark_ec::PrimeGroup>::ScalarField, ECCVMFlavour>::accumulate_ecc_msm_relation::<P, { Self::MAX_PARTIAL_RELATION_LENGTH }>(
            &mut univariate_accumulators.r_ecc_msm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::<<P as ark_ec::PrimeGroup>::ScalarField, ECCVMFlavour>::accumulate_ecc_set_relation::<P, { Self::MAX_PARTIAL_RELATION_LENGTH }>(
            &mut univariate_accumulators.r_ecc_set,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            EccLookupRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_ecc_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            EccBoolsRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_ecc_bools,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_relation_evaluations<P: co_builder::prelude::HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
        scaling_factor: &P::ScalarField,
    ) {
        todo!("Implement Sumcheck Verifier for ECCVMFlavour");
    }

    fn scale_and_batch_elements<F: ark_ff::PrimeField>(
        all_rel_evals: &Self::AllRelationEvaluations<F>,
        first_scalar: F,
        elements: &Self::Alphas<F>,
    ) -> F {
        todo!("Implement Sumcheck Verifier for ECCVMFlavour");
    }

    fn receive_round_univariate_from_prover<
        F: ark_ff::PrimeField,
        H: TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H>,
        label: String,
    ) -> co_builder::HonkProofResult<Self::SumcheckRoundOutput<P::ScalarField>> {
        todo!("Implement Sumcheck Verifier for ECCVMFlavour");
    }

    fn receive_round_univariate_from_prover_zk<
        F: ark_ff::PrimeField,
        H: TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H>,
        label: String,
    ) -> co_builder::HonkProofResult<Self::SumcheckRoundOutputZK<P::ScalarField>> {
        todo!("Implement Sumcheck Verifier for ECCVMFlavour");
    }

    fn get_alpha_challenges<
        F: ark_ff::PrimeField,
        H: TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H>,
        alphas: &mut Self::Alphas<P::ScalarField>,
    ) {
        todo!("Implement Sumcheck Verifier for ECCVMFlavour");
    }
}
