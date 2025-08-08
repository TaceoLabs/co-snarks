use crate::decider::sumcheck::sumcheck_round_prover::SumcheckProverRound;
use crate::decider::sumcheck::sumcheck_round_verifier::SumcheckVerifierRound;
use crate::decider::types::{
    ClaimedEvaluations, ProverUnivariates, ProverUnivariatesSized, RelationParameters,
};
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::prelude::Univariate;
use ark_ff::PrimeField;
use co_builder::HonkProofResult;
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::prover_flavour::ProverFlavour;
use common::transcript::{Transcript, TranscriptFieldType, TranscriptHasher};
use std::array;

use crate::decider::relations::{
    auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc, AuxiliaryRelationEvals},
    delta_range_constraint_relation::{
        DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
        DeltaRangeConstraintRelationEvals,
    },
    elliptic_relation::{EllipticRelation, EllipticRelationAcc, EllipticRelationEvals},
    logderiv_lookup_relation::{
        LogDerivLookupRelation, LogDerivLookupRelationAcc, LogDerivLookupRelationEvals,
    },
    permutation_relation::{
        UltraPermutationRelation, UltraPermutationRelationAcc, UltraPermutationRelationEvals,
    },
    poseidon2_external_relation::{
        Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc, Poseidon2ExternalRelationEvals,
    },
    poseidon2_internal_relation::{
        Poseidon2InternalRelation, Poseidon2InternalRelationAcc, Poseidon2InternalRelationEvals,
    },
    ultra_arithmetic_relation::{
        UltraArithmeticRelation, UltraArithmeticRelationAcc, UltraArithmeticRelationEvals,
    },
};
use ark_ff::AdditiveGroup;

#[derive(Default)]
pub struct AllRelationAccUltra<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_aux: AuxiliaryRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
}

#[derive(Default)]
pub struct AllRelationEvaluationsUltra<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationEvals<F>,
    pub(crate) r_perm: UltraPermutationRelationEvals<F>,
    pub(crate) r_lookup: LogDerivLookupRelationEvals<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_elliptic: EllipticRelationEvals<F>,
    pub(crate) r_aux: AuxiliaryRelationEvals<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationEvals<F>,
}

fn extend_and_batch_univariates_template<F: PrimeField, const SIZE: usize>(
    acc: &AllRelationAccUltra<F>,
    result: &mut Univariate<F, SIZE>,
    extended_random_poly: &Univariate<F, SIZE>,
    partial_evaluation_result: &F,
) {
    tracing::trace!("Prove::Extend and batch univariates");
    acc.r_arith.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_perm.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_lookup.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_delta.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_elliptic.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_aux
        .extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result);
    acc.r_pos_ext.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_pos_int.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
}

impl PlainProverFlavour for UltraFlavour {
    type AllRelationAcc<F: PrimeField> = AllRelationAccUltra<F>;
    type AllRelationEvaluations<F: PrimeField> = AllRelationEvaluationsUltra<F>;
    type Alpha<F: PrimeField> = F;
    type SumcheckRoundOutput<F: PrimeField> =
        Univariate<F, { UltraFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;
    type SumcheckRoundOutputZK<F: PrimeField> =
        Univariate<F, { UltraFlavour::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;
    type ProverUnivariate<F: PrimeField> =
        Univariate<F, { UltraFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
        + UltraPermutationRelation::NUM_RELATIONS
        + DeltaRangeConstraintRelation::NUM_RELATIONS
        + EllipticRelation::NUM_RELATIONS
        + AuxiliaryRelation::NUM_RELATIONS
        + LogDerivLookupRelation::NUM_RELATIONS
        + Poseidon2ExternalRelation::NUM_RELATIONS
        + Poseidon2InternalRelation::NUM_RELATIONS;

    fn scale<F: PrimeField>(
        acc: &mut Self::AllRelationAcc<F>,
        first_scalar: F,
        elements: &[Self::Alpha<F>],
    ) {
        tracing::trace!("Prove::Scale");
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        acc.r_arith.scale(&[first_scalar, elements[0]]);
        acc.r_perm.scale(&elements[1..3]);
        acc.r_lookup.scale(&elements[3..5]);
        acc.r_delta.scale(&elements[5..9]);
        acc.r_elliptic.scale(&elements[9..11]);
        acc.r_aux.scale(&elements[11..17]);
        acc.r_pos_ext.scale(&elements[17..21]);
        acc.r_pos_int.scale(&elements[21..]);
    }

    fn extend_and_batch_univariates<F: PrimeField>(
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

    fn extend_and_batch_univariates_zk<F: PrimeField>(
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

    fn extend_and_batch_univariates_with_distinct_challenges<F: PrimeField, const SIZE: usize>(
        _acc: &Self::AllRelationAcc<F>,
        _result: &mut Univariate<F, SIZE>,
        _first_term: Univariate<F, SIZE>,
        _running_challenge: &[Univariate<F, SIZE>],
    ) {
        todo!();
    }

    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Prove::Accumulate relations");

        SumcheckProverRound::accumulate_one_relation_univariates::<
            UltraArithmeticRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            UltraPermutationRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            LogDerivLookupRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            DeltaRangeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_elliptic_curve_relation_univariates::<
            P,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            AuxiliaryRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            Poseidon2ExternalRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            Poseidon2InternalRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
    fn accumulate_relation_univariates_extended_parameters<
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        _univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        _extended_edges: &ProverUnivariatesSized<P::ScalarField, Self, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
        _scaling_factor: &P::ScalarField,
    ) {
        todo!()
    }
    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Verify::Accumulate relations");
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            UltraArithmeticRelation,
        >(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            UltraPermutationRelation,
        >(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            DeltaRangeConstraintRelation,
        >(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_elliptic_curve_relation_evaluations(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            LogDerivLookupRelation,
        >(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            Poseidon2ExternalRelation,
        >(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            Poseidon2InternalRelation,
        >(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn scale_and_batch_elements<F: PrimeField>(
        all_rel_evals: &Self::AllRelationEvaluations<F>,
        first_scalar: F,
        elements: &[Self::Alpha<F>],
    ) -> F {
        tracing::trace!("Verify::scale_and_batch_elements");
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        let mut output = F::zero();
        all_rel_evals
            .r_arith
            .scale_and_batch_elements(&[first_scalar, elements[0]], &mut output);
        all_rel_evals
            .r_perm
            .scale_and_batch_elements(&elements[1..3], &mut output);
        all_rel_evals
            .r_lookup
            .scale_and_batch_elements(&elements[3..5], &mut output);
        all_rel_evals
            .r_delta
            .scale_and_batch_elements(&elements[5..9], &mut output);
        all_rel_evals
            .r_elliptic
            .scale_and_batch_elements(&elements[9..11], &mut output);
        all_rel_evals
            .r_aux
            .scale_and_batch_elements(&elements[11..17], &mut output);

        all_rel_evals
            .r_pos_ext
            .scale_and_batch_elements(&elements[17..21], &mut output);
        all_rel_evals
            .r_pos_int
            .scale_and_batch_elements(&elements[21..], &mut output);

        output
    }

    fn scale_by_challenge_and_accumulate<F: PrimeField>(
        all_rel_evals: &Self::AllRelationEvaluations<F>,
        first_scalar: F,
        elements: &[Self::Alpha<F>],
    ) -> (F, F) {
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        let (mut linearly_dependent_contribution, mut linearly_independent_contribution) =
            (F::ZERO, F::ZERO);
        all_rel_evals.r_arith.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &[first_scalar, elements[0]],
        );
        all_rel_evals.r_perm.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[1..3],
        );
        all_rel_evals.r_lookup.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[3..5],
        );
        all_rel_evals.r_delta.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[5..9],
        );
        all_rel_evals.r_elliptic.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[9..11],
        );
        all_rel_evals.r_aux.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[11..17],
        );
        all_rel_evals.r_pos_ext.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[17..21],
        );
        all_rel_evals.r_pos_int.scale_by_challenge_and_accumulate(
            &mut linearly_independent_contribution,
            &mut linearly_dependent_contribution,
            &elements[21..],
        );

        (
            linearly_independent_contribution,
            linearly_dependent_contribution,
        )
    }

    fn receive_round_univariate_from_prover<
        F: PrimeField,
        H: TranscriptHasher<F>,
        P: HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H>,
        label: String,
    ) -> HonkProofResult<Self::SumcheckRoundOutput<P::ScalarField>> {
        let array = transcript
            .receive_fr_array_from_prover::<P, { Self::BATCHED_RELATION_PARTIAL_LENGTH }>(label)?;
        Ok(Self::SumcheckRoundOutput::<P::ScalarField> { evaluations: array })
    }

    fn receive_round_univariate_from_prover_zk<
        F: PrimeField,
        H: TranscriptHasher<F>,
        P: HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H>,
        label: String,
    ) -> HonkProofResult<Self::SumcheckRoundOutputZK<P::ScalarField>> {
        let array = transcript
            .receive_fr_array_from_prover::<P, { Self::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>(
                label,
            )?;
        Ok(Self::SumcheckRoundOutputZK::<P::ScalarField> { evaluations: array })
    }
    fn get_alpha_challenges<F: PrimeField, H: TranscriptHasher<F>, P: HonkCurve<F>>(
        transcript: &mut Transcript<F, H>,
        alphas: &mut Vec<Self::Alpha<P::ScalarField>>,
    ) {
        let args: [String; Self::NUM_ALPHAS] = array::from_fn(|i| format!("alpha_{i}"));
        alphas.resize(Self::NUM_ALPHAS, P::ScalarField::ZERO);
        alphas.copy_from_slice(&transcript.get_challenges::<P>(&args));
    }
}
