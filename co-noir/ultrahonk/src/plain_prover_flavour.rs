use crate::decider::types::RelationParameters;
use crate::decider::types::{ClaimedEvaluations, ProverUnivariates, ProverUnivariatesSized};
use crate::prelude::Univariate;
use ark_ff::PrimeField;
use co_builder::prover_flavour::ProverFlavour;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::transcript::{Transcript, TranscriptHasher};
use rand::{CryptoRng, Rng};
use std::fmt::Debug;

pub trait PlainProverFlavour: Default + ProverFlavour {
    type AllRelationAcc<F: PrimeField>: Default;
    type AllRelationEvaluations<F: PrimeField>: Default;
    type SumcheckRoundOutput<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + UnivariateTrait<F>;
    type SumcheckRoundOutputZK<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + std::ops::AddAssign
        + std::ops::SubAssign
        + UnivariateTrait<F>;
    type ProverUnivariate<F: PrimeField>: UnivariateTrait<F>
        + Clone
        + Debug
        + Default
        + std::marker::Sync
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + std::ops::Mul
        + num_traits::identities::Zero;

    const NUM_SUBRELATIONS: usize;
    const NUM_ALPHAS: usize = Self::NUM_SUBRELATIONS - 1;

    fn scale<F: PrimeField>(acc: &mut Self::AllRelationAcc<F>, first_scalar: F, elements: &[F]);
    fn extend_and_batch_univariates<F: PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutput<F>,
        extended_random_poly: &Self::SumcheckRoundOutput<F>,
        partial_evaluation_result: &F,
    );
    fn extend_and_batch_univariates_zk<F: PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutputZK<F>,
        extended_random_poly: &Self::SumcheckRoundOutputZK<F>,
        partial_evaluation_result: &F,
    );
    fn extend_and_batch_univariates_with_distinct_challenges<F: PrimeField, const SIZE: usize>(
        _univariate_accumulators: &Self::AllRelationAcc<F>,
        _result: &mut Univariate<F, SIZE>,
        _first_term: Univariate<F, SIZE>,
        _running_challenge: &[Univariate<F, SIZE>],
    ) {
        panic!(
            "extend_and_batch_univariates_with_distinct_challenges should not be called for this flavour"
        );
    }
    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    );
    fn accumulate_relation_univariates_extended_parameters<
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        _univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        _extended_edges: &ProverUnivariatesSized<P::ScalarField, Self, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
        _scaling_factor: &P::ScalarField,
    ) {
        panic!(
            "accumulate_relation_univariates_extended_parameters should not be called for this flavour"
        );
    }
    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    );
    fn scale_and_batch_elements<F: PrimeField>(
        all_rel_evals: &Self::AllRelationEvaluations<F>,
        first_scalar: F,
        elements: &[F],
    ) -> F;
    fn scale_by_challenge_and_accumulate<F: PrimeField>(
        _all_rel_evals: &Self::AllRelationEvaluations<F>,
        _first_scalar: F,
        _elements: &[F],
    ) -> (F, F) {
        panic!("scale_by_challenge_and_accumulate should not be called for this flavour");
    }
    fn receive_round_univariate_from_prover<
        F: PrimeField,
        H: TranscriptHasher<F, PlainUltraHonkDriver, P>,
        P: HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H, PlainUltraHonkDriver, P>,
        label: String,
    ) -> HonkProofResult<Self::SumcheckRoundOutput<P::ScalarField>>;
    fn receive_round_univariate_from_prover_zk<
        F: PrimeField,
        H: TranscriptHasher<F, PlainUltraHonkDriver, P>,
        P: HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H, PlainUltraHonkDriver, P>,
        label: String,
    ) -> HonkProofResult<Self::SumcheckRoundOutputZK<P::ScalarField>>;

    fn get_alpha_challenges<
        F: PrimeField,
        H: TranscriptHasher<F, PlainUltraHonkDriver, P>,
        P: HonkCurve<F>,
    >(
        transcript: &mut Transcript<F, H, PlainUltraHonkDriver, P>,
        alphas: &mut Vec<P::ScalarField>,
    );
}

pub trait UnivariateTrait<F: PrimeField> {
    fn double(self) -> Self;

    fn double_in_place(&mut self);

    fn sqr(self) -> Self;

    fn square_in_place(&mut self);

    fn extend_from(&mut self, poly: &[F]);

    fn evaluate(&self, u: F) -> F;

    fn get_random<R: Rng + CryptoRng>(rng: &mut R) -> Self;

    fn evaluations(&mut self) -> &mut [F];

    fn evaluations_as_ref(&self) -> &[F];

    fn value_at(&self, i: usize) -> F;
}
