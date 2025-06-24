use ark_ff::PrimeField;
use co_builder::HonkProofResult;
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};
use rand::{CryptoRng, Rng};
use std::fmt::Debug;

pub trait MPCProverFlavour: Default + ProverFlavour {
    type AllRelationAcc<F: PrimeField>: Default;
    type AllRelationEvaluations<F: PrimeField>: Default;

    type SumcheckRoundOutput<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + UnivariateTest<F>;
    type SumcheckRoundOutputZK<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + std::ops::AddAssign
        + std::ops::SubAssign
        + UnivariateTest<F>;
    type ProverUnivariate<F: PrimeField>: UnivariateTest<F>
        + Clone
        + Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Mul
        + num_traits::identities::Zero;
    type Alphas<F: PrimeField>: Default + Clone + Copy + Debug;

    const NUM_SUBRELATIONS: usize;
    const NUM_ALPHAS: usize = Self::NUM_SUBRELATIONS - 1;

    // fn scale<F: PrimeField>(
    //     acc: &mut Self::AllRelationAcc<F>,
    //     first_scalar: F,
    //     elements: &Self::Alphas<F>,
    // );
    // fn extend_and_batch_univariates<F: PrimeField>(
    //     acc: &Self::AllRelationAcc<F>,
    //     result: &mut Self::SumcheckRoundOutput<F>,
    //     extended_random_poly: &Self::SumcheckRoundOutput<F>,
    //     partial_evaluation_result: &F,
    // );
    // fn extend_and_batch_univariates_zk<F: PrimeField>(
    //     acc: &Self::AllRelationAcc<F>,
    //     result: &mut Self::SumcheckRoundOutputZK<F>,
    //     extended_random_poly: &Self::SumcheckRoundOutputZK<F>,
    //     partial_evaluation_result: &F,
    // );
    // fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
    //     univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
    //     extended_edges: &ProverUnivariates<P::ScalarField, Self>,
    //     relation_parameters: &RelationParameters<P::ScalarField, Self>,
    //     scaling_factor: &P::ScalarField,
    // );
    // fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
    //     univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
    //     extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
    //     relation_parameters: &RelationParameters<P::ScalarField, Self>,
    //     scaling_factor: &P::ScalarField,
    // );
    // fn scale_and_batch_elements<F: PrimeField>(
    //     all_rel_evals: &Self::AllRelationEvaluations<F>,
    //     first_scalar: F,
    //     elements: &Self::Alphas<F>,
    // ) -> F;
    // fn receive_round_univariate_from_prover<
    //     F: PrimeField,
    //     H: TranscriptHasher<F>,
    //     P: HonkCurve<F>,
    // >(
    //     transcript: &mut Transcript<F, H>,
    //     label: String,
    // ) -> HonkProofResult<Self::SumcheckRoundOutput<P::ScalarField>>;
    // fn receive_round_univariate_from_prover_zk<
    //     F: PrimeField,
    //     H: TranscriptHasher<F>,
    //     P: HonkCurve<F>,
    // >(
    //     transcript: &mut Transcript<F, H>,
    //     label: String,
    // ) -> HonkProofResult<Self::SumcheckRoundOutputZK<P::ScalarField>>;

    // fn get_alpha_challenges<F: PrimeField, H: TranscriptHasher<F>, P: HonkCurve<F>>(
    //     transcript: &mut Transcript<F, H>,
    //     alphas: &mut Self::Alphas<P::ScalarField>,
    // );
}

//TODO Florin Think of a name for this trait
pub trait UnivariateTest<F: PrimeField> {
    fn double(self) -> Self;

    fn double_in_place(&mut self);

    fn sqr(self) -> Self;

    fn square_in_place(&mut self);

    fn extend_from(&mut self, poly: &[F]);

    fn evaluate(&self, u: F) -> F;

    fn get_random<R: Rng + CryptoRng>(rng: &mut R) -> Self;

    fn evaluations(&mut self) -> &mut [F];

    fn evaluations_as_ref(&self) -> &[F];
}
