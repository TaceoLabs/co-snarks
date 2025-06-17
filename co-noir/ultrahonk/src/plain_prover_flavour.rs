use crate::decider::types::{ClaimedEvaluations, ProverUnivariates};
use crate::{
    decider::types::RelationParameters, prelude::Univariate, transcript::TranscriptFieldType,
};
use ark_ff::PrimeField;
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};
use rand::{CryptoRng, Rng};

pub trait PlainProverFlavour: Default + ProverFlavour {
    type AllRelationAcc<F: PrimeField>: Default;
    type AllRelationEvaluations<F: PrimeField>: Default;
    type Alphas<F: PrimeField>: Default + Clone + Copy;
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
        + std::ops::Add;

    const NUM_SUBRELATIONS: usize;

    fn scale<F: PrimeField>(
        acc: &mut Self::AllRelationAcc<F>,
        first_scalar: F,
        elements: &Self::Alphas<F>,
    );
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
    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
        scaling_factor: &P::ScalarField,
    );
    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
        scaling_factor: &P::ScalarField,
    );
    fn scale_and_batch_elements<F: PrimeField>(
        all_rel_evals: &Self::AllRelationEvaluations<F>,
        first_scalar: F,
        elements: &Self::Alphas<F>,
    ) -> F;
}

pub trait UnivariateTest<F: PrimeField> {
    // type ProverUnivariate<F: PrimeField>: Clone + Default;

    fn double(self) -> Self;

    fn double_in_place(&mut self);
    fn sqr(self) -> Self;

    fn square_in_place(&mut self);

    fn extend_from(&mut self, poly: &[F]);

    fn evaluate(&self, u: F) -> F;

    // fn extend_and_batch_univariates<const SIZE2: usize>(
    //     &self,
    //     result: &mut Univariate<F, SIZE2>,
    //     extended_random_poly: &Univariate<F, SIZE2>,
    //     partial_evaluation_result: &F,
    //     linear_independent: bool,
    // );

    fn get_random<R: Rng + CryptoRng>(rng: &mut R) -> Self;

    fn evaluations(&mut self) -> Vec<F>;
    fn evaluations_as_ref(&self) -> &[F];

    // fn extend_and_batch_univariates<const SIZE: usize, F: PrimeField>(
    //     lhs: &Univariate<F, SIZE>,
    //     result: &mut Self::ProverUnivariate<F>,
    //     extended_random_poly: &Self::ProverUnivariate<F>,
    //     partial_evaluation_result: &F,
    //     linear_independent: bool,
    // );
}
