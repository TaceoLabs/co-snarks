use std::array;

use crate::decider::types::ClaimedEvaluations;
use crate::{
    decider::types::{ProverUnivariates, RelationParameters},
    prelude::Univariate,
    transcript::TranscriptFieldType,
};
use ark_ff::PrimeField;
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};
use rand::{CryptoRng, Rng};

pub trait PlainProverFlavour<F: PrimeField>:
    Default + ProverFlavour + ProverUnivariatePlainFlavour
{
    type AllRelationAcc: Default;
    type AllRelationEvaluations: Default;
    const NUM_SUBRELATIONS: usize;

    fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]);
    fn extend_and_batch_univariates<const SIZE: usize>(
        acc: &Self::AllRelationAcc,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    );
    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        univariate_accumulators: &mut Self::AllRelationAcc,
        extended_edges: &Self::ProverUnivariate<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    );
    fn scale_and_batch_elements(
        all_rel_evals: &Self::AllRelationEvaluations,
        first_scalar: F,
        elements: &[F],
    ) -> F;
}

pub trait ProverUnivariatePlainFlavour {
    type ProverUnivariate<F: PrimeField>: Clone + Default;

    fn double<F: PrimeField>(poly: Self::ProverUnivariate<F>) -> Self::ProverUnivariate<F> {
        let mut result = poly.clone();
        Self::double_in_place(&mut result);
        result
    }
    fn double_in_place<F: PrimeField>(poly: &mut Self::ProverUnivariate<F>);
    fn sqr<F: PrimeField>(poly: Self::ProverUnivariate<F>) -> Self::ProverUnivariate<F> {
        let mut result = poly.clone();
        Self::square_in_place(&mut result);
        result
    }
    fn square_in_place<F: PrimeField>(poly: &mut Self::ProverUnivariate<F>);
    fn extend_from<F: PrimeField>(poly_to: &mut Self::ProverUnivariate<F>, poly_from: &[F]);
    fn evaluate<F: PrimeField>(poly: &Self::ProverUnivariate<F>, u: F) -> F;
    fn get_random<R: Rng + CryptoRng, F: PrimeField>(rng: &mut R) -> Self::ProverUnivariate<F>;
    fn extend_and_batch_univariates<const SIZE: usize, F: PrimeField>(
        lhs: &Univariate<F, SIZE>,
        result: &mut Self::ProverUnivariate<F>,
        extended_random_poly: &Self::ProverUnivariate<F>,
        partial_evaluation_result: &F,
        linear_independent: bool,
    );
}
