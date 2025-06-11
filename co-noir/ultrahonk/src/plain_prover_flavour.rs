use crate::{
    decider::types::{ProverUnivariates, RelationParameters},
    prelude::Univariate,
    transcript::TranscriptFieldType,
};
use ark_ff::PrimeField;
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};

pub trait PlainProverFlavour<F: PrimeField>: Default + ProverFlavour<F> {
    type AllRelationAcc: Default;

    const NUM_SUBRELATIONS: usize;

    fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]);
    fn extend_and_batch_univariates<const SIZE: usize>(
        acc: &Self::AllRelationAcc,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    );
    fn accumulate_relation_univariates<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        const UNIVARIATE_SIZE: usize,
    >(
        univariate_accumulators: &mut Self::AllRelationAcc,
        extended_edges: &ProverUnivariates<F, Self, UNIVARIATE_SIZE>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
}
