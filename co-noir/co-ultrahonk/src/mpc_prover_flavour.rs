use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::{HonkProofResult, TranscriptFieldType};
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};
use mpc_net::Network;
use std::fmt::Debug;
use ultrahonk::plain_prover_flavour::UnivariateTrait;
use ultrahonk::prelude::{Transcript, TranscriptHasher};

use crate::co_decider::types::RelationParameters;
use crate::mpc::NoirUltraHonkProver;
use crate::types_batch::AllEntitiesBatchRelationsTrait;

pub trait MPCProverFlavour: Default + ProverFlavour {
    type AllRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup>;
    type AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: CurveGroup>: Default;

    type SumcheckRoundOutput<T: NoirUltraHonkProver<P>, P: CurveGroup>: Default
        + SharedUnivariateTrait<T, P>;
    type SumcheckRoundOutputZK<T: NoirUltraHonkProver<P>, P: CurveGroup>: Default
        + SharedUnivariateTrait<T, P>;
    type SumcheckRoundOutputPublic<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + UnivariateTrait<F>;
    type SumcheckRoundOutputZKPublic<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + std::ops::AddAssign
        + std::ops::SubAssign
        + UnivariateTrait<F>;
    type ProverUnivariateShared<T: NoirUltraHonkProver<P>, P: CurveGroup>: SharedUnivariateTrait<T, P>
        + Clone
        + Default
        + std::marker::Sync;
    type ProverUnivariatePublic<P: CurveGroup>: UnivariateTrait<P::ScalarField>
        + Clone
        + Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Mul
        + std::marker::Sync
        + num_traits::identities::Zero;

    type AllEntitiesBatchRelations<T: NoirUltraHonkProver<P>,  P: HonkCurve<TranscriptFieldType>,>:AllEntitiesBatchRelationsTrait<T, P,Self>;
    type Alphas<F: PrimeField>: Default + Clone + Copy + Debug;

    const NUM_SUBRELATIONS: usize;
    const NUM_ALPHAS: usize = Self::NUM_SUBRELATIONS - 1;
    const CRAND_PAIRS_FACTOR: usize;

    fn scale<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &Self::Alphas<P::ScalarField>,
    );
    fn extend_and_batch_univariates<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutput<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    );
    fn extend_and_batch_univariates_zk<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutputZK<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputZKPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    );
    fn accumulate_relation_univariates_batch<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirUltraHonkProver<P>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &Self::AllEntitiesBatchRelations<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
    ) -> HonkProofResult<()>;

    fn get_alpha_challenges<F: PrimeField, H: TranscriptHasher<F>, P: HonkCurve<F>>(
        transcript: &mut Transcript<F, H>,
        alphas: &mut Self::Alphas<P::ScalarField>,
    );
    fn reshare<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        acc: Self::AllRelationAccHalfShared<T, P>,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<Self::AllRelationAcc<T, P>>;
}

pub trait SharedUnivariateTrait<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    fn extend_from(&mut self, poly: &[T::ArithmeticShare]);

    fn get_random<N: Network>(net: &N, state: &mut T::State) -> eyre::Result<Self>
    where
        Self: std::marker::Sized;

    fn evaluations(&mut self) -> &mut [T::ArithmeticShare];

    fn evaluations_as_ref(&self) -> &[T::ArithmeticShare];

    fn mul_public<K>(&self, other: &K) -> Self
    where
        K: UnivariateTrait<P::ScalarField>;

    fn sub(&self, rhs: &Self) -> Self;

    fn add(&self, rhs: &Self) -> Self;
}
