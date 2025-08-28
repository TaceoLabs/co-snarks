use crate::co_decider::types::RelationParameters;
use crate::co_decider::univariates::SharedUnivariate;
use crate::types::AllEntities;
use crate::types_batch::{AllEntitiesBatch, AllEntitiesBatchRelationsTrait};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::{HonkProofResult, TranscriptFieldType};
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};
use common::mpc::NoirUltraHonkProver;
use common::transcript::{Transcript, TranscriptHasher};
use core::panic;
use mpc_net::Network;
use std::fmt::Debug;
use ultrahonk::plain_prover_flavour::UnivariateTrait;
use ultrahonk::prelude::Univariate;

pub trait MPCProverFlavour: Default + ProverFlavour {
    type AllRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup>;
    type AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: CurveGroup>: Default;
    type AllRelationEvaluations<T: NoirUltraHonkProver<P>, P: CurveGroup>: Default;

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
        + Debug
        + Default
        + std::marker::Sync;
    type ProverUnivariatePublic<P: CurveGroup>: UnivariateTrait<P::ScalarField>
        + Clone
        + Debug
        + Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Mul
        + std::marker::Sync
        + num_traits::identities::Zero;

    type AllEntitiesBatchRelations<T: NoirUltraHonkProver<P>,  P: HonkCurve<TranscriptFieldType>,>:AllEntitiesBatchRelationsTrait<T, P,Self>;

    const NUM_SUBRELATIONS: usize;
    const NUM_ALPHAS: usize = Self::NUM_SUBRELATIONS - 1;
    const CRAND_PAIRS_FACTOR: usize;

    fn scale<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &[P::ScalarField],
    );
    fn scale_by_challenge_and_accumulate<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        _acc: &mut Self::AllRelationEvaluations<T, P>,
        _first_scalar: P::ScalarField,
        _elements: &[P::ScalarField],
    ) -> (T::ArithmeticShare, T::ArithmeticShare) {
        panic!("scale_by_challenge_and_accumulate is not implemented for this flavor");
    }
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
    fn extend_and_batch_univariates_with_distinct_challenges<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        const SIZE: usize,
    >(
        _acc: &Self::AllRelationAcc<T, P>,
        _result: &mut SharedUnivariate<T, P, SIZE>,
        _first_term: Univariate<P::ScalarField, SIZE>,
        _running_challenge: &[Univariate<P::ScalarField, SIZE>],
    ) {
        panic!(
            "extend_and_batch_univariates_with_distinct_challenges is not implemented for this flavor"
        );
    }

    fn accumulate_relation_evaluations<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        _net: &N,
        _state: &mut T::State,
        _accumulators: &mut Self::AllRelationEvaluations<T, P>,
        _extended_edges: &AllEntities<T::ArithmeticShare, P::ScalarField, Self>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        _scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        panic!("accumulate_relation_evaluations is not implemented for this flavor");
    }
    fn accumulate_relation_univariates_batch<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirUltraHonkProver<P>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &Self::AllEntitiesBatchRelations<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> HonkProofResult<()>;
    fn accumulate_relation_univariates_with_extended_parameters<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirUltraHonkProver<P>,
        N: Network,
        const SIZE: usize,
    >(
        _net: &N,
        _state: &mut T::State,
        _univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        _input: &AllEntitiesBatch<T, P, Self>,
        _relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
        _scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        panic!(
            "accumulate_relation_univariates_with_extended_parameters is not implemented for this flavor"
        );
    }

    fn get_alpha_challenges<F: PrimeField, H: TranscriptHasher<F>, P: HonkCurve<F>>(
        transcript: &mut Transcript<F, H>,
        alphas: &mut Vec<P::ScalarField>,
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
