use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_builder::{prelude::HonkCurve, prover_flavour::ProverFlavour};
use co_builder::{HonkProofResult, TranscriptFieldType};
use rand::{CryptoRng, Rng};
use std::fmt::Debug;
use ultrahonk::plain_prover_flavour::UnivariateTest;
use ultrahonk::prelude::{Transcript, TranscriptHasher};

use crate::co_decider::types::RelationParameters;
use crate::mpc::NoirUltraHonkProver;
use crate::types_batch::AllEntitiesBatchRelations;

pub trait MPCProverFlavour: Default + ProverFlavour {
    type AllRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing>: Default;
    type AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: Pairing>: Default;

    type SumcheckRoundOutput<T: NoirUltraHonkProver<P>, P: Pairing>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + SharedUnivariateTest<T, P>;
    type SumcheckRoundOutputZK<T: NoirUltraHonkProver<P>, P: Pairing>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + std::ops::AddAssign
        + std::ops::SubAssign
        + SharedUnivariateTest<T, P>;
    type SumcheckRoundOutputPublic<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + UnivariateTest<F>;
    type SumcheckRoundOutputZKPublic<F: PrimeField>: Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Sub
        + std::ops::AddAssign
        + std::ops::SubAssign
        + UnivariateTest<F>;
    type ProverUnivariateShared<T: NoirUltraHonkProver<P>, P: Pairing>: SharedUnivariateTest<T, P>
        + Clone
        + Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Mul
        + num_traits::identities::Zero;
    type ProverUnivariatePublic<P: Pairing>: UnivariateTest<P::ScalarField>
        + Clone
        + Default
        + std::ops::MulAssign
        + std::ops::Add
        + std::ops::Mul
        + num_traits::identities::Zero;
    type Alphas<F: PrimeField>: Default + Clone + Copy + Debug;

    const NUM_SUBRELATIONS: usize;
    const NUM_ALPHAS: usize = Self::NUM_SUBRELATIONS - 1;

    fn scale<T: NoirUltraHonkProver<P>, P: Pairing>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &Self::Alphas<P::ScalarField>,
    );
    fn extend_and_batch_univariates<T: NoirUltraHonkProver<P>, P: Pairing>(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutput<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    );
    fn extend_and_batch_univariates_zk<T: NoirUltraHonkProver<P>, P: Pairing>(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutputZK<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputZKPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    );
    fn accumulate_relation_univariates_batch<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirUltraHonkProver<P>,
    >(
        driver: &mut T,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &AllEntitiesBatchRelations<T, P, Self>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
    ) -> HonkProofResult<()>;

    fn get_alpha_challenges<F: PrimeField, H: TranscriptHasher<F>, P: HonkCurve<F>>(
        transcript: &mut Transcript<F, H>,
        alphas: &mut Self::Alphas<P::ScalarField>,
    );
    fn reshare<T: NoirUltraHonkProver<P>, P: Pairing>(
        acc: Self::AllRelationAccHalfShared<T, P>,
        driver: &mut T,
    ) -> HonkProofResult<Self::AllRelationAcc<T, P>>;
}

//TODO Florin Think of a name for this trait
pub trait SharedUnivariateTest<T: NoirUltraHonkProver<P>, P: Pairing> {
    fn double(self) -> Self;

    fn double_in_place(&mut self);

    fn sqr(self) -> Self;

    fn square_in_place(&mut self);

    fn extend_from(&mut self, poly: &[T::ArithmeticShare]);

    fn get_random<R: Rng + CryptoRng>(rng: &mut R) -> Self;

    fn evaluations(&mut self) -> &mut [T::ArithmeticShare];

    fn evaluations_as_ref(&self) -> &[T::ArithmeticShare];

    fn mul_public<K>(&self, other: &K) -> Self
    where
        K: UnivariateTest<P::ScalarField>;

    fn sub(&self, rhs: &Self) -> Self;

    fn add(&self, rhs: &Self) -> Self;
}
