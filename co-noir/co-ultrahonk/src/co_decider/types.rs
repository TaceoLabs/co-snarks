use super::univariates::SharedUnivariate;
use crate::{
    types::{AllEntities, Polynomials},
    types_batch::AllEntitiesBatch,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use co_noir_common::mpc::NoirUltraHonkProver;
use itertools::izip;
use std::iter;
use ultrahonk::{NUM_ALPHAS, prelude::Univariate};

pub(crate) struct ProverMemory<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) polys: AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField>,
    pub(crate) alphas: [P::ScalarField; NUM_ALPHAS],
    pub(crate) gate_challenges: Vec<P::ScalarField>,
}

pub(crate) const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
pub(crate) const BATCHED_RELATION_PARTIAL_LENGTH: usize = MAX_PARTIAL_RELATION_LENGTH + 1;
pub(crate) const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = BATCHED_RELATION_PARTIAL_LENGTH + 1;

pub(crate) type ProverUnivariates<T, P> = AllEntities<
    SharedUnivariate<T, P, MAX_PARTIAL_RELATION_LENGTH>,
    Univariate<<P as PrimeGroup>::ScalarField, MAX_PARTIAL_RELATION_LENGTH>,
>;

pub(crate) type ProverUnivariatesBatch<T, P> = AllEntitiesBatch<T, P>;
pub(crate) type PartiallyEvaluatePolys<T, P> = AllEntities<
    Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>,
    Vec<<P as PrimeGroup>::ScalarField>,
>;
pub(crate) type ClaimedEvaluations<F> = AllEntities<F, F>;

pub(crate) struct RelationParameters<F: PrimeField> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) public_input_delta: F,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> ProverMemory<T, P> {
    pub(crate) fn from_memory_and_polynomials(
        prover_memory: crate::co_oink::types::ProverMemory<T, P>,
        polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    ) -> Self {
        let relation_parameters = RelationParameters {
            eta_1: prover_memory.challenges.eta_1,
            eta_2: prover_memory.challenges.eta_2,
            eta_3: prover_memory.challenges.eta_3,
            beta: prover_memory.challenges.beta,
            gamma: prover_memory.challenges.gamma,
            public_input_delta: prover_memory.public_input_delta,
        };
        let alphas = prover_memory.challenges.alphas;
        let gate_challenges = Default::default();

        let mut memory = AllEntities::default();

        // TACEO TODO Barretenberg uses the same memory for the shifted polynomials as for the non-shifted ones

        // Missing lookups
        *memory.witness.lookup_inverses_mut() = prover_memory.lookup_inverses.into_vec();
        *memory.witness.lookup_read_counts_mut() =
            polynomials.witness.lookup_read_counts().as_ref().to_vec();
        *memory.witness.lookup_read_tags_mut() =
            polynomials.witness.lookup_read_tags().as_ref().to_vec();

        // Shift the witnesses
        for (des_shifted, des, src) in izip!(
            memory.shifted_witness.iter_mut(),
            memory.witness.to_be_shifted_mut(),
            polynomials
                .witness
                .into_wires()
                .take(3)
                .chain(iter::once(prover_memory.w_4))
                .chain(iter::once(prover_memory.z_perm)),
        ) {
            // TACEO TODO use same memory to prevent copying?
            *des_shifted = src.shifted().to_vec();
            *des = src.into_vec();
        }

        // Copy precomputed polynomials
        for (des, src) in izip!(
            memory.precomputed.iter_mut(),
            polynomials.precomputed.into_iter()
        ) {
            *des = src.into_vec();
        }

        Self {
            polys: memory,
            relation_parameters,
            alphas,
            gate_challenges,
        }
    }
}
