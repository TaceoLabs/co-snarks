use super::univariate::Univariate;
use crate::{NUM_ALPHAS, types::AllEntities};
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::PrimeField;
use co_builder::prelude::VerifyingKey;
use co_noir_common::polynomials::polynomial::Polynomials;
use itertools::izip;
use std::{iter, vec};

pub(crate) struct ProverMemory<P: CurveGroup> {
    pub(crate) polys: AllEntities<Vec<P::ScalarField>>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField>,
    pub(crate) alphas: [P::ScalarField; NUM_ALPHAS],
    pub(crate) gate_challenges: Vec<P::ScalarField>,
}

pub(crate) struct VerifierMemory<C: CurveGroup> {
    pub(crate) verifier_commitments: VerifierCommitments<C::Affine>,
    pub(crate) relation_parameters: RelationParameters<C::ScalarField>,
    pub(crate) alphas: [C::ScalarField; NUM_ALPHAS],
    pub(crate) gate_challenges: Vec<C::ScalarField>,
    pub(crate) claimed_evaluations: ClaimedEvaluations<C::ScalarField>,
}

pub(crate) const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
pub(crate) const BATCHED_RELATION_PARTIAL_LENGTH: usize = MAX_PARTIAL_RELATION_LENGTH + 1;
pub(crate) const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = BATCHED_RELATION_PARTIAL_LENGTH + 1;

pub(crate) type ProverUnivariates<F> = AllEntities<Univariate<F, MAX_PARTIAL_RELATION_LENGTH>>;
pub(crate) type PartiallyEvaluatePolys<F> = AllEntities<Vec<F>>;
pub(crate) type ClaimedEvaluations<F> = AllEntities<F>;
pub(crate) type VerifierCommitments<P> = AllEntities<P>;

pub(crate) struct RelationParameters<F: PrimeField> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) public_input_delta: F,
}

pub struct GateSeparatorPolynomial<F: PrimeField> {
    betas: Vec<F>,
    pub beta_products: Vec<F>,
    pub partial_evaluation_result: F,
    current_element_idx: usize,
    pub periodicity: usize,
}

impl<F: PrimeField> GateSeparatorPolynomial<F> {
    pub fn new(betas: Vec<F>, log_num_mononmials: usize) -> Self {
        let pow_size = 1 << log_num_mononmials;
        let current_element_idx = 0;
        let periodicity = 2;
        let partial_evaluation_result = F::ONE;

        // Barretenberg uses multithreading here and a simpler algorithm with worse complexity
        let mut beta_products = vec![F::ONE; pow_size];
        for (i, beta) in betas.iter().take(log_num_mononmials).enumerate() {
            let index = 1 << i;
            beta_products[index] = *beta;
            for j in 1..index {
                beta_products[index + j] = beta_products[j] * beta;
            }
        }

        Self {
            betas,
            beta_products,
            partial_evaluation_result,
            current_element_idx,
            periodicity,
        }
    }

    pub fn new_without_products(betas: Vec<F>) -> Self {
        let current_element_idx = 0;
        let periodicity = 2;
        let partial_evaluation_result = F::ONE;

        Self {
            betas,
            beta_products: Vec::new(),
            partial_evaluation_result,
            current_element_idx,
            periodicity,
        }
    }

    pub fn current_element(&self) -> F {
        self.betas[self.current_element_idx]
    }

    pub fn partially_evaluate(&mut self, round_challenge: F) {
        let current_univariate_eval =
            F::ONE + (round_challenge * (self.betas[self.current_element_idx] - F::ONE));
        self.partial_evaluation_result *= current_univariate_eval;
        self.current_element_idx += 1;
        self.periodicity *= 2;
    }

    pub fn partially_evaluate_with_padding(&mut self, round_challenge: F, indicator: F) {
        let current_univariate_eval =
            F::ONE + (round_challenge * (self.betas[self.current_element_idx] - F::ONE));
        // If dummy round, make no update to the partial_evaluation_result
        self.partial_evaluation_result = (F::ONE - indicator) * self.partial_evaluation_result
            + indicator * self.partial_evaluation_result * current_univariate_eval;
        self.current_element_idx += 1;
        self.periodicity *= 2;
    }

    pub fn construct_virtual_separator(betas: &[F], round_challenges: &[F]) -> Self {
        let mut separator = Self::new_without_products(betas.to_vec());
        for u_k in round_challenges {
            separator.partially_evaluate(*u_k);
        }
        separator
    }
}

impl<P: CurveGroup> ProverMemory<P> {
    pub(crate) fn from_memory_and_polynomials(
        prover_memory: crate::oink::types::ProverMemory<P>,
        polynomials: Polynomials<P::ScalarField>,
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

impl<C: CurveGroup> VerifierMemory<C> {
    #[expect(clippy::field_reassign_with_default)]
    pub(crate) fn from_memory_and_key<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        verifier_memory: crate::oink::types::VerifierMemory<C>,
        vk: &VerifyingKey<P>,
    ) -> Self {
        let relation_parameters = RelationParameters {
            eta_1: verifier_memory.challenges.eta_1,
            eta_2: verifier_memory.challenges.eta_2,
            eta_3: verifier_memory.challenges.eta_3,
            beta: verifier_memory.challenges.beta,
            gamma: verifier_memory.challenges.gamma,
            public_input_delta: verifier_memory.public_input_delta,
        };
        let alphas = verifier_memory.challenges.alphas;
        let gate_challenges = Default::default();

        let mut memory = AllEntities::<C::Affine>::default();
        memory.witness = verifier_memory.witness_commitments;
        memory.precomputed = vk.inner_vk.commitments.clone();

        // These copies are not required
        // for (des, src) in izip!(
        //     memory.shifted_witness.iter_mut(),
        //     memory.witness.to_be_shifted().iter().cloned(),
        // ) {
        //     *des = src;
        // }
        // for (des, src) in izip!(
        //     memory.shifted_tables.iter_mut(),
        //     memory.precomputed.get_table_polynomials().iter().cloned()
        // ) {
        //     *des = src;
        // }

        Self {
            relation_parameters,
            verifier_commitments: memory,
            alphas,
            gate_challenges,
            claimed_evaluations: Default::default(),
        }
    }
}
