use super::univariate::Univariate;
use crate::{
    types::{AllEntities, Polynomials},
    NUM_ALPHAS,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use itertools::izip;
use std::{iter, vec};

pub(crate) struct ProverMemory<P: Pairing> {
    pub(crate) polys: AllEntities<Vec<P::ScalarField>>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField>,
}

pub(crate) const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
pub(crate) type ProverUnivariates<F> = AllEntities<Univariate<F, MAX_PARTIAL_RELATION_LENGTH>>;
pub(crate) type PartiallyEvaluatePolys<F> = AllEntities<Vec<F>>;
pub(crate) type ClaimedEvaluations<F> = AllEntities<F>;

pub(crate) struct RelationParameters<F: PrimeField> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) public_input_delta: F,
    pub(crate) alphas: [F; NUM_ALPHAS],
    pub(crate) gate_challenges: Vec<F>,
}

pub(crate) struct GateSeparatorPolynomial<F: PrimeField> {
    betas: Vec<F>,
    pub(crate) beta_products: Vec<F>,
    pub(crate) partial_evaluation_result: F,
    current_element_idx: usize,
    pub(crate) periodicity: usize,
}

impl<F: PrimeField> GateSeparatorPolynomial<F> {
    pub(crate) fn new(betas: Vec<F>) -> Self {
        let pow_size = 1 << betas.len();
        let current_element_idx = 0;
        let periodicity = 2;
        let partial_evaluation_result = F::ONE;

        // Barretenberg uses multithreading here and a simpler algorithm with worse complexity
        let mut beta_products = vec![F::ONE; pow_size];
        for (i, beta) in betas.iter().enumerate() {
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

    pub(crate) fn current_element(&self) -> F {
        self.betas[self.current_element_idx]
    }

    pub(crate) fn partially_evaluate(&mut self, round_challenge: F) {
        let current_univariate_eval =
            F::ONE + (round_challenge * (self.betas[self.current_element_idx] - F::ONE));
        self.partial_evaluation_result *= current_univariate_eval;
        self.current_element_idx += 1;
        self.periodicity *= 2;
    }
}

impl<F: PrimeField> Default for RelationParameters<F> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            public_input_delta: Default::default(),
            alphas: [Default::default(); NUM_ALPHAS],
            gate_challenges: Default::default(),
        }
    }
}

impl<P: Pairing> ProverMemory<P> {
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
            alphas: prover_memory.challenges.alphas,
            gate_challenges: Default::default(),
        };

        let mut memory = AllEntities::<Vec<P::ScalarField>>::default();

        // TODO Barretenberg uses the same memory for the shifted polynomials as for the non-shifted ones

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
            // TODO use same memory to prevent copying?
            *des_shifted = src.shifted().to_vec();
            *des = src.into_vec();
        }

        // Shift the tables
        for (des, src) in izip!(
            memory.shifted_tables.iter_mut(),
            polynomials.precomputed.get_table_polynomials()
        ) {
            // TODO use same memory to prevent copying?
            *des = src.shifted().to_vec();
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
        }
    }
}