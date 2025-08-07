use super::univariate::Univariate;
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::types::AllEntities;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::{
    ProverWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::prelude::Polynomial;
use co_builder::prelude::{Polynomials, VerifyingKey};
use co_builder::prover_flavour::Flavour;
use itertools::izip;
use std::{iter, vec};

#[derive(Default)]
pub struct ProverMemory<P: Pairing, L: PlainProverFlavour> {
    pub polys: AllEntities<Vec<P::ScalarField>, L>,
    pub relation_parameters: RelationParameters<P::ScalarField>,
    pub alphas: Vec<L::Alpha<P::ScalarField>>,
    pub gate_challenges: Vec<P::ScalarField>,
}

pub(crate) struct VerifierMemory<P: Pairing, L: PlainProverFlavour> {
    pub(crate) verifier_commitments: VerifierCommitments<P::G1Affine, L>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField>,
    pub(crate) alphas: Vec<L::Alpha<P::ScalarField>>,
    pub(crate) gate_challenges: Vec<P::ScalarField>,
    pub(crate) claimed_evaluations: ClaimedEvaluations<P::ScalarField, L>,
}

pub(crate) type ProverUnivariates<F, L> =
    AllEntities<<L as PlainProverFlavour>::ProverUnivariate<F>, L>;
pub(crate) type ProverUnivariatesSized<F, L, const SIZE: usize> =
    AllEntities<Univariate<F, SIZE>, L>;
pub(crate) type PartiallyEvaluatePolys<F, L> = AllEntities<Vec<F>, L>;
pub(crate) type ClaimedEvaluations<F, L> = AllEntities<F, L>;
pub(crate) type VerifierCommitments<P, L> = AllEntities<P, L>;

 #[derive(Default, PartialEq, Debug)]
pub struct RelationParameters<T> {
    pub eta_1: T,
    pub eta_2: T,
    pub eta_3: T,
    pub beta: T,
    pub gamma: T,
    pub public_input_delta: T,
    pub lookup_grand_product_delta: T,
}

impl<T: PartialEq> RelationParameters<T> {
    pub fn get_params_as_mut(&mut self) -> Vec<&mut T> {
        vec![
            &mut self.eta_1,
            &mut self.eta_2,
            &mut self.eta_3,
            &mut self.beta,
            &mut self.gamma,
            &mut self.public_input_delta,
            &mut self.lookup_grand_product_delta,
        ]
    }
    
    pub fn get_params(&self) -> Vec<&T> {
        vec![
            &self.eta_1,
            &self.eta_2,
            &self.eta_3,
            &self.beta,
            &self.gamma,
            &self.public_input_delta,
            &self.lookup_grand_product_delta,
        ]
    }
}

pub struct GateSeparatorPolynomial<F: PrimeField> {
    pub betas: Vec<F>,
    pub beta_products: Vec<F>,
    pub partial_evaluation_result: F,
    pub current_element_idx: usize,
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
}

impl<P: Pairing, L: PlainProverFlavour> ProverMemory<P, L> {
    pub fn from_memory_and_polynomials(
        prover_memory: crate::oink::types::ProverMemory<P, L>,
        polynomials: Polynomials<P::ScalarField, L>,
    ) -> Self {
        let relation_parameters = RelationParameters {
            eta_1: prover_memory.challenges.eta_1,
            eta_2: prover_memory.challenges.eta_2,
            eta_3: prover_memory.challenges.eta_3,
            beta: prover_memory.challenges.beta,
            gamma: prover_memory.challenges.gamma,
            public_input_delta: prover_memory.public_input_delta,
            // TODO TACEO: How to initialize this?
            lookup_grand_product_delta: Default::default(),
        };

        let alphas = prover_memory.challenges.alphas;
        let gate_challenges = Default::default();

        let mut memory = AllEntities::<Vec<P::ScalarField>, L>::default();

        // TACEO TODO Barretenberg uses the same memory for the shifted polynomials as for the non-shifted ones

        // Missing lookups
        *memory.witness.lookup_inverses_mut() = prover_memory.lookup_inverses.into_vec();
        *memory.witness.lookup_read_counts_mut() =
            polynomials.witness.lookup_read_counts().as_ref().to_vec();
        *memory.witness.lookup_read_tags_mut() =
            polynomials.witness.lookup_read_tags().as_ref().to_vec();
        if L::FLAVOUR == Flavour::Mega {
            for (des, src) in izip!(
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_ECC_OP_WIRE_1.expect("ECC_OP_WIRE_1 is not set")),
                polynomials
                    .witness
                    .iter()
                    .skip(L::ECC_OP_WIRE_1.expect("ECC_OP_WIRE_1 is not set"))
                    .take(7)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.calldata_inverses_mut() = prover_memory.calldata_inverses.into_vec();

            for (des, src) in izip!(
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_SECONDARY_CALLDATA.expect("SECONDARY_CALLDATA is not set")),
                polynomials
                    .witness
                    .iter()
                    .skip(L::SECONDARY_CALLDATA.expect("SECONDARY_CALLDATA is not set"))
                    .take(3)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.secondary_calldata_inverses_mut() =
                prover_memory.secondary_calldata_inverses.into_vec();

            for (des, src) in izip!(
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_RETURN_DATA.expect("RETURN_DATA is not set")),
                polynomials
                    .witness
                    .iter()
                    .skip(L::RETURN_DATA.expect("RETURN_DATA is not set"))
                    .take(3)
            ) {
                *des = src.as_ref().to_vec();
            }
            *memory.witness.return_data_inverses_mut() =
                prover_memory.return_data_inverses.into_vec();
        }

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
            let poly: Polynomial<P::ScalarField> = src;
            *des = poly.into_vec();
        }

        Self {
            polys: memory,
            relation_parameters,
            alphas,
            gate_challenges,
        }
    }
}

impl<P: Pairing, L: PlainProverFlavour> VerifierMemory<P, L> {
    #[expect(clippy::field_reassign_with_default)]
    pub(crate) fn from_memory_and_key(
        verifier_memory: crate::oink::types::VerifierMemory<P, L>,
        vk: &VerifyingKey<P, L>,
    ) -> Self {
        let relation_parameters = RelationParameters {
            eta_1: verifier_memory.challenges.eta_1,
            eta_2: verifier_memory.challenges.eta_2,
            eta_3: verifier_memory.challenges.eta_3,
            beta: verifier_memory.challenges.beta,
            gamma: verifier_memory.challenges.gamma,
            public_input_delta: verifier_memory.public_input_delta,
            // TODO TACEO: How to initialize this?
            lookup_grand_product_delta: Default::default(),
        };
        let alphas = verifier_memory.challenges.alphas;
        let gate_challenges = Default::default();

        let mut memory = AllEntities::<P::G1Affine, _>::default();
        memory.witness = verifier_memory.witness_commitments;
        memory.precomputed = vk.commitments.clone();

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
