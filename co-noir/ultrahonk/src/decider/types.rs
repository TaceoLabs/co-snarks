use super::univariate::Univariate;
use crate::{types::AllEntities, NUM_ALPHAS};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct ProverMemory<P: Pairing> {
    pub memory: MemoryElements<Vec<P::ScalarField>>,
    pub relation_parameters: RelationParameters<P::ScalarField>,
}

pub const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
#[derive(Default)]
pub struct ProverUnivariates<F: PrimeField> {
    pub memory: MemoryElements<Univariate<F, MAX_PARTIAL_RELATION_LENGTH>>,
    pub polys: AllEntities<Univariate<F, MAX_PARTIAL_RELATION_LENGTH>>,
}

#[derive(Default)]
pub struct PartiallyEvaluatePolys<F: PrimeField> {
    pub memory: MemoryElements<Vec<F>>,
    pub polys: AllEntities<Vec<F>>,
}

#[derive(Default)]
pub struct ClaimedEvaluations<F: PrimeField> {
    pub memory: MemoryElements<F>,
    pub polys: AllEntities<F>,
}

#[derive(Default)]
pub struct MemoryElements<T> {
    pub elements: [T; 4],
}

pub struct RelationParameters<F: PrimeField> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub public_input_delta: F,
    pub alphas: [F; NUM_ALPHAS],
    pub gate_challenges: Vec<F>,
}

pub struct GateSeparatorPolynomial<F: PrimeField> {
    betas: Vec<F>,
    pub(crate) beta_products: Vec<F>,
    pub(crate) partial_evaluation_result: F,
    current_element_idx: usize,
    pub(crate) periodicity: usize,
}

impl<F: PrimeField> GateSeparatorPolynomial<F> {
    pub fn new(betas: Vec<F>) -> Self {
        let pow_size = 1 << betas.len();
        let current_element_idx = 0;
        let periodicity = 2;
        let partial_evaluation_result = F::ONE;

        let mut beta_products = Vec::with_capacity(pow_size);

        // Barretenberg uses multithreading here
        for i in 0..pow_size {
            let mut res = F::one();
            let mut j = i;
            let mut beta_idx = 0;
            while j > 0 {
                if j & 1 == 1 {
                    res *= betas[beta_idx];
                }
                j >>= 1;
                beta_idx += 1;
            }
            beta_products.push(res);
        }

        Self {
            betas,
            beta_products,
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

impl<P: Pairing> Default for ProverMemory<P> {
    fn default() -> Self {
        Self {
            memory: Default::default(),
            relation_parameters: Default::default(),
        }
    }
}

impl<P: Pairing> From<crate::oink::types::ProverMemory<P>> for ProverMemory<P> {
    fn from(prover_memory: crate::oink::types::ProverMemory<P>) -> Self {
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

        Self {
            memory: Default::default(),
            relation_parameters,
        }
    }
}

impl<F: PrimeField> ProverUnivariates<F> {
    pub fn iter(&self) -> impl Iterator<Item = &Univariate<F, MAX_PARTIAL_RELATION_LENGTH>> {
        self.memory.iter().chain(self.polys.iter())
    }

    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut Univariate<F, MAX_PARTIAL_RELATION_LENGTH>> {
        self.memory.iter_mut().chain(self.polys.iter_mut())
    }
}

impl<F: PrimeField> PartiallyEvaluatePolys<F> {
    pub fn iter(&self) -> impl Iterator<Item = &Vec<F>> {
        self.memory.iter().chain(self.polys.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Vec<F>> {
        self.memory.iter_mut().chain(self.polys.iter_mut())
    }
}

impl<F: PrimeField> ClaimedEvaluations<F> {
    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.memory.iter().chain(self.polys.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut F> {
        self.memory.iter_mut().chain(self.polys.iter_mut())
    }
}

impl<T: Default> MemoryElements<T> {
    const W_4: usize = 0; // column 3
    const Z_PERM: usize = 1; // column 4
    const LOOKUP_INVERSES: usize = 2; // column 5
    const Z_PERM_SHIFT: usize = 3; // TODO this is never calculated? also the permutation relation might always be skipped right now?

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.elements.iter_mut()
    }

    pub fn w_4(&self) -> &T {
        &self.elements[Self::W_4]
    }

    pub fn z_perm(&self) -> &T {
        &self.elements[Self::Z_PERM]
    }

    pub fn lookup_inverses(&self) -> &T {
        &self.elements[Self::LOOKUP_INVERSES]
    }

    pub fn z_perm_shift(&self) -> &T {
        &self.elements[Self::Z_PERM_SHIFT]
    }
}
