use crate::{decider::polynomial::Polynomial, NUM_ALPHAS};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct ProverMemory<P: Pairing> {
    pub w_4: Polynomial<P::ScalarField>,             // column 3
    pub z_perm: Polynomial<P::ScalarField>,          // column 4
    pub lookup_inverses: Polynomial<P::ScalarField>, // column 5
    pub public_input_delta: P::ScalarField,
    pub challenges: Challenges<P::ScalarField>,
}

pub struct Challenges<F: PrimeField> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub alphas: [F; NUM_ALPHAS],
}

impl<F: PrimeField> Default for Challenges<F> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            alphas: [Default::default(); NUM_ALPHAS],
        }
    }
}

impl<P: Pairing> Default for ProverMemory<P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            z_perm: Default::default(),
            lookup_inverses: Default::default(),
            public_input_delta: Default::default(),
            challenges: Default::default(),
        }
    }
}
