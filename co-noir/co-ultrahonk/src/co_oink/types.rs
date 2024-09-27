use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use mpc_core::traits::PrimeFieldMpcProtocol;
use ultrahonk::prelude::Polynomial;

use crate::NUM_ALPHAS;

pub(crate) struct ProverMemory<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) w_4: Polynomial<T::FieldShare>,    // column 3
    pub(crate) z_perm: Polynomial<T::FieldShare>, // column 4
    pub(crate) lookup_inverses: Polynomial<T::FieldShare>, // column 5
    pub(crate) public_input_delta: P::ScalarField,
    pub(crate) challenges: Challenges<P::ScalarField>,
}

pub(crate) struct Challenges<F: PrimeField> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) alphas: [F; NUM_ALPHAS],
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

impl<T, P: Pairing> Default for ProverMemory<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
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
