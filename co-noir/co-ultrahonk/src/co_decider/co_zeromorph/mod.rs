pub(crate) mod prover;
pub(crate) mod types;

use super::polynomial::SharedPolynomial;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use mpc_core::traits::PrimeFieldMpcProtocol;

pub(crate) struct ZeroMorphOpeningClaim<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) polynomial: SharedPolynomial<T, P>,
    pub(crate) opening_pair: OpeningPair<P::ScalarField>,
}

pub(crate) struct OpeningPair<F: PrimeField> {
    pub(crate) challenge: F,
    pub(crate) evaluation: F,
}
