// Zeromorph is based on the one in aztec-package-v0.53.0, but is not used anymore at this point and replaced by Shplemini. We still keep it around for now.

#![allow(dead_code)]
pub(crate) mod prover;
pub(crate) mod types;

use crate::mpc::NoirUltraHonkProver;

use super::polynomial::SharedPolynomial;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub(crate) struct ZeroMorphOpeningClaim<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) polynomial: SharedPolynomial<T, P>,
    pub(crate) opening_pair: OpeningPair<P::ScalarField>,
}

pub(crate) struct OpeningPair<F: PrimeField> {
    pub(crate) challenge: F,
    pub(crate) evaluation: F,
}
