// pub(crate) mod prover;
pub(crate) mod gemini_verifier;
pub(crate) mod prover;
pub(crate) mod types;
pub(crate) mod verifier;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use crate::prelude::Polynomial;
pub(crate) struct ShpleminiVerifierOpeningClaim<P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) scalars: Vec<P::ScalarField>,
    pub(crate) commitments: Vec<P::G1Affine>,
}
pub(crate) struct ShpleminiOpeningClaim<F: PrimeField> {
    pub(crate) polynomial: Polynomial<F>,
    pub(crate) opening_pair: OpeningPair<F>,
}

pub(crate) struct OpeningPair<F: PrimeField> {
    pub(crate) challenge: F,
    pub(crate) evaluation: F,
}

#[allow(dead_code)]
pub(crate) struct ZeroMorphVerifierOpeningClaim<P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) evaluation: P::ScalarField,
    pub(crate) commitment: P::G1,
}
