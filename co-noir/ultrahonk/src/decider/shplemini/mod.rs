// pub(crate) mod prover;
pub(crate) mod gemini_verifier;
pub(crate) mod prover;
pub(crate) mod types;
pub(crate) mod verifier;
use super::polynomial::Polynomial;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub(crate) struct ShpleminiVerifierOpeningClaim<P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) scalars: Vec<P::ScalarField>,
    pub(crate) commitments: Vec<P::G1Affine>,
}
