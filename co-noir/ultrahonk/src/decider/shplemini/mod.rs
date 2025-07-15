pub(crate) mod shplemini_prover;
pub(crate) mod shplemini_verifier;
pub(crate) mod types;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_builder::prelude::Polynomial;

pub(crate) struct ShpleminiVerifierOpeningClaim<P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) scalars: Vec<P::ScalarField>,
    pub(crate) commitments: Vec<P::G1Affine>,
}
#[derive(Clone)]
pub(crate) struct ShpleminiOpeningClaim<F: PrimeField> {
    pub(crate) polynomial: Polynomial<F>,
    pub(crate) opening_pair: OpeningPair<F>,
    pub(crate) gemini_fold: bool,
}
#[derive(Clone)]
pub(crate) struct OpeningPair<F: PrimeField> {
    pub(crate) challenge: F,
    pub(crate) evaluation: F,
}
