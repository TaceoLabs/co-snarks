use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_builder::prelude::Polynomial;

pub struct ShpleminiVerifierOpeningClaim<P: Pairing> {
    pub challenge: P::ScalarField,
    pub scalars: Vec<P::ScalarField>,
    pub commitments: Vec<P::G1Affine>,
}
#[derive(Clone)]
pub struct ShpleminiOpeningClaim<F: PrimeField> {
    pub polynomial: Polynomial<F>,
    pub opening_pair: OpeningPair<F>,
    pub gemini_fold: bool,
}
#[derive(Clone)]
pub struct OpeningPair<F: PrimeField> {
    pub challenge: F,
    pub evaluation: F,
}
