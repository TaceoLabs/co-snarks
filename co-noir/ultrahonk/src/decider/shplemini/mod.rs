pub(crate) mod shplemini_prover;
pub(crate) mod shplemini_verifier;
pub(crate) mod types;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::prelude::Polynomial;

pub(crate) struct ShpleminiVerifierOpeningClaim<P: CurveGroup> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) scalars: Vec<P::ScalarField>,
    pub(crate) commitments: Vec<P::Affine>,
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
