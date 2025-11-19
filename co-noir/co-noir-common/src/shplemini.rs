use crate::polynomials::polynomial::Polynomial;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

pub struct ShpleminiVerifierOpeningClaim<P: CurveGroup> {
    pub challenge: P::ScalarField,
    pub scalars: Vec<P::ScalarField>,
    pub commitments: Vec<P::Affine>,
}
#[derive(Clone, Default)]
pub struct ShpleminiOpeningClaim<F: PrimeField> {
    pub polynomial: Polynomial<F>,
    pub opening_pair: OpeningPair<F>,
    pub gemini_fold: bool,
}
#[derive(Clone, Default)]
pub struct OpeningPair<F: PrimeField> {
    pub challenge: F,
    pub evaluation: F,
}
