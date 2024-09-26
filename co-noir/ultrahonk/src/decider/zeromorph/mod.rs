pub(crate) mod prover;
pub(crate) mod types;

use super::polynomial::Polynomial;
use ark_ff::PrimeField;

pub(crate) struct ZeroMorphOpeningClaim<F: PrimeField> {
    pub(crate) polynomial: Polynomial<F>,
    pub(crate) opening_pair: OpeningPair<F>,
}

pub(crate) struct OpeningPair<F: PrimeField> {
    pub(crate) challenge: F,
    pub(crate) evaluation: F,
}
