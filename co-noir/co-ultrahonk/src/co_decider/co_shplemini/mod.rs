pub(crate) mod prover;
pub(crate) mod types;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use crate::mpc::NoirUltraHonkProver;

use super::polynomial::SharedPolynomial;
pub(crate) struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) polynomial: SharedPolynomial<T, P>,
    pub(crate) opening_pair: ShpleminiOpeningPair<T, P>,
}

pub(crate) struct ShpleminiOpeningPair<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) evaluation: T::ArithmeticShare,
}
