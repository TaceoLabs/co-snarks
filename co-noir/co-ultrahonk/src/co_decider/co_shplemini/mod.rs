pub(crate) mod prover;
pub(crate) mod types;
use ark_ec::pairing::Pairing;

use crate::mpc::NoirUltraHonkProver;

use super::polynomial::SharedPolynomial;
pub(crate) struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) polynomial: SharedPolynomial<T, P>,
    pub(crate) opening_pair: OpeningPair<T, P>,
    pub(crate) gemini_fold: bool,
}

pub(crate) struct OpeningPair<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) evaluation: T::ArithmeticShare,
}
