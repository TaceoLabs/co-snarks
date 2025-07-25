use ark_ec::pairing::Pairing;

use crate::{mpc::NoirUltraHonkProver, shared_polynomial::SharedPolynomial};

pub struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub polynomial: SharedPolynomial<T, P>,
    pub opening_pair: OpeningPair<T, P>,
    pub gemini_fold: bool,
}

pub struct OpeningPair<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub challenge: P::ScalarField,
    pub evaluation: T::ArithmeticShare,
}
