use ark_ec::CurveGroup;

use crate::{mpc::NoirUltraHonkProver, shared_polynomial::SharedPolynomial};

#[derive(Default, Clone)]
pub struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub polynomial: SharedPolynomial<T, P>,
    pub opening_pair: OpeningPair<T, P>,
    pub gemini_fold: bool,
}

#[derive(Default, Clone)]
pub struct OpeningPair<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub challenge: P::ScalarField,
    pub evaluation: T::ArithmeticShare,
}
