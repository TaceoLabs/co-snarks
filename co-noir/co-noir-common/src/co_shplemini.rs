use ark_ec::CurveGroup;

use crate::{mpc::NoirUltraHonkProver, polynomials::shared_polynomial::SharedPolynomial};

#[derive(Clone)]
pub struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub polynomial: SharedPolynomial<T, P>,
    pub opening_pair: OpeningPair<T, P>,
    pub gemini_fold: bool,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for ShpleminiOpeningClaim<T, P> {
    fn default() -> Self {
        Self {
            polynomial: SharedPolynomial::default(),
            opening_pair: OpeningPair::default(),
            gemini_fold: false,
        }
    }
}

#[derive(Clone)]
pub struct OpeningPair<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub challenge: P::ScalarField,
    pub evaluation: T::ArithmeticShare,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for OpeningPair<T, P> {
    fn default() -> Self {
        Self {
            challenge: P::ScalarField::default(),
            evaluation: T::ArithmeticShare::default(),
        }
    }
}
