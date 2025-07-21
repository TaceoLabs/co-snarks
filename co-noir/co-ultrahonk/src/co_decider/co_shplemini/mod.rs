pub(crate) mod co_shplemini_prover;
pub(crate) mod types;
use crate::mpc::NoirUltraHonkProver;
use ark_ec::CurveGroup;

use super::polynomial::SharedPolynomial;
pub struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub polynomial: SharedPolynomial<T, P>,
    pub opening_pair: OpeningPair<T, P>,
    pub gemini_fold: bool,
}

pub struct OpeningPair<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub challenge: P::ScalarField,
    pub evaluation: T::ArithmeticShare,
}
