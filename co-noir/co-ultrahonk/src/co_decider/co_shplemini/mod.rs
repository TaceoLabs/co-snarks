pub(crate) mod co_shplemini_prover;
pub(crate) mod types;
use crate::mpc::NoirUltraHonkProver;
use ark_ec::CurveGroup;

use super::polynomial::SharedPolynomial;
pub(crate) struct ShpleminiOpeningClaim<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) polynomial: SharedPolynomial<T, P>,
    pub(crate) opening_pair: OpeningPair<T, P>,
    pub(crate) gemini_fold: bool,
}

pub(crate) struct OpeningPair<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) evaluation: T::ArithmeticShare,
}
