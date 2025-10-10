pub(crate) mod co_sumcheck_prover;
pub(crate) mod co_sumcheck_round;
pub(crate) mod zk_data;

use co_noir_common::polynomials::shared_polynomial::SharedPolynomial;
use co_noir_common::{
    honk_curve::HonkCurve, honk_proof::TranscriptFieldType, mpc::NoirUltraHonkProver,
};
pub struct SumcheckOutput<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> {
    pub challenges: Vec<P::ScalarField>,
    pub claimed_libra_evaluation: Option<P::ScalarField>,
    pub round_univariates: Option<Vec<SharedPolynomial<T, P>>>,
    pub round_univariate_evaluations: Option<Vec<[T::ArithmeticShare; 3]>>,
}
