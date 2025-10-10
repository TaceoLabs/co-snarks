pub(crate) mod sumcheck_prover;
pub(crate) mod sumcheck_round_prover;
pub(crate) mod sumcheck_round_verifier;
pub(crate) mod sumcheck_verifier;
pub(crate) mod zk_data;

use crate::plain_prover_flavour::PlainProverFlavour;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;
use co_noir_common::polynomials::polynomial::Polynomial;

pub struct SumcheckOutput<F: PrimeField, L: PlainProverFlavour> {
    pub(crate) _claimed_evaluations: ClaimedEvaluations<F, L>, // TACEO TODO: Is this ever needed?
    pub challenges: Vec<F>,
    pub claimed_libra_evaluation: Option<F>,
    pub round_univariates: Option<Vec<Polynomial<F>>>,
    pub round_univariate_evaluations: Option<Vec<[F; 3]>>,
}

pub struct SumcheckVerifierOutput<F: PrimeField> {
    pub multivariate_challenge: Vec<F>,
    pub verified: bool,
    pub claimed_libra_evaluation: Option<F>,
}
