pub(crate) mod prover;
pub(crate) mod round_prover;
pub(crate) mod round_verifier;
pub(crate) mod verifier;
pub(crate) mod zk_data;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) _claimed_evaluations: ClaimedEvaluations<F>,
    pub(crate) challenges: Vec<F>,
    pub(crate) claimed_libra_evaluation: Option<F>,
}

pub struct SumcheckVerifierOutput<F: PrimeField> {
    pub multivariate_challenge: Vec<F>,
    pub verified: bool,
    pub claimed_libra_evaluation: Option<F>,
}
