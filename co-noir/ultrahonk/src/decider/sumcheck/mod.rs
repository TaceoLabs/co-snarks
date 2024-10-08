pub(crate) mod prover;
pub(crate) mod round_prover;
pub(crate) mod round_verifier;
pub(crate) mod verifier;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) claimed_evaluations: ClaimedEvaluations<F>,
    pub(crate) challenges: Vec<F>,
}

pub struct SumcheckVerifierOutput<F: PrimeField> {
    pub multivariate_challenge: Vec<F>,
    pub verified: bool,
}
