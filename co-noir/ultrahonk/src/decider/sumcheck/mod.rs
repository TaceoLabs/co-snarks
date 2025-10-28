pub(crate) mod sumcheck_prover;
pub(crate) mod sumcheck_round_prover;
pub(crate) mod sumcheck_round_verifier;
pub(crate) mod sumcheck_verifier;
pub(crate) mod zk_data;

use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) challenges: Vec<F>,
    pub(crate) claimed_libra_evaluation: Option<F>,
}

pub struct SumcheckVerifierOutput<F: PrimeField> {
    pub multivariate_challenge: Vec<F>,
    pub verified: bool,
    pub claimed_libra_evaluation: Option<F>,
}
