pub mod prover;
pub mod sumcheck_round;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub struct SumcheckOutput<F: PrimeField> {
    pub(crate) claimed_evaluations: ClaimedEvaluations<F>,
    pub(crate) challenges: Vec<F>,
}
