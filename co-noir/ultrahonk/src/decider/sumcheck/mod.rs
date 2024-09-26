pub(crate) mod prover;
pub(crate) mod sumcheck_round;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) claimed_evaluations: ClaimedEvaluations<F>,
    pub(crate) challenges: Vec<F>,
}
