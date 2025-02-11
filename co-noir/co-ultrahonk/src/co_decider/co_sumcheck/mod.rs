pub(crate) mod prover;
pub(crate) mod round;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) _claimed_evaluations: ClaimedEvaluations<F>,
    pub(crate) challenges: Vec<F>,
}
