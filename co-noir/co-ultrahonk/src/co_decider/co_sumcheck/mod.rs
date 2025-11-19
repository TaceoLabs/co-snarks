pub(crate) mod co_sumcheck_prover;
pub(crate) mod co_sumcheck_round;
pub(crate) mod zk_data;

use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) challenges: Vec<F>,
    pub(crate) claimed_libra_evaluation: Option<F>,
}
