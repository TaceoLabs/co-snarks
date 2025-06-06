pub(crate) mod prover;
pub(crate) mod round;
pub(crate) mod zk_data;

use crate::mpc_prover_flavour::MPCProverFlavour;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField, L: MPCProverFlavour> {
    pub(crate) _claimed_evaluations: ClaimedEvaluations<F, L>,
    pub(crate) challenges: Vec<F>,
    pub(crate) claimed_libra_evaluation: Option<F>,
}
