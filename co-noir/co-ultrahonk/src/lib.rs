pub(crate) mod decider;
pub(crate) mod oink;
pub(crate) mod parse;
pub mod prelude;
pub(crate) mod prover;
pub(crate) mod types;

use ark_ec::pairing::Pairing;
use mpc_core::protocols::plain::PlainDriver;
use parse::builder_variable::SharedBuilderVariable;

impl<P: Pairing> SharedBuilderVariable<PlainDriver<P::ScalarField>, P> {
    pub fn promote_public_witness_vector(
        witness: Vec<P::ScalarField>,
    ) -> Vec<SharedBuilderVariable<PlainDriver<P::ScalarField>, P>> {
        witness
            .into_iter()
            .map(SharedBuilderVariable::Public)
            .collect()
    }
}

pub(crate) const NUM_ALPHAS: usize = decider::relations::NUM_SUBRELATIONS - 1;
// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub(crate) const N_MAX: usize = 1 << 25;
