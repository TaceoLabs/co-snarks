#![warn(clippy::iter_over_hash_type)]

pub mod co_decider;
pub mod co_oink;
pub(crate) mod co_ultra_prover;
pub mod prelude;
pub mod types;
pub mod types_batch;

// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = ultrahonk::CONST_PROOF_SIZE_LOG_N;
