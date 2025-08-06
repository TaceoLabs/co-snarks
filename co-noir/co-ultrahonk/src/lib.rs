#![warn(clippy::iter_over_hash_type)]

pub(crate) mod co_decider;
pub(crate) mod co_oink;
pub(crate) mod co_ultra_prover;
pub mod key;
pub(crate) mod mpc_flavours;
pub(crate) mod mpc_prover_flavour;
pub mod prelude;
pub(crate) mod types;
pub(crate) mod types_batch;

use ark_ec::PrimeGroup;
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, ShamirAcvmSolver};
use co_builder::prelude::GenericUltraCircuitBuilder;

pub type PlainCoBuilder<P> =
    GenericUltraCircuitBuilder<P, PlainAcvmSolver<<P as PrimeGroup>::ScalarField>>;
pub type Rep3CoBuilder<'a, P, N> =
    GenericUltraCircuitBuilder<P, Rep3AcvmSolver<'a, <P as PrimeGroup>::ScalarField, N>>;
pub type ShamirCoBuilder<'a, P, N> =
    GenericUltraCircuitBuilder<P, ShamirAcvmSolver<'a, <P as PrimeGroup>::ScalarField, N>>;

// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = ultrahonk::CONST_PROOF_SIZE_LOG_N;
