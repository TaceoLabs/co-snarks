pub(crate) mod proving_key;
pub(crate) mod types;

use ark_ec::pairing::Pairing;
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, ShamirAcvmSolver};
use co_builder::prelude::GenericUltraCircuitBuilder;

pub type PlainCoBuilder<P> =
    GenericUltraCircuitBuilder<P, PlainAcvmSolver<<P as Pairing>::ScalarField>>;
pub type Rep3CoBuilder<P, N> =
    GenericUltraCircuitBuilder<P, Rep3AcvmSolver<<P as Pairing>::ScalarField, N>>;
pub type ShamirCoBuilder<P, N> =
    GenericUltraCircuitBuilder<P, ShamirAcvmSolver<<P as Pairing>::ScalarField, N>>;
