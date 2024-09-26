pub(crate) mod builder_variable;
pub(crate) mod proving_key;

use ark_ec::pairing::Pairing;
use builder_variable::SharedBuilderVariable;
use mpc_core::protocols::{plain::PlainDriver, rep3::Rep3Protocol};
use ultrahonk::prelude::GenericUltraCircuitBuilder;

pub type CoUltraCircuitBuilder<T, P> = GenericUltraCircuitBuilder<P, SharedBuilderVariable<T, P>>;

pub type PlainCoBuilder<P> = CoUltraCircuitBuilder<PlainDriver<<P as Pairing>::ScalarField>, P>;
pub type Rep3CoBuilder<P, N> =
    CoUltraCircuitBuilder<Rep3Protocol<<P as Pairing>::ScalarField, N>, P>;
