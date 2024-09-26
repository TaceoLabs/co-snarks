pub(crate) mod parse;
pub(crate) mod types;

use ark_ec::pairing::Pairing;
use mpc_core::protocols::{plain::PlainDriver, rep3::Rep3Protocol};

pub use parse::{builder_variable::SharedBuilderVariable, CoUltraCircuitBuilder};
pub type PlainCoBuilder<P> = CoUltraCircuitBuilder<PlainDriver<<P as Pairing>::ScalarField>, P>;
pub type Rep3CoBuilder<P, N> =
    CoUltraCircuitBuilder<Rep3Protocol<<P as Pairing>::ScalarField, N>, P>;

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
