pub(crate) mod parse;
pub mod prelude;
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
