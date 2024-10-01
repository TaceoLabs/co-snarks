pub(crate) mod co_decider;
pub(crate) mod co_oink;
pub(crate) mod parse;
pub mod prelude;
pub(crate) mod prover;
pub(crate) mod types;

use ark_ec::pairing::Pairing;
use mpc_core::{
    protocols::plain::PlainDriver,
    traits::{EcMpcProtocol, MSMProvider, PrimeFieldMpcProtocol},
};
use parse::builder_variable::SharedBuilderVariable;
use ultrahonk::prelude::ProverCrs;

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

pub(crate) const NUM_ALPHAS: usize = co_decider::relations::NUM_SUBRELATIONS - 1;
// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub(crate) const N_MAX: usize = 1 << 25;

// TODO do not forget to remove this
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;
pub(crate) type FieldShare<T, P> =
    <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
pub(crate) type PointShare<T, C> = <T as EcMpcProtocol<C>>::PointShare;

pub(crate) struct CoUtils {}

impl CoUtils {
    pub(crate) fn commit<T, P: Pairing>(
        driver: &mut T,
        poly: &[FieldShare<T, P>],
        crs: &ProverCrs<P>,
    ) -> PointShare<T, P::G1>
    where
        T: MSMProvider<P::G1>,
    {
        let len = poly.len();
        let poly_vec = FieldShareVec::<T, P>::from(poly.to_vec());
        MSMProvider::msm_public_points(driver, &crs.monomials[..len], &poly_vec)
    }

    pub(crate) fn batch_invert<T, P: Pairing>(
        driver: &mut T,
        poly: &mut [FieldShare<T, P>],
    ) -> std::io::Result<()>
    where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        driver.inv_many_in_place(poly)
    }
}
