#![warn(clippy::iter_over_hash_type)]

pub(crate) mod co_decider;
pub(crate) mod co_oink;
pub(crate) mod key;
pub(crate) mod mpc;
pub mod prelude;
pub(crate) mod prover;
pub(crate) mod types;
pub(crate) mod types_batch;

use ark_ec::pairing::Pairing;
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, ShamirAcvmSolver};
use co_builder::prelude::GenericUltraCircuitBuilder;
use co_builder::prelude::ProverCrs;
use mpc::NoirUltraHonkProver;
use mpc_net::Network;

pub type PlainCoBuilder<P> =
    GenericUltraCircuitBuilder<P, PlainAcvmSolver<<P as Pairing>::ScalarField>>;
pub type Rep3CoBuilder<'a, P, N> =
    GenericUltraCircuitBuilder<P, Rep3AcvmSolver<'a, <P as Pairing>::ScalarField, N>>;
pub type ShamirCoBuilder<'a, P, N> =
    GenericUltraCircuitBuilder<P, ShamirAcvmSolver<'a, <P as Pairing>::ScalarField, N>>;

pub(crate) const NUM_ALPHAS: usize = ultrahonk::NUM_ALPHAS;
// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = ultrahonk::CONST_PROOF_SIZE_LOG_N;

pub(crate) struct CoUtils {}

impl CoUtils {
    pub(crate) fn commit<T: NoirUltraHonkProver<P>, P: Pairing>(
        poly: &[T::ArithmeticShare],
        crs: &ProverCrs<P>,
    ) -> T::PointShare {
        Self::msm::<T, P>(poly, &crs.monomials)
    }

    pub(crate) fn msm<T: NoirUltraHonkProver<P>, P: Pairing>(
        poly: &[T::ArithmeticShare],
        crs: &[P::G1Affine],
    ) -> T::PointShare {
        let len = poly.len();
        T::msm_public_points(&crs[..len], poly)
    }

    pub(crate) fn batch_invert<T: NoirUltraHonkProver<P>, P: Pairing, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inv_many_in_place(poly, net, state)
    }

    pub(crate) fn batch_invert_leaking_zeros<T: NoirUltraHonkProver<P>, P: Pairing, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inv_many_in_place_leaking_zeros(poly, net, state)
    }
}
