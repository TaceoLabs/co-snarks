use std::fmt::Debug;

pub(crate) mod plain;
// pub(crate) mod rep3;
// pub(crate) mod shamir;

use icicle_core::{
    curve::{Affine, Curve},
    msm::MSM,
    ntt::NTT,
    traits::{Arithmetic, FieldImpl},
    vec_ops::VecOps,
};
use icicle_runtime::{
    memory::{DeviceSlice, DeviceVec},
    stream::IcicleStream,
};
use mpc_core::MpcState;
use mpc_net::Network;
pub use plain::PlainGroth16Driver;

use crate::bridges::ArkIcicleBridge;
// pub use rep3::Rep3Groth16Driver;
// pub use shamir::ShamirGroth16Driver;

/// This trait represents the operations used during Groth16 proof generation
pub trait CircomGroth16Prover<F: FieldImpl<Config: VecOps<F> + NTT<F, F>> + Arithmetic>:
    Send + Sized
{
    /// The arithmetic share type
    type ArithmeticShare;
    type DeviceShares;
    type DevicePointShares<C: Curve<ScalarField = F>>;

    /// Internal state of used MPC protocol
    type State: MpcState + Send;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &DeviceSlice<F>,
    ) -> Self::DeviceShares;

    /// Performs element-wise multiplication of two vectors of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// You must *NOT* perform additional non-linear operations on the result of this function.
    fn local_mul_vec(
        a: &Self::DeviceShares,
        b: &Self::DeviceShares,
        state: &mut Self::State,
        stream: &IcicleStream,
    ) -> DeviceVec<F>;

    /// Performs multiplication of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// You must *NOT* perform additional non-linear operations on the result of this function.
    fn local_mul(
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        state: &mut Self::State,
    ) -> F;

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut Self::DeviceShares,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    );

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const_hs(
        coeffs: &mut DeviceVec<F>,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    );

    /// Converts a shared value to a half shared value. Local interaction only.
    fn to_half_share(a: &Self::ArithmeticShare) -> F;

    /// Converts shared values to half shared values. Local interaction only.
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F>;

    /// Add a public point B in place to the shared point A
    fn add_assign_points_public_hs<C: Curve<ScalarField = F>>(
        id: <Self::State as MpcState>::PartyID,
        a: &mut Affine<C>,
        b: &Affine<C>,
    );

    /// Perform msm between `points` and `scalars`
    fn msm_public_points_hs<C: Curve<ScalarField = F> + MSM<C>>(
        points: &DeviceSlice<Affine<C>>,
        scalars: &DeviceSlice<F>,
        stream: &IcicleStream,
    ) -> Affine<C>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul<N: Network, C: Curve<ScalarField = F>>(
        a: &Affine<C>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Affine<C>>;

    fn fft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream);

    fn ifft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream);

    fn fft_in_place_hs(input: &mut DeviceVec<F>, stream: &IcicleStream);

    fn ifft_in_place_hs(input: &mut DeviceVec<F>, stream: &IcicleStream);

    fn copy_to_device_shares(
        src: &Self::DeviceShares,
        dst: &mut Self::DeviceShares,
        start: usize,
        end: usize,
    );

    // ICICLE <-> ARK functions

    /// Generate a random arithmetic share
    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_half_point<
        N: Network,
        C: Curve<ScalarField = F>,
        B: ArkIcicleBridge<IcicleScalarField = F>,
    >(
        a: Affine<C>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Affine<C>>;
}
