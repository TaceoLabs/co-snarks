pub(crate) mod plain;
pub(crate) mod rep3;
// pub(crate) mod shamir;

use std::mem::transmute;

use co_groth16::ConstraintMatrices;
use icicle_core::{
    curve::{Affine, Curve},
    ntt::NTT,
    traits::{Arithmetic, FieldImpl, MontgomeryConvertible},
    vec_ops::{VecOps, VecOpsConfig, mul_scalars},
};
use icicle_runtime::{
    memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice},
    stream::IcicleStream,
};
use mpc_core::MpcState;
use mpc_net::Network;

use crate::bridges::ArkIcicleBridge;

pub use plain::PlainGroth16Driver;
pub use rep3::Rep3Groth16Driver;
// pub use shamir::ShamirGroth16Driver;

/// This trait represents the operations used during Groth16 proof generation
pub trait CircomGroth16Prover<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>> + Arithmetic + MontgomeryConvertible,
>: Send + Sized
{
    /// The arithmetic share type
    type ArithmeticShare;

    /// Represents a vector of field shares on the device
    type DeviceShares;

    /// Represents a vector of point shares on the device
    type DevicePointShares<C: Curve<ScalarField = F>>;

    /// Internal state of used MPC protocol
    type State: MpcState + Send;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &DeviceSlice<F>,
    ) -> Self::DeviceShares;

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut Self::DeviceShares,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    );

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    // TODO CESAR: Check if we can avoid alloc
    // TODO CESAR: Remove
    fn distribute_powers_and_mul_by_const_hs(
        coeffs: &mut DeviceVec<F>,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    ) {
        let mut result = DeviceVec::device_malloc_async(coeffs.len(), stream)
            .expect("Failed to allocate device vector");
        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;

        mul_scalars(coeffs, roots, result.as_mut_slice(), &cfg).unwrap();
        *coeffs = result;
    }

    /// Converts a shared value to a half shared value. Local interaction only.
    fn to_half_share(a: &Self::ArithmeticShare) -> F;

    /// Converts shared values to half shared values. Local interaction only.
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F>;

    // TODO CESAR: Remove
    /// Add a public point B in place to the shared point A
    fn add_assign_points_public_hs<C: Curve<ScalarField = F>>(
        _: <Self::State as MpcState>::PartyID,
        a: &mut Affine<C>,
        b: &Affine<C>,
    ) {
        *a = (a.to_projective() + b.to_projective()).into();
    }

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

    fn shares_to_device<
        B: ArkIcicleBridge<IcicleScalarField = F>,
        T: co_groth16::CircomGroth16Prover<B::ArkPairing> + 'static,
    >(
        shares: &Vec<T::ArithmeticShare>,
    ) -> Self::DeviceShares;

    fn evaluate_constraints<
        B: ArkIcicleBridge<IcicleScalarField = F>,
        T: co_groth16::CircomGroth16Prover<B::ArkPairing> + 'static,
    >(
        id: <Self::State as MpcState>::PartyID,
        matrices: &ConstraintMatrices<B::ArkScalarField>,
        public_inputs: &[B::ArkScalarField],
        private_witness: &[T::ArithmeticShare],
        domain_size: usize,
    ) -> (Self::DeviceShares, Self::DeviceShares) {
        let id = unsafe {
            transmute::<&<Self::State as MpcState>::PartyID, &<T::State as MpcState>::PartyID>(&id)
        };

        let eval_a = co_groth16::evaluate_constraint::<B::ArkPairing, T>(
            id.clone(),
            domain_size,
            &matrices.a,
            public_inputs,
            private_witness,
        );

        let eval_b = co_groth16::evaluate_constraint::<B::ArkPairing, T>(
            id.clone(),
            domain_size,
            &matrices.b,
            public_inputs,
            private_witness,
        );

        (
            Self::shares_to_device::<B, T>(&eval_a),
            Self::shares_to_device::<B, T>(&eval_b),
        )
    }

    /// Performs element-wise multiplication of two vectors of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// You must *NOT* perform additional non-linear operations on the result of this function.
    fn local_mul_vec<B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Self::DeviceShares,
        b: &Self::DeviceShares,
        state: &mut Self::State,
        stream: &IcicleStream,
    ) -> DeviceVec<F>;

    fn local_mul<B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        state: &mut Self::State,
    ) -> F;

    /// Generate a random arithmetic share
    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare>;

    /// Reconstructs a shared point in G1: A = Open(\[A\]).
    fn open_half_point_g1<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: Affine<B::IcicleG1>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG1>>;

    /// Reconstructs a shared point in G2: A = Open(\[A\]).
    fn open_half_point_g2<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: Affine<B::IcicleG2>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG2>>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul_g1<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Affine<B::IcicleG1>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG1>>;
}
