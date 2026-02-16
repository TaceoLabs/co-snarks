use std::{
    fmt::Debug,
};


pub(crate) mod plain;
pub(crate) mod rep3;
// pub(crate) mod shamir;

use icicle_core::{affine::Affine, ecntt::Projective, field::Field, msm::MSM, ntt::ntt_inplace, ntt::{NTTConfig, NTT,  ntt}, pairing::Pairing, vec_ops::VecOps};
use icicle_runtime::{Device, memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice}};
use mpc_core::MpcState;
use mpc_net::Network;
pub use plain::PlainGroth16Driver;

use crate::{ bridges::ArkIcicleBridge, gpu_utils::DeviceMatrix};
pub use rep3::Rep3Groth16Driver;
// pub use shamir::ShamirGroth16Driver;

/// This trait represents the operations used during Groth16 proof generation
pub trait CircomGroth16Prover<F: Field + VecOps<F> + NTT<F, F>>: Send + Sized {

    /// The arithmetic share type
    type ArithmeticShare;
    type DeviceShares;
    type DevicePointShares<C: Projective>;

    /// Internal state of used MPC protocol
    type State: MpcState + Send;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraints(
        id: <Self::State as MpcState>::PartyID,
        domain_size: usize,
        matrix: &DeviceMatrix<F>,
        public_inputs: &DeviceSlice<F>,
        private_witness: &Self::DeviceShares,
    ) -> Self::DeviceShares;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        id: <Self::State as MpcState>::PartyID,
        active_values: &DeviceSlice<F>,
        active_public_inputs: &DeviceSlice<F>,
        active_private_witness: &Self::DeviceShares,
    ) -> Self::ArithmeticShare;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint_half_share(
        id: <Self::State as MpcState>::PartyID,
        active_values: &DeviceSlice<F>,
        active_public_inputs: &DeviceSlice<F>,
        active_private_witness: &Self::DeviceShares,
    ) -> F;

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
    );

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const_hs(
        coeffs: &mut DeviceVec<F>,
        roots: &DeviceSlice<F>,
    );

    /// Converts a shared value to a half shared value. Local interaction only.
    fn to_half_share(a: &Self::ArithmeticShare) -> F;

    /// Converts shared values to half shared values. Local interaction only.
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F>;

    /// Add a public point B in place to the shared point A
    fn add_assign_points_public_hs<P: Projective<ScalarField = F>>(
        id: <Self::State as MpcState>::PartyID,
        a: &mut P::Affine,
        b: &P::Affine,
    );

    /// Perform msm between `points` and `scalars`
    fn msm_public_points_hs<P: Projective<ScalarField = F> +  MSM<P>>(
        points: &DeviceSlice<P::Affine>,
        scalars: &DeviceSlice<F>,
    ) -> P::Affine;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul<N: Network, P: Projective<ScalarField = F>>(
        a: &P::Affine,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<P::Affine>;

    fn fft_in_place(input: &mut Self::DeviceShares);

    fn ifft_in_place(input: &mut Self::DeviceShares);

    fn fft_in_place_hs(input: &mut DeviceVec<F>);

    fn ifft_in_place_hs(input: &mut DeviceVec<F>);

    fn copy_to_device_shares(src: &Self::DeviceShares, dst: &mut Self::DeviceShares, start: usize, end: usize);

    // ICICLE <-> ARK functions

    /// Generate a random arithmetic share
    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_half_point<N: Network, P: Projective<ScalarField = F>, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: P::Affine,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<P::Affine>;
}
