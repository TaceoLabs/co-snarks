use core::fmt;
use std::{fmt::Debug, marker::PhantomData};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, Zero};
use ark_poly::domain::DomainCoeff;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

use icicle_bn254::curve::ScalarField;
use icicle_core::{curve::Curve, traits::FieldImpl};
use icicle_runtime::{
    memory::{DeviceVec, HostOrDeviceSlice, HostSlice},
    stream::IcicleStream,
};
pub use plain::PlainGroth16Driver;
pub use rep3::Rep3Groth16Driver;
pub use shamir::ShamirGroth16Driver;

pub trait FftHandle<P: Pairing, T> {
    fn join(self) -> T;
}

type IoResult<T> = std::io::Result<T>;

/// This trait represents the operations used during Groth16 proof generation
pub trait CircomGroth16Prover<P: Pairing>: Send + Sized {
    /// The arithemitc share type
    type ArithmeticShare: CanonicalSerialize
        + CanonicalDeserialize
        + Copy
        + Clone
        + Default
        + Send
        + Debug
        + DomainCoeff<P::ScalarField>
        + 'static;
    /// The G1 point share type
    type PointShare<C>: Debug + Send + 'static
    where
        C: CurveGroup;
    /// The party id type
    type PartyID: Send + Sync + Copy + fmt::Display + 'static;

    type FftHandle: FftHandle<P, Vec<Self::ArithmeticShare>>;

    /// Generate a random arithemitc share
    fn rand(&mut self) -> IoResult<Self::ArithmeticShare>;

    /// Get the party id
    fn get_party_id(&self) -> Self::PartyID;

    fn fft(coeffs: Vec<Self::ArithmeticShare>) -> Vec<Self::ArithmeticShare>;
    fn fft_async(coeffs: Vec<Self::ArithmeticShare>) -> Self::FftHandle;
    fn fft_half_share(coeffs: Vec<P::ScalarField>) -> Vec<P::ScalarField>;
    // fn fft_half_share_async(coeffs: Vec<P::ScalarField>) -> FftHandle<P::ScalarField, ScalarField>;
    fn ifft(coeffs: Vec<Self::ArithmeticShare>) -> Vec<Self::ArithmeticShare>;
    fn ifft_async(coeffs: Vec<Self::ArithmeticShare>) -> Self::FftHandle;
    fn ifft_half_share(coeffs: Vec<P::ScalarField>) -> Vec<P::ScalarField>;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare>;

    /// Performs element-wise multiplication of two vectors of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// You must *NOT* perform additional non-linear operations on the result of this function.
    fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> Vec<P::ScalarField>;

    /// Compute the msm of `h` and `h_query` and multiplication `r` * `s`.
    fn mul(
        &mut self,
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare>;

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    );

    /// Perform msm between `points` and `scalars`
    fn msm_public_points<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point<C>(a: &C, b: Self::ArithmeticShare) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>);

    /// Subtract a shared point B in place from the shared point A: \[A\] -= \[B\]
    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>);

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_points_half_share<C: CurveGroup>(a: Self::PointShare<C>, b: &C) -> C;

    /// Add a public point B in place to the shared point A
    fn add_assign_points_public<C: CurveGroup>(
        id: Self::PartyID,
        a: &mut Self::PointShare<C>,
        b: &C,
    );

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_point<C>(&mut self, a: &Self::PointShare<C>) -> IoResult<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul<C>(
        &mut self,
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Reconstructs a shared points: A = Open(\[A\]), B = Open(\[B\]).
    fn open_two_points(
        &mut self,
        a: P::G1,
        b: Self::PointShare<P::G2>,
    ) -> std::io::Result<(P::G1, P::G2)>;

    /// Reconstruct point G_a and perform scalar multiplication of G1_b and r concurrently
    #[expect(clippy::type_complexity)]
    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointShare<P::G1>,
        g1_b: &Self::PointShare<P::G1>,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(P::G1, Self::PointShare<P::G1>)>;
}
