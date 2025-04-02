use core::fmt;
use std::{
    fmt::Debug,
    ops::{AddAssign, MulAssign, SubAssign},
};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_poly::domain::DomainCoeff;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

pub use plain::PlainGroth16Driver;
pub use rep3::Rep3Groth16Driver;
pub use shamir::ShamirGroth16Driver;

type IoResult<T> = std::io::Result<T>;

/// This trait represents the operations used during Groth16 proof generation
pub trait CircomGroth16Prover<P: Pairing>: Send + Sized {
    /// The arithmetic share type
    type ArithmeticShare: CanonicalSerialize
        + CanonicalDeserialize
        + Copy
        + Clone
        + Default
        + Send
        + Debug
        + DomainCoeff<P::ScalarField>
        + 'static;

    /// The arithmetic half share type. For Rep3 this is an unreplicated additive share. For Shamir this is a degree-2t sharing.
    type ArithmeticHalfShare: CanonicalSerialize
        + CanonicalDeserialize
        + Copy
        + Clone
        + Default
        + Send
        + Debug
        + DomainCoeff<P::ScalarField>
        + MulAssign<P::ScalarField>
        + 'static;

    /// The point share type
    type PointShare<C>: Debug + Send + 'static
    where
        C: CurveGroup;

    /// The point half share type
    type PointHalfShare<C>: Debug + Send + 'static + AddAssign + SubAssign
    where
        C: CurveGroup;
    /// The party id type
    type PartyID: Send + Sync + Copy + fmt::Display + 'static;

    /// Generate a random arithemitc share
    fn rand(&mut self) -> IoResult<Self::ArithmeticShare>;

    /// Get the party id
    fn get_party_id(&self) -> Self::PartyID;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint_half_share(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticHalfShare;

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
    ) -> Vec<Self::ArithmeticHalfShare>;

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

    /// Converts a shared value to a half shared value. Local interaction only.
    fn to_half_share(a: Self::ArithmeticShare) -> Self::ArithmeticHalfShare;

    /// Perform msm between `points` and `scalars`
    fn msm_public_points<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Perform msm between `points` and `scalars`
    fn msm_public_points_hs<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticHalfShare],
    ) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point<C>(a: &C, b: Self::ArithmeticShare) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point_hs<C>(
        a: &C,
        b: Self::ArithmeticHalfShare,
    ) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>);

    /// Subtract a shared point B in place from the shared point A: \[A\] -= \[B\]
    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>);

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_points_half_share<C: CurveGroup>(a: Self::PointShare<C>, b: &C) -> C;

    /// Add a public point B in place to the shared point A
    fn add_assign_points_public_hs<C: CurveGroup>(
        id: Self::PartyID,
        a: &mut Self::PointHalfShare<C>,
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
    fn open_two_half_points(
        &mut self,
        a: Self::PointHalfShare<P::G1>,
        b: Self::PointHalfShare<P::G2>,
    ) -> std::io::Result<(P::G1, P::G2)>;

    /// Reconstruct point G_a and perform scalar multiplication of G1_b and r concurrently
    #[expect(clippy::type_complexity)]
    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointHalfShare<P::G1>,
        g1_b: &Self::PointHalfShare<P::G1>,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(P::G1, Self::PointHalfShare<P::G1>)>;
}
