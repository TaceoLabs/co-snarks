use std::{
    fmt::Debug,
    ops::{AddAssign, MulAssign, SubAssign},
};

use ark_ec::{CurveGroup, pairing::Pairing};
use ark_poly::domain::DomainCoeff;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

use mpc_core::MpcState;
use mpc_net::Network;
pub use plain::PlainGroth16Driver;
pub use rep3::Rep3Groth16Driver;
pub use shamir::ShamirGroth16Driver;

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

    /// The point half share type
    type PointHalfShare<C>: Debug + Send + Sync + 'static + AddAssign + SubAssign
    where
        C: CurveGroup;

    /// Internal state of used MPC protocol
    type State: MpcState + Send;

    /// Generate a random arithmetic share
    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare>;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        id: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint_half_share(
        id: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticHalfShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare>;

    /// Performs element-wise multiplication of two vectors of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// You must *NOT* perform additional non-linear operations on the result of this function.
    fn local_mul_many(
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
        state: &mut Self::State,
    ) -> Vec<Self::ArithmeticHalfShare>;

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    );

    /// Converts a shared value to a half shared value. Local interaction only.
    fn to_half_share(a: Self::ArithmeticShare) -> Self::ArithmeticHalfShare;

    /// Perform msm between `points` and `scalars`
    fn msm_public_points_hs<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticHalfShare],
    ) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point_hs<C>(
        a: &C,
        b: Self::ArithmeticHalfShare,
    ) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Add a public point B in place to the shared point A
    fn add_assign_points_public_hs<C: CurveGroup>(
        id: <Self::State as MpcState>::PartyID,
        a: &mut Self::PointHalfShare<C>,
        b: &C,
    );

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_half_point<N: Network, C>(
        a: Self::PointHalfShare<C>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul<N: Network>(
        a: &Self::PointHalfShare<P::G1>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::PointHalfShare<P::G1>>;
}
