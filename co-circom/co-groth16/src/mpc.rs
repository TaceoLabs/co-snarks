use std::fmt::Debug;

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_poly::domain::DomainCoeff;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

use mpc_core::Fork;
use mpc_engine::Network;
pub use plain::PlainGroth16Driver;
pub use rep3::Rep3Groth16Driver;
pub use shamir::ShamirGroth16Driver;

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
    type PointShare<C>: Debug + Send + Sync + 'static
    where
        C: CurveGroup + Send;
    /// Internal state of used MPC protocol
    type State: Fork + Send;

    /// Generate a random arithemitc share
    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare>;

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        party_id: usize,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: usize,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare>;

    /// Performs element-wise multiplication of two vectors of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// You must *NOT* perform additional non-linear operations on the result of this function.
    fn local_mul_vec(
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
        data: &mut Self::State,
    ) -> Vec<P::ScalarField>;

    /// Compute the msm of `h` and `h_query` and multiplication `r` * `s`.
    fn mul<N: Network>(
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
        net: &N,
        data: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare>;

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
    fn add_assign_points_public<C: CurveGroup>(id: usize, a: &mut Self::PointShare<C>, b: &C);

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_point<C, N: Network>(
        a: &Self::PointShare<C>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_half_point<N: Network>(
        a: P::G1,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<P::G1>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul<C, N: Network>(
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
        net: &N,
        rngs: &mut Self::State,
    ) -> eyre::Result<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>;
}
