use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

use mpc_core::MpcState;
use mpc_net::Network;
pub use plain::PlainPlonkDriver;
pub use rep3::Rep3PlonkDriver;
pub use shamir::ShamirPlonkDriver;

/// This trait represents the operations used during Groth16 proof generation
pub trait CircomPlonkProver<P: Pairing> {
    /// The arithmetic share type
    type ArithmeticShare: CanonicalSerialize + CanonicalDeserialize + Copy + Clone + Default + Send;
    /// The G1 point share type
    type PointShareG1: Send;
    /// The G2 point share type
    type PointShareG2: Send;
    /// Internal state of used MPC protocol
    type State: MpcState + Send;

    /// Generate a random arithmetic share
    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare>;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Add a public value a to the share b: \[c\] = a + \[b\]
    fn add_with_public(
        id: <Self::State as MpcState>::PartyID,
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Negates a vector of shared values: \[b\] = -\[a\] for every element in place.
    fn neg_vec_in_place(a: &mut [Self::ArithmeticShare]);

    /// Multiply a share b by a public value a: c = a * \[b\].
    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare;

    /// Performs element-wise multiplication of two vectors of shared values.
    /// Does not perform any networking.
    ///
    /// # Security
    /// If you want to perform additional non-linear operations on the result of this function,
    /// you *MUST* call [`CircomPlonkProver::io_round_mul_many`] first. Only then the relevant network round is performed.
    fn local_mul_many(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        state: &mut Self::State,
    ) -> Vec<P::ScalarField>;

    /// Performs networking round of `local_mul_many`
    fn io_round_mul_many<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Performs element-wise multiplication of two vectors of shared values.
    ///
    /// Use this function for small vecs. For large vecs see [`CircomPlonkProver::local_mul_many`]
    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Performs element-wise multiplication of three vectors of shared values.
    ///
    /// Use this function for small vecs. For large vecs see [`CircomPlonkProver::local_mul_many`]
    fn mul_many_pairs<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Convenience method for \[a\] + \[b\] * \[c\]
    fn add_mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Convenience method for \[a\] + \[b\] * c
    fn add_mul_public(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        c: P::ScalarField,
    ) -> Self::ArithmeticShare {
        Self::add(a, Self::mul_with_public(b, c))
    }

    /// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
    fn mul_open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>>;

    /// Reconstructs many shared values: a = Open(\[a\]).
    fn open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>>;

    /// Computes the inverse of many shared values: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare;

    /// Computes the FFT of a vector of shared field elements.
    fn fft<D: EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare>;

    /// Computes the inverse FFT of a vector of shared field elements.
    fn ifft<D: EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_point_g1<N: Network>(
        a: Self::PointShareG1,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<P::G1>;

    /// Reconstructs many shared points: A = Open(\[A\]).
    fn open_point_vec_g1<N: Network>(
        a: &[Self::PointShareG1],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::G1>>;

    /// Perform msm between G1 `points` and `scalars`
    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1;

    /// Evaluate the shared polynomial at the public point.
    /// Returns the evaluation and the polynomial
    fn evaluate_poly_public(
        poly: Vec<Self::ArithmeticShare>,
        point: P::ScalarField,
    ) -> (Self::ArithmeticShare, Vec<Self::ArithmeticShare>);

    /// Perform elementwise multiplication of the three vectors of shares and then perform the array_prod_mul protocol
    fn array_prod_mul<N: Network>(
        inv: bool,
        arr1: &[Self::ArithmeticShare],
        arr2: &[Self::ArithmeticShare],
        arr3: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;
}
