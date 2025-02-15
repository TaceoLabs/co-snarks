use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

/// This trait represents the operations used during UltraHonk proof generation
pub trait NoirUltraHonkProver<P: Pairing>: Send + Sized {
    /// The arithemitc share type
    type ArithmeticShare: CanonicalSerialize
        + CanonicalDeserialize
        + Copy
        + Clone
        + Default
        + Send
        + PartialEq
        + std::fmt::Debug
        + 'static;
    /// The G1 point share type
    type PointShare: std::fmt::Debug + Send + 'static;
    /// The party id type
    type PartyID: Copy;

    /// Generate a share of a random value. The value is thereby unknown to anyone.
    fn rand(&mut self) -> std::io::Result<Self::ArithmeticShare>;

    /// Get the party id
    fn get_party_id(&self) -> Self::PartyID;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub(&self, a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Add two shares: \[c\] = \[a\] + \[b\]
    fn add(&self, a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Negates a shared value: \[b\] = -\[a\].
    fn neg(&mut self, a: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Multiply a share b by a public value a: c = a * \[b\].
    fn mul_with_public(
        &self,
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    /// Multiply two shares: \[c\] = \[a\] * \[b\]. Requires network communication.
    fn mul_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>>;

    /// Add a public value a to the share b: \[c\] = a + \[b\]
    fn add_with_public(
        &self,
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(
        id: Self::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_point(&mut self, a: Self::PointShare) -> std::io::Result<P::G1>;

    /// Reconstructs many shared points: A = Open(\[A\]).
    fn open_point_many(&mut self, a: &[Self::PointShare]) -> std::io::Result<Vec<P::G1>>;

    /// Reconstructs many shared values: a = Open(\[a\]).
    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> std::io::Result<Vec<P::ScalarField>>;

    /// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<P::ScalarField>>;

    /// Computes the inverse of many shared values: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>>;

    /// Computes the inverse of many shared values: \[a\] = \[a\] ^ -1. Requires network communication.
    /// This function ignores the case of one share to be zero and maps it to zero.
    fn inv_many_in_place(&mut self, a: &mut [Self::ArithmeticShare]) -> std::io::Result<()>;

    /// Computes the inverse of many shared values: \[a\] = \[a\] ^ -1. Requires network communication.
    /// This function ignores the case of one share to be zero and maps it to zero.
    fn inv_many_in_place_leaking_zeros(
        &mut self,
        a: &mut [Self::ArithmeticShare],
    ) -> std::io::Result<()>;

    /// Perform msm between `points` and `scalars`
    fn msm_public_points(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare;

    /// Evaluates shared polynomials at one point
    fn eval_poly(
        &mut self,
        coeffs: &[Self::ArithmeticShare],
        point: P::ScalarField,
    ) -> Self::ArithmeticShare;
}
