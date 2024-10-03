#![allow(async_fn_in_trait)]

use core::fmt;
use std::{fmt::Debug, future::Future, sync::Arc};

use ark_ec::pairing::Pairing;
use ark_poly::{domain::DomainCoeff, EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

pub use plain::PlainGroth16Driver;
pub use rep3::Rep3Groth16Driver;
pub use shamir::ShamirGroth16Driver;

type IoResult<T> = std::io::Result<T>;

pub trait CircomGroth16Prover<P: Pairing>: Send + Sized {
    type ArithmeticShare: CanonicalSerialize
        + CanonicalDeserialize
        + Copy
        + Clone
        + Default
        + Send
        + Debug
        + DomainCoeff<P::ScalarField>
        + 'static;
    type PointShareG1: Debug + Send + 'static;
    type PointShareG2: Debug + Send + 'static;
    type PartyID: Send + Sync + Copy + fmt::Display + 'static;

    async fn close_network(self) -> IoResult<()>;

    fn rand(&mut self) -> IoResult<Self::ArithmeticShare>;

    fn get_party_id(&self) -> Self::PartyID;

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

    async fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> IoResult<Vec<P::ScalarField>>;

    async fn msm_and_mul(
        &mut self,
        h: Vec<<P as Pairing>::ScalarField>,
        h_query: Arc<Vec<P::G1Affine>>,
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
    ) -> IoResult<(Self::PointShareG1, Self::ArithmeticShare)>;

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    );

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1;

    fn msm_public_points_g2(
        points: &[P::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG2;

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point_g1(a: &P::G1, b: Self::ArithmeticShare) -> Self::PointShareG1;

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1);
    fn add_assign_points_public_g1(id: Self::PartyID, a: &mut Self::PointShareG1, b: &P::G1);

    /// Reconstructs a shared point: A = Open(\[A\]).
    async fn open_point_g1(&mut self, a: &Self::PointShareG1) -> IoResult<P::G1>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    async fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShareG1>;

    /// Subtract a shared point B in place from the shared point A: \[A\] -= \[B\]
    fn sub_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1);

    fn scalar_mul_public_point_g2(a: &P::G2, b: Self::ArithmeticShare) -> Self::PointShareG2;
    fn add_assign_points_g2(a: &mut Self::PointShareG2, b: &Self::PointShareG2);
    fn add_assign_points_public_g2(id: Self::PartyID, a: &mut Self::PointShareG2, b: &P::G2);

    async fn open_two_points(
        &mut self,
        a: Self::PointShareG1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(P::G1, P::G2)>;

    async fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointShareG1,
        g1_b: &Self::PointShareG1,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(P::G1, Self::PointShareG1)>;
}
