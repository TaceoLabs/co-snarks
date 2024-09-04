use ark_ec::{pairing::Pairing, CurveGroup};
use ark_poly::EvaluationDomain;
use mpc_core::traits::SecretShared;

pub(crate) mod plain;
pub(crate) mod rep3;
pub(crate) mod shamir;

type IoResult<T> = std::io::Result<T>;

pub trait CircomGroth16Prover<P: Pairing> {
    type ArithmeticShare: SecretShared;
    type PointShare<C: CurveGroup>;

    fn rand(&self) -> Self::ArithmeticShare;
    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        &mut self,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        &self,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare>;

    /// Elementwise subtraction of two vectors of shares in place: \[a_i\] -= \[b_i\]
    fn sub_assign_vec(&mut self, a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]);

    async fn mul(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare>;

    /// Elementwise multiplication of two vectors of shares: \[c_i\] = \[a_i\] * \[b_i\].
    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>>;

    fn fft_in_place<D: EvaluationDomain<P::ScalarField>>(
        &mut self,
        data: &mut [Self::ArithmeticShare],
        domain: &D,
    );

    /// Computes the inverse FFT of a vector of shared field elements in place.
    fn ifft_in_place<D: EvaluationDomain<P::ScalarField>>(
        &mut self,
        data: &mut [Self::ArithmeticShare],
        domain: &D,
    );

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(
        &mut self,
        coeffs: &mut [Self::ArithmeticShare],
        g: P::ScalarField,
        c: P::ScalarField,
    );

    fn msm_public_points<C: CurveGroup>(
        &mut self,
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>;

    //TODO DO WE NEED PROJECTIVE AND AFFINE METHODS????

    /// Add a public point B to the shared point A in place: \[A\] += B
    fn add_assign_points_public<C: CurveGroup>(&mut self, a: &mut Self::PointShare<C>, b: &C);

    /// Add a public affine point B to the shared point A in place: \[A\] += B
    fn add_assign_points_public_affine<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &C::Affine,
    );

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &Self::PointShare<C>,
    );

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point<C: CurveGroup>(
        &mut self,
        a: &C,
        b: &Self::ArithmeticShare,
    ) -> Self::PointShare<C>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    async fn open_point<C: CurveGroup>(&mut self, a: &Self::PointShare<C>) -> IoResult<C>;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    async fn scalar_mul<C: CurveGroup>(
        &mut self,
        a: &Self::PointShare<C>,
        b: &Self::ArithmeticShare,
    ) -> IoResult<Self::PointShare<C>>;

    /// Subtract a shared point B in place from the shared point A: \[A\] -= \[B\]
    fn sub_assign_points<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &Self::PointShare<C>,
    );

    fn open_two_points<C1: CurveGroup, C2: CurveGroup>(
        &mut self,
        a: Self::PointShare<C1>,
        b: Self::PointShare<C2>,
    ) -> std::io::Result<(C1, C2)>;
}
