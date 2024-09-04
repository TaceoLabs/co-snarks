use ark_ec::{pairing::Pairing, CurveGroup};
use ark_poly::EvaluationDomain;
use mpc_core::traits::SecretShared;

mod plain;
mod rep3;
mod shamir;

type IoResult<T> = std::io::Result<T>;

pub trait CircomPlonkProver<P: Pairing> {
    type ArithmeticShare: SecretShared;
    type PointShare<C: CurveGroup>;

    fn rand(&self) -> Self::ArithmeticShare;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn add(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    /// Add a public value a to the share b: \[c\] = a + \[b\]
    fn add_with_public(
        &mut self,
        a: &P::ScalarField,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    /// Multiply a share b by a public value a: c = a * \[b\].
    fn mul_with_public(
        &mut self,
        a: &P::ScalarField,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>>;

    /// Convenience method for \[a\] + \[b\] * \[c\]
    async fn add_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>>;

    /// Convenience method for \[a\] + \[b\] * c
    fn add_mul_public(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        c: &P::ScalarField,
    ) -> Self::ArithmeticShare {
        let tmp = self.mul_with_public(c, b);
        self.add(a, &tmp)
    }

    /// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<P::ScalarField>>;

    /// Computes the inverse of many shared values: \[b\] = \[a\] ^ -1. Requires network communication.
    async fn inv_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>>;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(&self, public_values: P::ScalarField) -> Self::ArithmeticShare;

    /// Computes the FFT of a vector of shared field elements.
    fn fft<D: EvaluationDomain<P::ScalarField>>(
        &mut self,
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare>;

    /// Computes the inverse FFT of a vector of shared field elements.
    fn ifft<D: EvaluationDomain<P::ScalarField>>(
        &mut self,
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare>;

    /// Reconstructs many shared points: A = Open(\[A\]).
    fn open_point_many<C: CurveGroup>(&mut self, a: &[Self::PointShare<C>]) -> IoResult<Vec<C>>;

    // WE NEED THIS ALSO FOR GROTH16
    fn msm_public_points<C: CurveGroup>(
        &mut self,
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>;
}
