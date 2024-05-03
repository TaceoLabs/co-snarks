use ark_ec::CurveGroup;
use ark_ff::PrimeField;

/// A trait encompassing basic operations for MPC protocols over prime fields.
pub trait PrimeFieldMpcProtocol<F: PrimeField> {
    type FieldShare;
    type FieldShareVec;
    type FieldShareSlice;
    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;
    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;
    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare>;
    fn inv(&mut self, a: &Self::FieldShare) -> Self::FieldShare;
    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare;
    fn rand(&mut self) -> Self::FieldShare;
}

pub trait EcMpcProtocol<C: CurveGroup>: PrimeFieldMpcProtocol<C::ScalarField> {
    type PointShare;
    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;
    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;
    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare;
    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &C::ScalarField,
    ) -> Self::PointShare;
    fn scalar_mul(&mut self, a: &Self::PointShare, b: &Self::FieldShare) -> Self::PointShare;
}

pub trait FFTProvider<F: PrimeField>: PrimeFieldMpcProtocol<F> {
    fn fft(&mut self, data: &[Self::FieldShare]) -> Vec<Self::FieldShare>;
    fn ifft(&mut self, data: &[Self::FieldShare]) -> Vec<Self::FieldShare>;
}

pub trait MSMProvider<C: CurveGroup>: EcMpcProtocol<C> {
    fn msm_public_points(&mut self, points: &[C], scalars: &[Self::FieldShare]) -> C;
}
