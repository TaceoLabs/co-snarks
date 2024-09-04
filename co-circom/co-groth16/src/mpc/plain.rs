use ark_ec::{pairing::Pairing, CurveGroup};
use mpc_core::traits::SecretShared;

use super::CircomGroth16Prover;

pub(crate) struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver
where
    P::ScalarField: SecretShared,
{
    type ArithmeticShare = P::ScalarField;

    type PointShare<C: CurveGroup> = C;

    fn rand(&self) -> Self::ArithmeticShare {
        todo!()
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn promote_to_trivial_shares(
        &self,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn sub_assign_vec(&mut self, a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        todo!()
    }

    async fn mul(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> super::IoResult<Self::ArithmeticShare> {
        todo!()
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        &mut self,
        data: &mut [Self::ArithmeticShare],
        domain: &D,
    ) {
        todo!()
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        &mut self,
        data: &mut [Self::ArithmeticShare],
        domain: &D,
    ) {
        todo!()
    }

    fn distribute_powers_and_mul_by_const(
        &mut self,
        coeffs: &mut [Self::ArithmeticShare],
        g: P::ScalarField,
        c: P::ScalarField,
    ) {
        todo!()
    }

    fn msm_public_points<C: CurveGroup>(
        &mut self,
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C> {
        todo!()
    }

    fn add_assign_points_public<C: CurveGroup>(&mut self, a: &mut Self::PointShare<C>, b: &C) {
        todo!()
    }

    fn add_assign_points_public_affine<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &C::Affine,
    ) {
        todo!()
    }

    fn add_assign_points<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &Self::PointShare<C>,
    ) {
        todo!()
    }

    fn scalar_mul_public_point<C: CurveGroup>(
        &mut self,
        a: &C,
        b: &Self::ArithmeticShare,
    ) -> Self::PointShare<C> {
        todo!()
    }

    async fn open_point<C: CurveGroup>(&mut self, a: &Self::PointShare<C>) -> super::IoResult<C> {
        todo!()
    }

    async fn scalar_mul<C: CurveGroup>(
        &mut self,
        a: &Self::PointShare<C>,
        b: &Self::ArithmeticShare,
    ) -> super::IoResult<Self::PointShare<C>> {
        todo!()
    }

    fn sub_assign_points<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &Self::PointShare<C>,
    ) {
        todo!()
    }

    fn open_two_points<C1: CurveGroup, C2: CurveGroup>(
        &mut self,
        a: Self::PointShare<C1>,
        b: Self::PointShare<C2>,
    ) -> std::io::Result<(C1, C2)> {
        todo!()
    }
}
