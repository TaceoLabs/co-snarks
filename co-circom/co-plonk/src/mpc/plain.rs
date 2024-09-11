use ark_ec::pairing::Pairing;

use super::CircomPlonkProver;

pub struct PlainPlonkDriver;

impl<P: Pairing> CircomPlonkProver<P> for PlainPlonkDriver {
    type ArithmeticShare = P::ScalarField;

    type PointShare<C: ark_ec::CurveGroup> = C;

    fn rand(&self) -> Self::ArithmeticShare {
        todo!()
    }

    fn add(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn add_with_public(
        &mut self,
        a: &<P as Pairing>::ScalarField,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn sub(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn neg_vec_in_place(&mut self, a: &mut [Self::ArithmeticShare]) {
        todo!()
    }

    fn mul_with_public(
        &mut self,
        a: &<P as Pairing>::ScalarField,
        b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    async fn add_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<<P as Pairing>::ScalarField>> {
        todo!()
    }

    fn open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<<P as Pairing>::ScalarField>> {
        todo!()
    }

    async fn inv_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn promote_to_trivial_share(
        &self,
        public_values: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn fft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        &mut self,
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn ifft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        &mut self,
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn open_point_many<C: ark_ec::CurveGroup>(
        &mut self,
        a: &[Self::PointShare<C>],
    ) -> super::IoResult<Vec<C>> {
        todo!()
    }

    fn msm_public_points<C: ark_ec::CurveGroup>(
        &mut self,
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C> {
        todo!()
    }

    fn evaluate_poly_public(
        &mut self,
        poly: &[Self::ArithmeticShare],
        point: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        todo!()
    }
}
