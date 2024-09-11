use ark_ec::pairing::Pairing;
use mpc_core::protocols::rep3::{
    network::{IoContext, Rep3Network},
    Rep3PointShare, Rep3PrimeFieldShare,
};

use super::CircomPlonkProver;

pub(crate) struct Rep3PlonkDriver<N: Rep3Network> {
    io_context: IoContext<N>,
}

impl<P: Pairing, N: Rep3Network> CircomPlonkProver<P> for Rep3PlonkDriver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;

    type PointShare<C: ark_ec::CurveGroup> = Rep3PointShare<C>;

    fn rand(&self) -> Self::ArithmeticShare {
        todo!()
    }

    fn add(
        &mut self,
        _a: &Self::ArithmeticShare,
        _b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn add_with_public(
        &mut self,
        _a: &<P as Pairing>::ScalarField,
        _b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn sub(
        &mut self,
        _a: &Self::ArithmeticShare,
        _b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn neg_vec_in_place(&mut self, _a: &mut [Self::ArithmeticShare]) {
        todo!()
    }

    fn mul_with_public(
        &mut self,
        _a: &<P as Pairing>::ScalarField,
        _b: &Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    async fn mul_vec(
        &mut self,
        _a: &[Self::ArithmeticShare],
        _b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    async fn add_mul_vec(
        &mut self,
        _a: &[Self::ArithmeticShare],
        _b: &[Self::ArithmeticShare],
        _c: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn mul_open_many(
        &mut self,
        _a: &[Self::ArithmeticShare],
        _b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<<P as Pairing>::ScalarField>> {
        todo!()
    }

    fn open_many(
        &mut self,
        _a: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<<P as Pairing>::ScalarField>> {
        todo!()
    }

    async fn inv_many(
        &mut self,
        _a: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn promote_to_trivial_share(
        &self,
        _public_values: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn fft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        &mut self,
        _data: &[Self::ArithmeticShare],
        _domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn ifft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        &mut self,
        _data: &[Self::ArithmeticShare],
        _domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn open_point_many<C: ark_ec::CurveGroup>(
        &mut self,
        _a: &[Self::PointShare<C>],
    ) -> super::IoResult<Vec<C>> {
        todo!()
    }

    fn msm_public_points<C: ark_ec::CurveGroup>(
        &mut self,
        _points: &[C::Affine],
        _scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C> {
        todo!()
    }

    fn evaluate_poly_public(
        &mut self,
        _poly: &[Self::ArithmeticShare],
        _point: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        todo!()
    }
}
