use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;
use mpc_core::protocols::rep3::{
    arithmetic,
    id::PartyID,
    network::{IoContext, Rep3Network},
    pointshare, poly, Rep3PointShare, Rep3PrimeFieldShare,
};

use super::{CircomPlonkProver, IoResult};

pub struct Rep3PlonkDriver<N: Rep3Network> {
    io_context: IoContext<N>,
}

impl<N: Rep3Network> Rep3PlonkDriver<N> {
    pub fn new(io_context: IoContext<N>) -> Self {
        Self { io_context }
    }
}

impl<P: Pairing, N: Rep3Network> CircomPlonkProver<P> for Rep3PlonkDriver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShareG1 = Rep3PointShare<P::G1>;
    type PointShareG2 = Rep3PointShare<P::G2>;

    type PartyID = PartyID;

    fn debug_print(_: Self::ArithmeticShare) {
        todo!()
    }

    async fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        Ok(Self::ArithmeticShare::rand(&mut self.io_context))
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.io_context.id
    }

    fn fork(&mut self) -> Self {
        todo!()
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_with_public(
        party_id: Self::PartyID,
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public, party_id)
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn neg_vec_in_place(&mut self, vec: &mut [Self::ArithmeticShare]) {
        #[allow(unused_mut)]
        for mut a in vec.iter_mut() {
            *a = arithmetic::neg(*a);
        }
    }

    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    async fn mul_vec(
        &mut self,
        lhs: &[Self::ArithmeticShare],
        rhs: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_vec(lhs, rhs, &mut self.io_context).await
    }

    async fn mul_vecs(
        &mut self,
        _a: &[Self::ArithmeticShare],
        _b: &[Self::ArithmeticShare],
        _c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        todo!();
    }

    async fn add_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        let mut result = arithmetic::mul_vec(b, c, &mut self.io_context).await?;
        arithmetic::add_vec_assign(&mut result, a);
        Ok(result)
    }

    async fn mul_open_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<P::ScalarField>> {
        arithmetic::mul_open_vec(a, b, &mut self.io_context).await
    }

    async fn open_vec(&mut self, a: &[Self::ArithmeticShare]) -> IoResult<Vec<P::ScalarField>> {
        arithmetic::open_vec(a, &mut self.io_context).await
    }

    async fn inv_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, &mut self.io_context).await
    }

    fn promote_to_trivial_share(
        party_id: Self::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        Self::ArithmeticShare::promote_from_trivial(&public_value, party_id)
    }

    fn fft<D: EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(&data)
    }

    fn ifft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(&data)
    }

    async fn open_point_g1(&mut self, a: Self::PointShareG1) -> IoResult<P::G1> {
        pointshare::open_point(&a, &mut self.io_context).await
    }

    async fn open_point_vec_g1(&mut self, a: &[Self::PointShareG1]) -> IoResult<Vec<P::G1>> {
        pointshare::open_point_many(a, &mut self.io_context).await
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        pointshare::msm_public_points(points, scalars)
    }

    fn evaluate_poly_public(
        coeffs: &[Self::ArithmeticShare],
        point: P::ScalarField,
    ) -> Self::ArithmeticShare {
        poly::eval_poly(coeffs, point)
    }
}
