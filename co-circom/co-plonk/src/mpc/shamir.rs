use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;

use mpc_core::protocols::shamir::{
    arithmetic, network::ShamirNetwork, pointshare, ShamirPointShare, ShamirPrimeFieldShare,
    ShamirProtocol,
};

use super::{CircomPlonkProver, IoResult};

pub struct ShamirPlonkDriver<F: PrimeField, N: ShamirNetwork> {
    protocol: ShamirProtocol<F, N>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirPlonkDriver<F, N> {
    pub fn new(protocol: ShamirProtocol<F, N>) -> Self {
        Self { protocol }
    }
}

impl<P: Pairing, N: ShamirNetwork> CircomPlonkProver<P> for ShamirPlonkDriver<P::ScalarField, N> {
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type PointShareG1 = ShamirPointShare<P::G1>;
    type PointShareG2 = ShamirPointShare<P::G2>;

    type PartyID = usize;

    fn debug_print(_a: Self::ArithmeticShare) {
        todo!()
    }

    async fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        self.protocol.rand().await
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.protocol.network.get_id()
    }

    fn fork(&mut self) -> Self {
        todo!()
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_with_public(
        _party_id: Self::PartyID,
        shared: Self::ArithmeticShare,
        public: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public)
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn neg_vec_in_place(&mut self, a: &mut [Self::ArithmeticShare]) {
        for a in a.iter_mut() {
            *a = arithmetic::neg(*a);
        }
    }

    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_vec(a, b, &mut self.protocol).await
    }

    async fn mul_vecs(
        &mut self,
        _a: &[Self::ArithmeticShare],
        _b: &[Self::ArithmeticShare],
        _c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    async fn add_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        let mut result = arithmetic::mul_vec(b, c, &mut self.protocol).await?;
        arithmetic::add_vec_assign(&mut result, a);
        Ok(result)
    }

    async fn mul_open_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<<P as Pairing>::ScalarField>> {
        arithmetic::mul_open_vec(a, b, &mut self.protocol).await
    }

    async fn open_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<<P as Pairing>::ScalarField>> {
        arithmetic::open_vec(a, &mut self.protocol).await
    }

    async fn inv_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, &mut self.protocol).await
    }

    fn promote_to_trivial_share(
        _party_id: Self::PartyID,
        public_value: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(public_value)
    }

    fn fft<D: EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(data)
    }

    fn ifft<D: EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }

    async fn open_point_g1(&mut self, a: Self::PointShareG1) -> IoResult<<P as Pairing>::G1> {
        pointshare::open_point(&a, &mut self.protocol).await
    }

    async fn open_point_vec_g1(
        &mut self,
        a: &[Self::PointShareG1],
    ) -> IoResult<Vec<<P as Pairing>::G1>> {
        pointshare::open_point_many(a, &mut self.protocol).await
    }

    fn msm_public_points_g1(
        points: &[<P as Pairing>::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        pointshare::msm_public_points(points, scalars)
    }

    fn evaluate_poly_public(
        poly: &[Self::ArithmeticShare],
        point: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        // poly::eval_poly(coeffs, point)
        todo!() // TODO RH create poly module
    }
}
