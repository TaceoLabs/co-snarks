use ark_ec::pairing::Pairing;
use itertools::izip;
use mpc_core::protocols::rep3::{
    self, arithmetic,
    id::PartyID,
    network::{IoContext, Rep3Network},
    Rep3PointShare, Rep3PrimeFieldShare,
};

use super::{CircomGroth16Prover, IoResult};

pub struct Rep3Groth16Driver<N: Rep3Network> {
    io_context: IoContext<N>,
}

impl<N: Rep3Network> Rep3Groth16Driver<N> {
    pub fn new(io_context: IoContext<N>) -> Self {
        Self { io_context }
    }
}

impl<P: Pairing, N: Rep3Network> CircomGroth16Prover<P> for Rep3Groth16Driver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShareG1 = Rep3PointShare<P::G1>;
    type PointShareG2 = Rep3PointShare<P::G2>;

    type PartyID = PartyID;

    fn rand(&mut self) -> Self::ArithmeticShare {
        Self::ArithmeticShare::rand(&mut self.io_context)
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.io_context.id
    }

    fn fork(&mut self) -> Self {
        todo!()
    }

    fn evaluate_constraint(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Rep3PrimeFieldShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                arithmetic::add_assign_public(&mut acc, mul_result, party_id);
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                arithmetic::add_assign(&mut acc, arithmetic::mul_public(current_witness, *coeff));
            }
        }
        acc
    }

    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .iter()
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn sub_assign_vec(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        for (a, b) in izip!(a, b) {
            rep3::arithmetic::sub_assign(a, *b);
        }
    }

    async fn mul(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        rep3::arithmetic::mul(a, b, &mut self.io_context).await
    }

    async fn mul_vec(
        &mut self,
        lhs: &[Self::ArithmeticShare],
        rhs: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        rep3::arithmetic::mul_vec(lhs, rhs, &mut self.io_context).await
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare>,
        domain: &D,
    ) {
        domain.fft_in_place(data)
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare>,
        domain: &D,
    ) {
        domain.ifft_in_place(data)
    }

    fn ifft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(&data)
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        g: P::ScalarField,
        c: P::ScalarField,
    ) {
        let mut pow = c;
        for share in coeffs.iter_mut() {
            rep3::arithmetic::mul_assign_public(share, pow);
            pow *= g;
        }
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        rep3::pointshare::msm_public_points(points, scalars)
    }

    fn msm_public_points_g2(
        points: &[P::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG2 {
        rep3::pointshare::msm_public_points(points, scalars)
    }

    fn scalar_mul_public_point_g1(
        a: &<P as Pairing>::G1,
        b: Self::ArithmeticShare,
    ) -> Self::PointShareG1 {
        rep3::pointshare::scalar_mul_public_point(a, b)
    }

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        rep3::pointshare::add_assign(a, b)
    }

    fn add_assign_points_public_g1(id: Self::PartyID, a: &mut Self::PointShareG1, b: &P::G1) {
        rep3::pointshare::add_assign_public(a, b, id)
    }

    async fn open_point_g1(&mut self, a: &Self::PointShareG1) -> IoResult<<P as Pairing>::G1> {
        let c = self.io_context.network.reshare(a.b).await?;
        Ok(a.a + a.b + c)
    }

    async fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShareG1> {
        rep3::pointshare::scalar_mul(a, b, &mut self.io_context).await
    }

    fn sub_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        rep3::pointshare::sub_assign(a, b);
    }

    fn scalar_mul_public_point_g2(a: &P::G2, b: Self::ArithmeticShare) -> Self::PointShareG2 {
        rep3::pointshare::scalar_mul_public_point(a, b)
    }

    fn add_assign_points_g2(a: &mut Self::PointShareG2, b: &Self::PointShareG2) {
        rep3::pointshare::add_assign(a, b)
    }

    fn add_assign_points_public_g2(id: Self::PartyID, a: &mut Self::PointShareG2, b: &P::G2) {
        rep3::pointshare::add_assign_public(a, b, id)
    }

    async fn open_two_points(
        &mut self,
        a: Self::PointShareG1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a.b;
        let s2 = b.b;
        let (mut r1, mut r2) = self.io_context.network.reshare((s1, s2)).await?;
        r1 += a.a + a.b;
        r2 += b.a + b.b;
        Ok((r1, r2))
    }
}
