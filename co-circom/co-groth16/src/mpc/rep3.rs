use ark_ec::pairing::Pairing;
use mpc_core::protocols::rep3::{
    arithmetic,
    id::PartyID,
    network::{IoContext, Rep3Network},
    pointshare, Rep3PointShare, Rep3PrimeFieldShare,
};
use rayon::prelude::*;
use tokio::sync::oneshot;

use super::{CircomGroth16Prover, IoResult};

pub struct Rep3Groth16Driver<N: Rep3Network> {
    io_context0: IoContext<N>,
    io_context1: IoContext<N>,
}

impl<N: Rep3Network> Rep3Groth16Driver<N> {
    pub fn new(io_context0: IoContext<N>, io_context1: IoContext<N>) -> Self {
        Self {
            io_context0,
            io_context1,
        }
    }
}

impl<P: Pairing, N: Rep3Network> CircomGroth16Prover<P> for Rep3Groth16Driver<N>
where
    N: 'static,
{
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShareG1 = Rep3PointShare<P::G1>;
    type PointShareG2 = Rep3PointShare<P::G2>;

    type PartyID = PartyID;

    async fn close_network(self) -> IoResult<()> {
        self.io_context0.network.shutdown().await?;
        self.io_context1.network.shutdown().await?;
        Ok(())
    }

    fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        Ok(Self::ArithmeticShare::rand(&mut self.io_context0))
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.io_context0.id
    }

    fn evaluate_constraint(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Self::ArithmeticShare::default();
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
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    async fn mul(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        arithmetic::mul(a, b, &mut self.io_context0).await
    }

    async fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> IoResult<Vec<P::ScalarField>> {
        //squeeze all random elements at once in beginning for determinismus
        let mut correlated_randomness = self.io_context0.fork_randomness();
        let (tx, rx) = oneshot::channel();
        rayon::spawn(move || {
            let result = arithmetic::local_mul_vec(&a, &b, &mut correlated_randomness);
            tx.send(result).expect("channel not dropped");
        });
        Ok(rx.await.expect("channel not dropped"))
    }

    async fn io_round_mul_vec(
        &mut self,
        a: Vec<P::ScalarField>,
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        arithmetic::io_mul_vec(a, &mut self.io_context0).await
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    ) {
        coeffs
            .par_iter_mut()
            .zip_eq(roots.par_iter())
            .with_min_len(512)
            .for_each(|(c, pow)| {
                arithmetic::mul_assign_public(c, *pow);
            })
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        pointshare::msm_public_points(points, scalars)
    }

    fn msm_public_points_g2(
        points: &[P::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG2 {
        pointshare::msm_public_points(points, scalars)
    }

    fn scalar_mul_public_point_g1(a: &P::G1, b: Self::ArithmeticShare) -> Self::PointShareG1 {
        pointshare::scalar_mul_public_point(a, b)
    }

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        pointshare::add_assign(a, b)
    }

    fn add_assign_points_public_g1(id: Self::PartyID, a: &mut Self::PointShareG1, b: &P::G1) {
        pointshare::add_assign_public(a, b, id)
    }

    async fn open_point_g1(&mut self, a: &Self::PointShareG1) -> IoResult<P::G1> {
        pointshare::open_point(a, &mut self.io_context0).await
    }

    async fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShareG1> {
        pointshare::scalar_mul(a, b, &mut self.io_context0).await
    }

    fn sub_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        pointshare::sub_assign(a, b);
    }

    fn scalar_mul_public_point_g2(a: &P::G2, b: Self::ArithmeticShare) -> Self::PointShareG2 {
        pointshare::scalar_mul_public_point(a, b)
    }

    fn add_assign_points_g2(a: &mut Self::PointShareG2, b: &Self::PointShareG2) {
        pointshare::add_assign(a, b)
    }

    fn add_assign_points_public_g2(id: Self::PartyID, a: &mut Self::PointShareG2, b: &P::G2) {
        pointshare::add_assign_public(a, b, id)
    }

    async fn open_two_points(
        &mut self,
        a: Self::PointShareG1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a.b;
        let s2 = b.b;
        let (mut r1, mut r2) = self.io_context0.network.reshare((s1, s2)).await?;
        r1 += a.a + a.b;
        r2 += b.a + b.b;
        Ok((r1, r2))
    }

    async fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointShareG1,
        g1_b: &Self::PointShareG1,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(<P as Pairing>::G1, Self::PointShareG1)> {
        let (opened, mul_result) = tokio::join!(
            pointshare::open_point(g_a, &mut self.io_context0),
            pointshare::scalar_mul(g1_b, r, &mut self.io_context1),
        );
        Ok((opened?, mul_result?))
    }
}
