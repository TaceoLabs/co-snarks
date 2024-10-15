use ark_ec::pairing::Pairing;
use mpc_core::protocols::rep3::{
    arithmetic,
    id::PartyID,
    network::{IoContext, Rep3Network},
    pointshare, Rep3PointShare, Rep3PrimeFieldShare,
};
use rayon::prelude::*;

use super::{CircomGroth16Prover, IoResult};

/// A Groth16 driver for REP3 secret sharing
///
/// Contains two [`IoContext`]s, `io_context0` for the main execution and `io_context1` for parts that can run concurrently.
pub struct Rep3Groth16Driver<N: Rep3Network> {
    io_context0: IoContext<N>,
    io_context1: IoContext<N>,
}

impl<N: Rep3Network> Rep3Groth16Driver<N> {
    /// Create a new [`Rep3Groth16Driver`] with two [`IoContext`]s
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

    fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(&a, &b, &mut self.io_context0.rngs)
    }

    fn mul(
        &mut self,
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        arithmetic::mul(r, s, &mut self.io_context1)
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

    fn add_points_g1_half_share(a: Self::PointShareG1, b: &P::G1) -> P::G1 {
        let (a, _) = a.ab();
        a + b
    }

    fn add_assign_points_public_g1(id: Self::PartyID, a: &mut Self::PointShareG1, b: &P::G1) {
        pointshare::add_assign_public(a, b, id)
    }

    fn open_point_g1(&mut self, a: &Self::PointShareG1) -> IoResult<P::G1> {
        pointshare::open_point(a, &mut self.io_context0)
    }

    fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShareG1> {
        pointshare::scalar_mul(a, b, &mut self.io_context0)
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

    fn open_two_points(
        &mut self,
        a: P::G1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let mut s1 = a;
        let s2 = b.b;
        let (r1, r2) = std::thread::scope(|s| {
            let r1 = s.spawn(|| self.io_context0.network.broadcast(s1));
            let r2 = s.spawn(|| self.io_context1.network.reshare(s2));
            (r1.join().expect("can join"), r2.join().expect("can join"))
        });
        let (r1b, r1c) = r1?;
        let mut r2 = r2?;
        s1 += r1b + r1c;
        r2 += b.a + b.b;
        Ok((s1, r2))
    }

    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointShareG1,
        g1_b: &Self::PointShareG1,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(<P as Pairing>::G1, Self::PointShareG1)> {
        std::thread::scope(|s| {
            let opened = s.spawn(|| pointshare::open_point(g_a, &mut self.io_context0));
            let mul_result = pointshare::scalar_mul(g1_b, r, &mut self.io_context1)?;
            Ok((opened.join().expect("can join")?, mul_result))
        })
    }
}
