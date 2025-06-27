use ark_ec::{CurveGroup, pairing::Pairing};
use mpc_core::protocols::rep3::{
    PartyID, Rep3PointShare, Rep3PrimeFieldShare, arithmetic,
    network::{IoContext, Rep3Network},
    pointshare,
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

    /// Get the underlying network
    pub fn get_network(self) -> N {
        self.io_context0.network
    }
}

impl<P: Pairing, N: Rep3Network> CircomGroth16Prover<P> for Rep3Groth16Driver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type ArithmeticHalfShare = P::ScalarField;

    type PointHalfShare<C>
        = C
    where
        C: CurveGroup;

    type PartyID = PartyID;

    fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        Ok(arithmetic::rand(&mut self.io_context0))
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

    fn evaluate_constraint_half_share(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticHalfShare {
        let mut acc = Self::ArithmeticHalfShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                match party_id {
                    PartyID::ID0 => acc += mul_result,
                    PartyID::ID1 => {}
                    PartyID::ID2 => {}
                }
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                let current_witness_hs = current_witness.a;
                acc += current_witness_hs * coeff;
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

    fn add_assign_points_public_hs<C: CurveGroup>(
        id: Self::PartyID,
        a: &mut Self::PointHalfShare<C>,
        b: &C,
    ) {
        match id {
            PartyID::ID0 => *a += b,
            PartyID::ID1 => {}
            PartyID::ID2 => {}
        }
    }

    fn open_two_half_points(&mut self, a: P::G1, b: P::G2) -> std::io::Result<(P::G1, P::G2)> {
        let mut s1 = a;
        let mut s2 = b;
        let (r1, r2) = std::thread::scope(|s| {
            let r1 = s.spawn(|| self.io_context0.network.broadcast(s1));
            let r2 = s.spawn(|| self.io_context1.network.broadcast(s2));
            (r1.join().expect("can join"), r2.join().expect("can join"))
        });
        let (r1b, r1c) = r1?;
        let (r2b, r2c) = r2?;
        s1 += r1b + r1c;
        s2 += r2b + r2c;
        Ok((s1, s2))
    }

    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointHalfShare<P::G1>,
        g1_b: &Self::PointHalfShare<P::G1>,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(<P as Pairing>::G1, Self::PointHalfShare<P::G1>)> {
        std::thread::scope(|s| {
            let opened = s.spawn(|| self.io_context0.network.broadcast(*g_a));
            let g1_b_hs = s.spawn(|| self.io_context1.network.reshare(*g1_b));
            let point = Rep3PointShare {
                a: *g1_b,
                b: g1_b_hs.join().expect("can join")?,
            };
            let mul_result = pointshare::scalar_mul_local(&point, r, &mut self.io_context1.rngs);

            let (g_a_1, g_a_2) = opened.join().expect("can join")?;
            let open_res = g_a_1 + g_a_2 + g_a;

            Ok((open_res, mul_result))
        })
    }

    fn to_half_share(a: Self::ArithmeticShare) -> <P as Pairing>::ScalarField {
        a.a
    }

    fn msm_public_points_hs<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticHalfShare],
    ) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = <P as Pairing>::ScalarField>,
    {
        C::msm_unchecked(points, scalars)
    }

    fn scalar_mul_public_point_hs<C>(a: &C, b: Self::ArithmeticHalfShare) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = <P as Pairing>::ScalarField>,
    {
        *a * b
    }
}
