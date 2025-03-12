use ark_ec::{pairing::Pairing, CurveGroup};
use mpc_core::protocols::rep3::{
    arithmetic::{self},
    pointshare::{self},
    Rep3PointShare, Rep3PrimeFieldShare, Rep3State,
};
use mpc_engine::Network;
use rayon::prelude::*;

use super::CircomGroth16Prover;

/// A Groth16 driver for REP3 secret sharing
pub struct Rep3Groth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for Rep3Groth16Driver {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShare<C>
        = Rep3PointShare<C>
    where
        C: CurveGroup;
    type State = Rep3State;

    fn rand<N: Network>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        Ok(Self::ArithmeticShare::rand(&mut state.rngs))
    }

    fn evaluate_constraint(
        party_id: usize,
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
        id: usize,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn local_mul_vec(
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
        state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(&a, &b, state)
    }

    fn mul<N: Network>(
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        arithmetic::mul(r, s, net, state)
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

    fn msm_public_points<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::msm_public_points(points, scalars)
    }

    fn scalar_mul_public_point<C>(a: &C, b: Self::ArithmeticShare) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::scalar_mul_public_point(a, b)
    }

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        pointshare::add_assign(a, b)
    }

    fn add_points_half_share<C: CurveGroup>(a: Self::PointShare<C>, b: &C) -> C {
        let (a, _) = a.ab();
        a + b
    }

    fn add_assign_points_public<C: CurveGroup>(id: usize, a: &mut Self::PointShare<C>, b: &C) {
        pointshare::add_assign_public(a, b, id)
    }

    fn open_point<C, N: Network>(
        a: &Self::PointShare<C>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::open_point(a, net)
    }

    fn open_half_point<N: Network>(
        a: P::G1,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<<P as Pairing>::G1> {
        pointshare::open_half_point(a, net)
    }

    fn scalar_mul<C, N: Network>(
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::scalar_mul(a, b, net, state)
    }

    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        pointshare::sub_assign(a, b);
    }
}
