use ark_ec::{CurveGroup, pairing::Pairing};
use mpc_core::{
    MpcState,
    protocols::rep3::{
        PartyID, Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, network, pointshare,
    },
};
use mpc_net::Network;
use rayon::prelude::*;

use super::CircomGroth16Prover;

/// A Groth16 driver for REP3 secret sharing
pub struct Rep3Groth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for Rep3Groth16Driver {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type ArithmeticHalfShare = P::ScalarField;
    type PointHalfShare<C>
        = C
    where
        C: CurveGroup;
    type State = Rep3State;

    fn rand<N: Network>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::rand(state))
    }

    fn evaluate_constraint(
        id: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Self::ArithmeticShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                arithmetic::add_assign_public(&mut acc, mul_result, id);
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                arithmetic::add_assign(&mut acc, arithmetic::mul_public(current_witness, *coeff));
            }
        }
        acc
    }

    fn evaluate_constraint_half_share(
        id: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticHalfShare {
        let mut acc = Self::ArithmeticHalfShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                match id {
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
        id: <Self::State as MpcState>::PartyID,
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
        id: <Self::State as MpcState>::PartyID,
        a: &mut Self::PointHalfShare<C>,
        b: &C,
    ) {
        match id {
            PartyID::ID0 => *a += b,
            PartyID::ID1 => {}
            PartyID::ID2 => {}
        }
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

    fn open_half_point<N: Network, C>(
        a: Self::PointHalfShare<C>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = <P as Pairing>::ScalarField>,
    {
        pointshare::open_half_point(a, net)
    }

    fn scalar_mul<N: Network>(
        a: &Self::PointHalfShare<<P as Pairing>::G1>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::PointHalfShare<<P as Pairing>::G1>> {
        let a_hs = network::reshare(net, *a)?;
        let point = Rep3PointShare::new(*a, a_hs);
        Ok(pointshare::scalar_mul_local(&point, b, state))
    }
}
