use super::CircomGroth16Prover;
use ark_ec::{CurveGroup, pairing::Pairing};
use mpc_core::{
    MpcState,
    protocols::shamir::{ShamirPrimeFieldShare, ShamirState, arithmetic, network, pointshare},
};
use mpc_net::Network;
use rayon::prelude::*;

/// A Groth16 dirver unsing shamir secret sharing
pub struct ShamirGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for ShamirGroth16Driver {
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type ArithmeticHalfShare = P::ScalarField;
    type PointHalfShare<C>
        = C
    where
        C: CurveGroup;
    type State = ShamirState<P::ScalarField>;

    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        state.rand(net)
    }

    fn evaluate_constraint(
        _: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Self::ArithmeticShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                arithmetic::add_assign_public(&mut acc, mul_result);
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                arithmetic::add_assign(&mut acc, arithmetic::mul_public(current_witness, *coeff));
            }
        }
        acc
    }

    fn evaluate_constraint_half_share(
        _: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticHalfShare {
        let mut acc = Self::ArithmeticHalfShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                acc += mul_result;
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                let current_witness_hs = current_witness.inner();
                acc += current_witness_hs * coeff;
            }
        }
        acc
    }

    fn promote_to_trivial_shares(
        _: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        arithmetic::promote_to_trivial_shares(public_values)
    }

    fn local_mul_vec(
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
        _: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(&a, &b)
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
        _: <Self::State as MpcState>::PartyID,
        a: &mut Self::PointHalfShare<C>,
        b: &C,
    ) {
        *a += b;
    }

    /// For Shamir sharing, a valid degree-t share is always a valid degree-2t share.
    fn to_half_share(a: Self::ArithmeticShare) -> <P as Pairing>::ScalarField {
        a.inner()
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
        state: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = <P as Pairing>::ScalarField>,
    {
        pointshare::open_half_point(a, net, state)
    }

    fn scalar_mul<N: Network>(
        a: &Self::PointHalfShare<<P as Pairing>::G1>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::PointHalfShare<<P as Pairing>::G1>> {
        let a = network::degree_reduce_point(net, state, *a)?;
        Ok(pointshare::scalar_mul_local(&a, b))
    }
}
