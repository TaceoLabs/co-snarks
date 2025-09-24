use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use mpc_core::MpcState;
use mpc_net::Network;
use rand::thread_rng;

use super::CircomGroth16Prover;

/// A plain Groth16 driver
pub struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver {
    type ArithmeticShare = P::ScalarField;
    type ArithmeticHalfShare = P::ScalarField;
    type PointHalfShare<C>
        = C
    where
        C: CurveGroup;
    type State = ();

    fn rand<N: Network>(_: &N, _: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn evaluate_constraint(
        _: <Self::State as MpcState>::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = P::ScalarField::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                acc += *coeff * public_inputs[*index];
            } else {
                acc += *coeff * private_witness[*index - public_inputs.len()];
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
        let mut acc = P::ScalarField::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                acc += *coeff * public_inputs[*index];
            } else {
                acc += *coeff * private_witness[*index - public_inputs.len()];
            }
        }
        acc
    }

    fn to_half_share(a: Self::ArithmeticShare) -> <P as Pairing>::ScalarField {
        a
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

    fn promote_to_trivial_shares(
        _: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn local_mul_many(
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
        _: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect()
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    ) {
        for (c, pow) in coeffs.iter_mut().zip(roots) {
            *c *= pow;
        }
    }

    fn add_assign_points_public_hs<C: CurveGroup>(
        _: <Self::State as MpcState>::PartyID,
        a: &mut Self::PointHalfShare<C>,
        b: &C,
    ) {
        *a += b;
    }

    fn scalar_mul_public_point_hs<C>(a: &C, b: Self::ArithmeticHalfShare) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        *a * b
    }

    fn open_half_point<N: Network, C>(
        a: Self::PointHalfShare<C>,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        Ok(a)
    }

    fn scalar_mul<N: Network>(
        a: &Self::PointHalfShare<P::G1>,
        b: Self::ArithmeticShare,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Self::PointHalfShare<P::G1>> {
        Ok(*a * b)
    }
}
