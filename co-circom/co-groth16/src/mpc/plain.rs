use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use mpc_engine::Network;
use rand::thread_rng;

use super::CircomGroth16Prover;

/// A plain Groth16 driver
pub struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver {
    type ArithmeticShare = P::ScalarField;

    type PointShare<C>
        = C
    where
        C: CurveGroup;

    type State = ();

    fn rand<N: Network>(_: &N, _: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn evaluate_constraint(
        _: usize,
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

    fn promote_to_trivial_shares(
        _: usize,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn local_mul_vec(
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
        _: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect()
    }

    fn mul<N: Network>(
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(r * s)
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    ) {
        for (c, pow) in coeffs.iter_mut().zip(roots) {
            *c *= pow;
        }
    }

    fn msm_public_points<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        C::msm_unchecked(points, scalars)
    }

    fn scalar_mul_public_point<C>(a: &C, b: Self::ArithmeticShare) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        *a * b
    }

    fn add_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        *a += b;
    }

    fn add_points_half_share<C: CurveGroup>(a: Self::PointShare<C>, b: &C) -> C {
        a + b
    }

    fn add_assign_points_public<C: CurveGroup>(_: usize, a: &mut Self::PointShare<C>, b: &C) {
        *a += b;
    }

    fn open_point<C, N: Network>(
        a: &Self::PointShare<C>,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        Ok(*a)
    }

    fn open_half_point<N: Network>(a: P::G1, _: &N, _: &mut Self::State) -> eyre::Result<P::G1> {
        Ok(a)
    }

    fn scalar_mul<C, N: Network>(
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        Ok(*a * b)
    }

    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        *a -= b;
    }
}
