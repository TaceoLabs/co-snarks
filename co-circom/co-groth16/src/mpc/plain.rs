use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use rand::thread_rng;

use super::CircomGroth16Prover;

type IoResult<T> = std::io::Result<T>;

/// A plain Groth16 driver
pub struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver {
    type ArithmeticShare = P::ScalarField;

    type PointShare<C> = C where C: CurveGroup;

    type PartyID = usize;

    fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn get_party_id(&self) -> Self::PartyID {
        //does't matter
        0
    }

    fn evaluate_constraint(
        _: Self::PartyID,
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
        _: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> Vec<P::ScalarField> {
        a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect()
    }

    fn mul(
        &mut self,
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        Ok(r * s)
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    ) {
        #[allow(unused_mut)]
        for (mut c, pow) in coeffs.iter_mut().zip(roots) {
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

    fn add_assign_points_public<C: CurveGroup>(
        _: Self::PartyID,
        a: &mut Self::PointShare<C>,
        b: &C,
    ) {
        *a += b;
    }

    fn open_point<C>(&mut self, a: &Self::PointShare<C>) -> super::IoResult<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        Ok(*a)
    }

    fn scalar_mul<C>(
        &mut self,
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
    ) -> super::IoResult<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        Ok(*a * b)
    }

    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        *a -= b;
    }

    fn open_two_points(
        &mut self,
        a: Self::PointShare<P::G1>,
        b: Self::PointShare<P::G2>,
    ) -> std::io::Result<(P::G1, P::G2)> {
        Ok((a, b))
    }

    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointShare<P::G1>,
        g1_b: &Self::PointShare<P::G1>,
        r: Self::ArithmeticShare,
    ) -> super::IoResult<(P::G1, Self::PointShare<P::G1>)> {
        Ok((*g_a, *g1_b * r))
    }
}
