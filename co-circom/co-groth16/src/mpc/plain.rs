use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ff::UniformRand;
use itertools::izip;
use rand::thread_rng;

use super::CircomGroth16Prover;

type IoResult<T> = std::io::Result<T>;

pub struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver {
    type ArithmeticShare = P::ScalarField;

    type PointShareG1 = P::G1;

    type PointShareG2 = P::G2;

    type PartyID = usize;

    async fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn get_party_id(&self) -> Self::PartyID {
        //does't matter
        0
    }

    fn fork(&mut self) -> Self {
        PlainGroth16Driver
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

    fn sub_assign_vec(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        for (a, b) in izip!(a.iter_mut(), b.iter()) {
            *a -= b;
        }
    }

    async fn mul(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> super::IoResult<Self::ArithmeticShare> {
        Ok(a * b)
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare>,
        domain: &D,
    ) {
        domain.fft_in_place(data);
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare>,
        domain: &D,
    ) {
        domain.ifft_in_place(data);
    }

    fn ifft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        g: P::ScalarField,
        c: P::ScalarField,
    ) {
        let mut pow = c;
        for c in coeffs.iter_mut() {
            *c *= pow;
            pow *= g;
        }
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        P::G1::msm_unchecked(points, scalars)
    }

    fn msm_public_points_g2(
        points: &[P::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG2 {
        P::G2::msm_unchecked(points, scalars)
    }

    fn scalar_mul_public_point_g1(a: &P::G1, b: Self::ArithmeticShare) -> Self::PointShareG1 {
        *a * b
    }

    fn add_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        *a += b;
    }

    fn add_assign_points_public_g1(_: Self::PartyID, a: &mut Self::PointShareG1, b: &P::G1) {
        *a += b;
    }

    async fn open_point_g1(&mut self, a: &Self::PointShareG1) -> super::IoResult<P::G1> {
        Ok(*a)
    }

    async fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> super::IoResult<Self::PointShareG1> {
        Ok(*a * b)
    }

    fn sub_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        *a -= b;
    }

    fn scalar_mul_public_point_g2(a: &P::G2, b: Self::ArithmeticShare) -> Self::PointShareG2 {
        *a * b
    }

    fn add_assign_points_g2(a: &mut Self::PointShareG2, b: &Self::PointShareG2) {
        *a += b;
    }

    fn add_assign_points_public_g2(_: Self::PartyID, a: &mut Self::PointShareG2, b: &P::G2) {
        *a += b;
    }

    async fn open_two_points(
        &mut self,
        a: Self::PointShareG1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(P::G1, P::G2)> {
        Ok((a, b))
    }
}
