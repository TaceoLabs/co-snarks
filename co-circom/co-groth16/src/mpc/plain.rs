use ark_ec::{pairing::Pairing, CurveGroup};

use super::CircomGroth16Prover;

pub(crate) struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver {
    type ArithmeticShare<F: ark_ff::PrimeField> = F;

    type PointShare<C: CurveGroup> = C;

    type PartyID = usize;

    fn rand(&mut self) -> Self::ArithmeticShare<<P as Pairing>::ScalarField> {
        todo!()
    }

    fn get_party_id(&self) -> Self::PartyID {
        todo!()
    }

    fn fork(&mut self) -> Self {
        todo!()
    }

    fn evaluate_constraint(
        party_id: &Self::PartyID,
        lhs: &[(<P as Pairing>::ScalarField, usize)],
        public_inputs: &[<P as Pairing>::ScalarField],
        private_witness: &[Self::ArithmeticShare<<P as Pairing>::ScalarField>],
    ) -> Self::ArithmeticShare<<P as Pairing>::ScalarField> {
        todo!()
    }

    fn promote_to_trivial_shares(
        id: &Self::PartyID,
        public_values: &[<P as Pairing>::ScalarField],
    ) -> Vec<Self::ArithmeticShare<<P as Pairing>::ScalarField>> {
        todo!()
    }

    fn sub_assign_vec(
        a: &mut [Self::ArithmeticShare<<P as Pairing>::ScalarField>],
        b: &[Self::ArithmeticShare<<P as Pairing>::ScalarField>],
    ) {
        todo!()
    }

    async fn mul(
        &mut self,
        a: Self::ArithmeticShare<<P as Pairing>::ScalarField>,
        b: Self::ArithmeticShare<<P as Pairing>::ScalarField>,
    ) -> super::IoResult<Self::ArithmeticShare<<P as Pairing>::ScalarField>> {
        todo!()
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare<<P as Pairing>::ScalarField>],
        b: &[Self::ArithmeticShare<<P as Pairing>::ScalarField>],
    ) -> super::IoResult<Vec<Self::ArithmeticShare<<P as Pairing>::ScalarField>>> {
        todo!()
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare<<P as Pairing>::ScalarField>>,
        domain: &D,
    ) {
        todo!()
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare<<P as Pairing>::ScalarField>>,
        domain: &D,
    ) {
        todo!()
    }

    fn ifft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare<<P as Pairing>::ScalarField>],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare<<P as Pairing>::ScalarField>> {
        todo!()
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare<<P as Pairing>::ScalarField>],
        g: <P as Pairing>::ScalarField,
        c: <P as Pairing>::ScalarField,
    ) {
        todo!()
    }

    fn msm_public_points<C: CurveGroup>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare<C::ScalarField>],
    ) -> Self::PointShare<C> {
        todo!()
    }

    fn add_assign_points_public<C: CurveGroup>(&mut self, a: &mut Self::PointShare<C>, b: &C) {
        todo!()
    }

    fn add_assign_points_public_affine<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &C::Affine,
    ) {
        todo!()
    }

    fn add_assign_points<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &Self::PointShare<C>,
    ) {
        todo!()
    }

    fn scalar_mul_public_point<C: CurveGroup>(
        &mut self,
        a: &C,
        b: &Self::ArithmeticShare<C::ScalarField>,
    ) -> Self::PointShare<C> {
        todo!()
    }

    async fn open_point<C: CurveGroup>(&mut self, a: &Self::PointShare<C>) -> super::IoResult<C> {
        todo!()
    }

    async fn scalar_mul<C: CurveGroup>(
        &mut self,
        a: &Self::PointShare<C>,
        b: &Self::ArithmeticShare<C::ScalarField>,
    ) -> super::IoResult<Self::PointShare<C>> {
        todo!()
    }

    fn sub_assign_points<C: CurveGroup>(
        &mut self,
        a: &mut Self::PointShare<C>,
        b: &Self::PointShare<C>,
    ) {
        todo!()
    }

    fn open_two_points<C1: CurveGroup, C2: CurveGroup>(
        &mut self,
        a: Self::PointShare<C1>,
        b: Self::PointShare<C2>,
    ) -> std::io::Result<(C1, C2)> {
        todo!()
    }
}
