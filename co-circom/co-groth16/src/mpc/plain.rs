use ark_ec::{pairing::Pairing, CurveGroup};

use super::CircomGroth16Prover;

pub(crate) struct PlainGroth16Driver;

impl<P: Pairing> CircomGroth16Prover<P> for PlainGroth16Driver {
    type ArithmeticShare = P::ScalarField;

    type PointShareG1 = P::G1;

    type PointShareG2 = P::G2;

    type PartyID = usize;

    fn rand(&mut self) -> Self::ArithmeticShare {
        todo!()
    }

    fn get_party_id(&self) -> Self::PartyID {
        //does't matter
        0
    }

    fn fork(&mut self) -> Self {
        todo!()
    }

    fn evaluate_constraint(
        party_id: Self::PartyID,
        lhs: &[(<P as Pairing>::ScalarField, usize)],
        public_inputs: &[<P as Pairing>::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        todo!()
    }

    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[<P as Pairing>::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn sub_assign_vec(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        todo!()
    }

    async fn mul(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> super::IoResult<Self::ArithmeticShare> {
        todo!()
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare>,
        domain: &D,
    ) {
        todo!()
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &mut Vec<Self::ArithmeticShare>,
        domain: &D,
    ) {
        todo!()
    }

    fn ifft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        todo!()
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        g: <P as Pairing>::ScalarField,
        c: <P as Pairing>::ScalarField,
    ) {
        todo!()
    }

    fn msm_public_points_g1(
        points: &[<P as Pairing>::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        todo!()
    }

    fn msm_public_points_g2(
        points: &[<P as Pairing>::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG2 {
        todo!()
    }

    fn scalar_mul_public_point_g1(
        a: &<P as Pairing>::G1,
        b: Self::ArithmeticShare,
    ) -> Self::PointShareG1 {
        todo!()
    }

    fn add_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        todo!()
    }

    fn add_assign_points_public_g1(
        id: Self::PartyID,
        a: &mut Self::PointShareG1,
        b: &<P as Pairing>::G1,
    ) {
        todo!()
    }

    async fn open_point_g1(
        &mut self,
        a: &Self::PointShareG1,
    ) -> super::IoResult<<P as Pairing>::G1> {
        todo!()
    }

    async fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> super::IoResult<Self::PointShareG1> {
        todo!()
    }

    fn sub_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        todo!()
    }

    fn scalar_mul_public_point_g2(
        a: &<P as Pairing>::G2,
        b: Self::ArithmeticShare,
    ) -> Self::PointShareG2 {
        todo!()
    }

    fn add_assign_points_g2(a: &mut Self::PointShareG2, b: &Self::PointShareG2) {
        todo!()
    }

    fn add_assign_points_public_g2(
        id: Self::PartyID,
        a: &mut Self::PointShareG2,
        b: &<P as Pairing>::G2,
    ) {
        todo!()
    }

    async fn open_two_points(
        &mut self,
        a: Self::PointShareG1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(<P as Pairing>::G1, <P as Pairing>::G2)> {
        todo!()
    }
}
