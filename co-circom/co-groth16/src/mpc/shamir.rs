use super::{CircomGroth16Prover, IoResult};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use mpc_core::protocols::shamir::{
    arithmetic, core, network::ShamirNetwork, pointshare, ShamirPointShare, ShamirPrimeFieldShare,
    ShamirProtocol,
};

pub struct ShamirGroth16Driver<F: PrimeField, N: ShamirNetwork> {
    protocol: ShamirProtocol<F, N>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirGroth16Driver<F, N> {
    pub fn new(protocol: ShamirProtocol<F, N>) -> Self {
        Self { protocol }
    }

    pub(crate) fn into_network(self) -> N {
        self.protocol.network
    }
}

impl<P: Pairing, N: ShamirNetwork> CircomGroth16Prover<P>
    for ShamirGroth16Driver<P::ScalarField, N>
{
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type PointShareG1 = ShamirPointShare<P::G1>;
    type PointShareG2 = ShamirPointShare<P::G2>;

    type PartyID = usize;

    async fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        self.protocol.rand().await
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.protocol.network.get_id()
    }

    async fn fork(&mut self) -> IoResult<Self> {
        Ok(Self {
            protocol: self.protocol.fork().await?,
        })
    }

    fn evaluate_constraint(
        _party_id: Self::PartyID,
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

    fn promote_to_trivial_shares(
        _id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        arithmetic::promote_to_trivial_shares(public_values)
    }

    async fn mul(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        arithmetic::mul(a, b, &mut self.protocol).await
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_vec(a, b, &mut self.protocol).await
    }

    fn local_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(a, b)
    }

    async fn io_round_mul_vec(
        &mut self,
        a: Vec<P::ScalarField>,
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        self.protocol.degree_reduce_vec(a).await
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        g: P::ScalarField,
        c: P::ScalarField,
    ) {
        let mut pow = c;
        for share in coeffs.iter_mut() {
            arithmetic::mul_assign_public(share, pow);
            pow *= g;
        }
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        pointshare::msm_public_points(points, scalars)
    }

    fn msm_public_points_g2(
        points: &[P::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG2 {
        pointshare::msm_public_points(points, scalars)
    }

    fn scalar_mul_public_point_g1(a: &P::G1, b: Self::ArithmeticShare) -> Self::PointShareG1 {
        pointshare::scalar_mul_public_point(b, a)
    }

    fn add_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        pointshare::add_assign(a, b)
    }

    fn add_assign_points_public_g1(_id: Self::PartyID, a: &mut Self::PointShareG1, b: &P::G1) {
        pointshare::add_assign_public(a, b)
    }

    async fn open_point_g1(&mut self, a: &Self::PointShareG1) -> IoResult<P::G1> {
        pointshare::open_point(a, &mut self.protocol).await
    }

    async fn scalar_mul_g1(
        &mut self,
        a: &Self::PointShareG1,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShareG1> {
        pointshare::scalar_mul(a, b, &mut self.protocol).await
    }

    fn sub_assign_points_g1(a: &mut Self::PointShareG1, b: &Self::PointShareG1) {
        pointshare::sub_assign(a, b);
    }

    fn scalar_mul_public_point_g2(a: &P::G2, b: Self::ArithmeticShare) -> Self::PointShareG2 {
        pointshare::scalar_mul_public_point(b, a)
    }

    fn add_assign_points_g2(a: &mut Self::PointShareG2, b: &Self::PointShareG2) {
        pointshare::add_assign(a, b)
    }

    fn add_assign_points_public_g2(_id: Self::PartyID, a: &mut Self::PointShareG2, b: &P::G2) {
        pointshare::add_assign_public(a, b)
    }

    async fn open_two_points(
        &mut self,
        a: Self::PointShareG1,
        b: Self::PointShareG2,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a.a;
        let s2 = b.a;

        let rcv: Vec<(P::G1, P::G2)> = self
            .protocol
            .network
            .broadcast_next((s1, s2), self.protocol.threshold + 1)
            .await?;
        let (r1, r2): (Vec<P::G1>, Vec<P::G2>) = rcv.into_iter().unzip();

        let r1 = core::reconstruct_point(&r1, &self.protocol.open_lagrange_t);
        let r2 = core::reconstruct_point(&r2, &self.protocol.open_lagrange_t);

        Ok((r1, r2))
    }
}
