use ark_ec::{pairing::Pairing, CurveGroup};
use mpc_core::protocols::{
    rep3::network::Rep3Network,
    rep3new::{self, network::IoContext, point::types::Rep3PointShare, Rep3PrimeFieldShare},
};
use tokio::runtime;

use super::CircomGroth16Prover;

pub(crate) struct Rep3Groth16Driver<N: Rep3Network> {
    io_context: IoContext<N>,
    runtime: Runtime,
}

impl<N: Rep3Network> Rep3Groth16Driver<N> {
    pub fn new(network: N) -> std::io::Result<Self> {
        Ok(Self {
            io_context: IoContext::init(network)?,
            runtime: runtime::Builder::new_current_thread().build()?,
        })
    }
}

impl<P: Pairing, N: Rep3Network> CircomGroth16Prover<P> for Rep3Groth16Driver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;

    type PointShare<C: CurveGroup> = Rep3PointShare<C>;

    fn rand(&self) -> Self::ArithmeticShare {
        let (a, b) = self.rngs.rand.random_fes();
        Ok(Self::ArithmeticShare::new(a, b))
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Rep3PrimeFieldShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                acc = self.add_with_public(&mul_result, &acc);
            } else {
                acc.a += *coeff * private_witness.a[*index - public_inputs.len()];
                acc.b += *coeff * private_witness.b[*index - public_inputs.len()];
            }
        }
        acc
    }

    fn promote_to_trivial_shares(
        &self,
        _public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        Self::ArithmeticShare::promote_from_trivial(&public_value, self.network.get_id())
    }

    fn sub_assign_vec(&mut self, a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        for (a, b) in izip!(a.a.iter_mut(), &b.a) {
            *a -= b;
        }
        for (a, b) in izip!(a.b.iter_mut(), &b.b) {
            *a -= b;
        }
    }

    async fn mul(
        &mut self,
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        rep3new::arithmetic::mul(a, b, io_context)
    }

    async fn mul_vec(
        &mut self,
        _a: &[Self::ArithmeticShare],
        _b: &[Self::ArithmeticShare],
    ) -> super::IoResult<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        &mut self,
        _data: &mut [Self::ArithmeticShare],
        _domain: &D,
    ) {
        todo!()
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        &mut self,
        _data: &mut [Self::ArithmeticShare],
        _domain: &D,
    ) {
        todo!()
    }

    fn distribute_powers_and_mul_by_const(
        &mut self,
        _coeffs: &mut [Self::ArithmeticShare],
        _g: P::ScalarField,
        _c: P::ScalarField,
    ) {
        todo!()
    }

    fn msm_public_points<C: CurveGroup>(
        &mut self,
        _points: &[C::Affine],
        _scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C> {
        todo!()
    }

    fn add_assign_points_public<C: CurveGroup>(&mut self, _a: &mut Self::PointShare<C>, _b: &C) {
        todo!()
    }

    fn add_assign_points_public_affine<C: CurveGroup>(
        &mut self,
        _a: &mut Self::PointShare<C>,
        _b: &C::Affine,
    ) {
        todo!()
    }

    fn add_assign_points<C: CurveGroup>(
        &mut self,
        _a: &mut Self::PointShare<C>,
        _b: &Self::PointShare<C>,
    ) {
        todo!()
    }

    fn scalar_mul_public_point<C: CurveGroup>(
        &mut self,
        _a: &C,
        _b: &Self::ArithmeticShare,
    ) -> Self::PointShare<C> {
        todo!()
    }

    async fn open_point<C: CurveGroup>(&mut self, _a: &Self::PointShare<C>) -> super::IoResult<C> {
        todo!()
    }

    async fn scalar_mul<C: CurveGroup>(
        &mut self,
        _a: &Self::PointShare<C>,
        _b: &Self::ArithmeticShare,
    ) -> super::IoResult<Self::PointShare<C>> {
        todo!()
    }

    fn sub_assign_points<C: CurveGroup>(
        &mut self,
        _a: &mut Self::PointShare<C>,
        _b: &Self::PointShare<C>,
    ) {
        todo!()
    }

    fn open_two_points<C1: CurveGroup, C2: CurveGroup>(
        &mut self,
        _a: Self::PointShare<C1>,
        _b: Self::PointShare<C2>,
    ) -> std::io::Result<(C1, C2)> {
        todo!()
    }
}
