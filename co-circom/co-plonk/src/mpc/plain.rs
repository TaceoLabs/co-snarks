use super::IoResult;
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Polynomial;
use itertools::izip;
use num_traits::Zero;

use super::CircomPlonkProver;
use rand::thread_rng;

pub struct PlainPlonkDriver;

impl<P: Pairing> CircomPlonkProver<P> for PlainPlonkDriver {
    type ArithmeticShare = P::ScalarField;

    type PointShareG1 = P::G1;

    type PointShareG2 = P::G2;

    //doesn't matter
    type PartyID = usize;

    fn debug_print(a: Self::ArithmeticShare) {
        println!("{a}")
    }

    async fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn get_party_id(&self) -> Self::PartyID {
        //doesn't matter
        0
    }

    async fn fork(&mut self) -> IoResult<Self> {
        Ok(PlainPlonkDriver)
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn add_with_public(
        _: Self::PartyID,
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        shared + public
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn neg_vec_in_place(&mut self, a: &mut [Self::ArithmeticShare]) {
        #[allow(unused_mut)]
        for mut a in a.iter_mut() {
            *a = -*a;
        }
    }

    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        shared * public
    }

    async fn mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        Ok(izip!(a, b).map(|(a, b)| *a * *b).collect())
    }

    async fn mul_vecs(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        Ok(izip!(a, b, c).map(|(a, b, c)| *a * *b * *c).collect())
    }

    async fn add_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        Ok(izip!(a, b, c).map(|(a, b, c)| *a + *b * *c).collect())
    }

    async fn mul_open_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<P::ScalarField>> {
        Ok(izip!(a, b).map(|(a, b)| *a * *b).collect())
    }

    async fn open_vec(&mut self, a: &[Self::ArithmeticShare]) -> IoResult<Vec<P::ScalarField>> {
        Ok(a.to_vec())
    }

    async fn inv_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> IoResult<Vec<Self::ArithmeticShare>> {
        let mut res = Vec::with_capacity(a.len());
        for a in a {
            if a.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot invert zero",
                ));
            }
            res.push(a.inverse().unwrap());
        }
        Ok(res)
    }

    fn promote_to_trivial_share(
        _: Self::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        public_value
    }

    fn fft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(data)
    }

    fn ifft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }

    async fn open_point_g1(&mut self, a: Self::PointShareG1) -> IoResult<P::G1> {
        Ok(a)
    }

    async fn open_point_vec_g1(&mut self, a: &[Self::PointShareG1]) -> IoResult<Vec<P::G1>> {
        Ok(a.to_vec())
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        P::G1::msm_unchecked(points, scalars)
    }

    fn evaluate_poly_public(
        coeffs: Vec<Self::ArithmeticShare>,
        point: P::ScalarField,
    ) -> (Self::ArithmeticShare, Vec<Self::ArithmeticShare>) {
        let poly = DensePolynomial { coeffs };
        let result = poly.evaluate(&point);
        (result, poly.coeffs)
    }
}
