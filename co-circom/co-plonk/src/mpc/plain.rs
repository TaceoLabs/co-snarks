use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;
use itertools::izip;
use mpc_core::MpcState;
use mpc_net::Network;
use num_traits::Zero;

use super::CircomPlonkProver;
use rand::thread_rng;

/// A plain Plonk driver
pub struct PlainPlonkDriver;

impl<P, C> CircomPlonkProver<P> for PlainPlonkDriver
where
    P: Pairing<G1 = Projective<C>, G1Affine = Affine<C>>,
    C: SWCurveConfig<ScalarField = P::ScalarField>,
{
    type ArithmeticShare = P::ScalarField;

    type PointShareG1 = P::G1;

    type PointShareG2 = P::G2;

    type State = ();

    fn rand<N: Network>(_: &N, _: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn add_with_public(
        _: <Self::State as MpcState>::PartyID,
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        shared + public
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn neg_vec_in_place(a: &mut [Self::ArithmeticShare]) {
        for a in a.iter_mut() {
            *a = -*a;
        }
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        izip!(a, b).map(|(a, b)| *a * *b).collect()
    }

    fn io_round_mul_vec<N: Network>(
        a: Vec<P::ScalarField>,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        Ok(a)
    }

    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        shared * public
    }

    fn mul_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        Ok(izip!(a, b).map(|(a, b)| *a * *b).collect())
    }

    fn mul_vecs<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        Ok(izip!(a, b, c).map(|(a, b, c)| *a * *b * *c).collect())
    }

    fn add_mul_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        Ok(izip!(a, b, c).map(|(a, b, c)| *a + *b * *c).collect())
    }

    fn mul_open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        Ok(izip!(a, b).map(|(a, b)| *a * *b).collect())
    }

    fn open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        Ok(a.to_vec())
    }

    fn inv_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut res = Vec::with_capacity(a.len());
        for a in a {
            if a.is_zero() {
                eyre::bail!("Cannot invert zero");
            }
            res.push(a.inverse().unwrap());
        }
        Ok(res)
    }

    fn promote_to_trivial_share(
        _: <Self::State as MpcState>::PartyID,
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

    fn open_point_g1<N: Network>(
        a: Self::PointShareG1,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P::G1> {
        Ok(a)
    }

    fn open_point_vec_g1<N: Network>(
        a: &[Self::PointShareG1],
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::G1>> {
        Ok(a.to_vec())
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        taceo_ark_algebra::msm::msm_unchecked(points, scalars)
    }

    fn evaluate_poly_public(
        coeffs: Vec<Self::ArithmeticShare>,
        point: P::ScalarField,
    ) -> (Self::ArithmeticShare, Vec<Self::ArithmeticShare>) {
        let poly = DensePolynomial { coeffs };
        let result = poly.evaluate(&point);
        (result, poly.coeffs)
    }

    fn array_prod_mul<N: Network>(
        arr1: &[Self::ArithmeticShare],
        arr2: &[Self::ArithmeticShare],
        arr3: &[Self::ArithmeticShare],
        chunk_size: usize,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        debug_assert_eq!(arr1.len() % chunk_size, 0);
        let mut res = izip!(arr1, arr2, arr3)
            .map(|(a, b, c)| *a * *b * *c)
            .collect::<Vec<_>>();
        for i in 1..res.len() {
            if i % chunk_size != 0 {
                let prev = res[i - 1];
                res[i] *= prev;
            }
        }
        Ok(res)
    }
}
