use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;

use mpc_core::MpcState;
use mpc_core::protocols::shamir::network::ShamirNetworkExt;
use mpc_core::protocols::shamir::{
    ShamirPointShare, ShamirPrimeFieldShare, ShamirState, arithmetic, pointshare,
};
use mpc_net::Network;

use super::CircomPlonkProver;

/// A Plonk driver using shamir secret sharing
pub struct ShamirPlonkDriver;

impl<P: Pairing> CircomPlonkProver<P> for ShamirPlonkDriver {
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type PointShareG1 = ShamirPointShare<P::G1>;
    type PointShareG2 = ShamirPointShare<P::G2>;
    type State = ShamirState<P::ScalarField>;

    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        state.rand(net)
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_with_public(
        _: <Self::State as MpcState>::PartyID,
        shared: Self::ArithmeticShare,
        public: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public)
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn neg_vec_in_place(a: &mut [Self::ArithmeticShare]) {
        for a in a.iter_mut() {
            *a = arithmetic::neg(*a);
        }
    }

    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    fn local_mul_many(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_many(a, b)
    }

    fn io_round_mul_many<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        net.degree_reduce_many(state, a)
    }

    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_many(a, b, net, state)
    }

    fn mul_many_pairs<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let tmp = arithmetic::mul_many(a, b, net, state)?;
        arithmetic::mul_many(&tmp, c, net, state)
    }

    fn add_mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        c: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut result = arithmetic::mul_many(b, c, net, state)?;
        arithmetic::add_many_assign(&mut result, a);
        Ok(result)
    }

    fn mul_open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<<P as Pairing>::ScalarField>> {
        arithmetic::mul_open_vec(a, b, net, state)
    }

    fn open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<<P as Pairing>::ScalarField>> {
        arithmetic::open_vec(a, net, state)
    }

    fn inv_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, net, state)
    }

    fn promote_to_trivial_share(
        _: <Self::State as MpcState>::PartyID,
        public_value: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(public_value)
    }

    fn fft<D: EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(data)
    }

    fn ifft<D: EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }

    fn open_point_g1<N: Network>(
        a: Self::PointShareG1,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<<P as Pairing>::G1> {
        pointshare::open_point(&a, net, state)
    }

    fn open_point_vec_g1<N: Network>(
        a: &[Self::PointShareG1],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<<P as Pairing>::G1>> {
        pointshare::open_point_many(a, net, state)
    }

    fn msm_public_points_g1(
        points: &[<P as Pairing>::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        pointshare::msm_public_points(points, scalars)
    }

    fn evaluate_poly_public(
        coeffs: Vec<Self::ArithmeticShare>,
        point: P::ScalarField,
    ) -> (Self::ArithmeticShare, Vec<Self::ArithmeticShare>) {
        let poly = DensePolynomial {
            coeffs: Self::ArithmeticShare::convert_vec(coeffs),
        };
        let result = Self::ArithmeticShare::new(poly.evaluate(&point));
        let coeffs = Self::ArithmeticShare::convert_vec_rev(poly.coeffs);
        (result, coeffs)
    }

    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    // TODO parallelize these? With a different network structure this might not be needed though
    fn array_prod_mul<N: Network>(
        inv: bool,
        arr1: &[Self::ArithmeticShare],
        arr2: &[Self::ArithmeticShare],
        arr3: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let arr = arithmetic::mul_many(arr1, arr2, net, state)?;
        let arr = arithmetic::mul_many(&arr, arr3, net, state)?;
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let len = arr.len();

        let mut r = Vec::with_capacity(len + 1);
        for _ in 0..=len {
            r.push(state.rand(net)?);
        }
        let r_inv = arithmetic::inv_vec(&r, net, state)?;
        let r_inv0 = vec![r_inv[0]; len];
        let mut unblind = arithmetic::mul_many(&r_inv0, &r[1..], net, state)?;

        let mul = arithmetic::mul_many(&r[..len], &arr, net, state)?;
        let mut open = arithmetic::mul_open_vec(&mul, &r_inv[1..], net, state)?;

        for i in 1..open.len() {
            open[i] = open[i] * open[i - 1];
        }

        for (unblind, open) in unblind.iter_mut().zip(open.into_iter()) {
            *unblind = arithmetic::mul_public(*unblind, open);
        }
        if inv {
            Ok(arithmetic::inv_vec(&unblind, net, state)?)
        } else {
            Ok(unblind)
        }
    }
}
