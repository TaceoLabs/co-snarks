use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;
use mpc_core::{
    MpcState,
    protocols::rep3::{
        Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, pointshare, poly,
    },
};
use mpc_net::Network;

use super::CircomPlonkProver;

/// A Plonk driver for REP3 secret sharing
pub struct Rep3PlonkDriver;

impl<P: Pairing> CircomPlonkProver<P> for Rep3PlonkDriver {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShareG1 = Rep3PointShare<P::G1>;
    type PointShareG2 = Rep3PointShare<P::G2>;
    type State = Rep3State;

    fn rand<N: Network>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::rand(state))
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_with_public(
        id: <Self::State as MpcState>::PartyID,
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public, id)
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn neg_vec_in_place(vec: &mut [Self::ArithmeticShare]) {
        for a in vec.iter_mut() {
            *a = arithmetic::neg(*a);
        }
    }

    fn mul_with_public(
        shared: Self::ArithmeticShare,
        public: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    fn local_mul_many(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_many::<P::ScalarField>(a, b, state)
    }

    fn io_round_mul_many<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::reshare_vec(a, net)
    }

    fn mul_many<N: Network>(
        lhs: &[Self::ArithmeticShare],
        rhs: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_many(lhs, rhs, net, state)
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
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::mul_open_vec(a, b, net, state)
    }

    fn open_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::open_vec(a, net)
    }

    fn inv_vec<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, net, state)
    }

    fn promote_to_trivial_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        Self::ArithmeticShare::promote_from_trivial(&public_value, id)
    }

    fn fft<D: EvaluationDomain<P::ScalarField>>(
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
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P::G1> {
        pointshare::open_point(&a, net)
    }

    fn open_point_vec_g1<N: Network>(
        a: &[Self::PointShareG1],
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::G1>> {
        pointshare::open_point_many(a, net)
    }

    fn msm_public_points_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShareG1 {
        pointshare::msm_public_points(points, scalars)
    }

    fn evaluate_poly_public(
        coeffs: Vec<Self::ArithmeticShare>,
        point: P::ScalarField,
    ) -> (Self::ArithmeticShare, Vec<Self::ArithmeticShare>) {
        let result = poly::eval_poly(&coeffs, point);
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
            r.push(arithmetic::rand(state));
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
