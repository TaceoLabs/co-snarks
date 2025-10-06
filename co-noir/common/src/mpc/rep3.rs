use super::NoirUltraHonkProver;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_ff::{Field, Zero};
use itertools::izip;
use mpc_core::{
    MpcState,
    protocols::rep3::{
        Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, id::PartyID, pointshare, poly,
    },
};
use mpc_net::Network;
use rayon::prelude::*;
#[derive(Debug)]
pub struct Rep3UltraHonkDriver;

impl<P: CurveGroup<BaseField: PrimeField>> NoirUltraHonkProver<P> for Rep3UltraHonkDriver {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShare = Rep3PointShare<P>;
    type State = Rep3State;

    fn rand<N: Network>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::rand(state))
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn sub_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        arithmetic::sub_assign(a, b);
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        arithmetic::sub_vec_assign(a, b);
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        arithmetic::add_assign(a, b);
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    ) {
        arithmetic::add_assign_public(a, b, id);
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::neg(a)
    }

    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField) {
        arithmetic::mul_assign_public(shared, public);
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    ) {
        if id == PartyID::ID0 {
            *share += public
        }
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        public * shared.a
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(a, b, state)
    }

    fn reshare<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::reshare_vec(a, net)
    }

    fn mul<N: Network>(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        arithmetic::mul_vec(&[a], &[b], net, state).map(|v| v[0])
    }

    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_vec(a, b, net, state)
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        id: <Self::State as MpcState>::PartyID,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public, id)
    }

    fn promote_to_trivial_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(id, public_value)
    }

    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn open_point<N: Network>(
        a: Self::PointShare,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P> {
        pointshare::open_point(&a, net)
    }

    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        pointshare::open_point_many(a, net)
    }

    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::open_vec(a, net)
    }

    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)> {
        pointshare::open_point_and_field(&a, &b, net)
    }

    fn open_point_and_field_many<N: Network>(
        a: &[Self::PointShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(Vec<P>, Vec<<P>::ScalarField>)> {
        pointshare::open_point_and_field_many(a, b, net)
    }

    fn mul_open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::mul_open_vec(a, b, net, state)
    }

    fn inv_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, net, state)
    }

    fn inv_many_in_place<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()> {
        let r = (0..a.len())
            .map(|_| <Self as NoirUltraHonkProver<P>>::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let y: Vec<P::ScalarField> =
            <Self as NoirUltraHonkProver<P>>::mul_open_many(a, &r, net, state)?;

        if y.iter().any(|y| y.is_zero()) {
            eyre::bail!("Cannot compute inverse of zero",);
        }
        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            *a = r * y.inverse().unwrap();
        }

        Ok(())
    }

    fn inv_many_in_place_leaking_zeros<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()> {
        let r = (0..a.len())
            .map(|_| <Self as NoirUltraHonkProver<P>>::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let y: Vec<P::ScalarField> =
            <Self as NoirUltraHonkProver<P>>::mul_open_many(a, &r, net, state)?;

        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            if y.is_zero() {
                *a = Self::ArithmeticShare::default();
            } else {
                *a = r * y.inverse().unwrap();
            }
        }

        Ok(())
    }

    fn msm_public_points(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        pointshare::msm_public_points(points, scalars)
    }

    fn point_add(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        pointshare::add(a, b)
    }

    fn eval_poly(coeffs: &[Self::ArithmeticShare], point: P::ScalarField) -> Self::ArithmeticShare {
        poly::eval_poly(coeffs, point)
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
    fn is_zero_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let zeroes = vec![P::ScalarField::zero(); a.len()];
        arithmetic::eq_public_many(a, &zeroes, net, state)
    }

    fn promote_to_trivial_point_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P,
    ) -> Self::PointShare {
        pointshare::promote_to_trivial_share(id, &public_value)
    }

    fn point_sub(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        pointshare::sub(a, b)
    }

    fn scalar_mul_public_point(a: &P, b: Self::ArithmeticShare) -> Self::PointShare {
        pointshare::scalar_mul_public_point(a, b)
    }
}
