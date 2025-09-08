use super::NoirUltraHonkProver;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use itertools::izip;
use mpc_core::{
    MpcState,
    protocols::rep3::{
        Rep3BigUintShare, Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, conversion,
        id::PartyID, pointshare, poly, yao,
    },
};
use mpc_net::Network;
use num_bigint::BigUint;
use num_traits::Zero;
use rayon::prelude::*;

pub struct Rep3UltraHonkDriver;

impl<P: CurveGroup<BaseField: PrimeField>> NoirUltraHonkProver<P> for Rep3UltraHonkDriver {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type BaseFieldArithmeticShare = Rep3PrimeFieldShare<P::BaseField>;
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

    /// Add two point shares: \[c\] = \[a\] + \[b\]
    fn add_point(a: &mut Self::PointShare, b: Self::PointShare) {
        unimplemented!()
    }

    /// Add two point shares: \[c\] = \[a\] + \[b\] and stores the result in \[a\].
    fn add_point_assign(a: &mut Self::PointShare, b: Self::PointShare) {
        unimplemented!()
    }

    /// Multiply a shared point by a shared field element: \[c\] = \[a\] * b.
    fn mul_point_and_scalar<N: Network>(
        point: Self::PointShare,
        field: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::PointShare> {
        unimplemented!()
    }

    fn is_zero_point<N: Network>(
        x: Self::PointShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        unimplemented!()
    }

    fn point_share_to_fieldshares<N: Network>(
        x: Self::PointShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(
        Self::BaseFieldArithmeticShare,
        Self::BaseFieldArithmeticShare,
        Self::BaseFieldArithmeticShare,
    )> {
        conversion::point_share_to_fieldshares(x, net, state)
    }

    fn slice<N: Network>(
        input: Self::BaseFieldArithmeticShare,
        msb: usize,
        lsb: usize,
        bitsize: usize,
        state: &mut Self::State,
        net: &N,
    ) -> eyre::Result<Vec<Self::BaseFieldArithmeticShare>> {
        unimplemented!()
    }

    fn decompose_arithmetic<N: Network>(
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        yao::decompose_arithmetic(
            input,
            net,
            state,
            total_bit_size_per_field,
            decompose_bit_size,
        )
    }

    fn cmux<N: Network>(
        cond: Self::ArithmeticShare,
        truthy: Self::ArithmeticShare,
        falsy: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let b_min_a = <Self as NoirUltraHonkProver<P>>::sub(truthy, falsy.clone());
        let d = <Self as NoirUltraHonkProver<P>>::mul(cond.into(), b_min_a, net, state)?;
        Ok(<Self as NoirUltraHonkProver<P>>::add(falsy, d))
    }

    // TODO CESAR
    fn le_public<N: Network>(
        lhs: Self::ArithmeticShare,
        rhs: P::ScalarField,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        arithmetic::le_public(lhs, rhs, net, state)
    }

    // TODO TACEO: Currently the implementation only works for LIMB_BITS = 136
    fn base_field_share_to_field_shares<N: Network, const LIMB_BITS: usize>(
        x: Self::BaseFieldArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        assert_eq!(
            LIMB_BITS, 136,
            "Only LIMB_BITS = 136 is supported, i.e. two Bn254::Fr elements per Bn254::Fq element"
        );
        let bin_share = conversion::a2b(x, net, state).unwrap();
        let low: Rep3BigUintShare<P::BaseField> =
            bin_share.clone() & ((BigUint::from(1u8) << LIMB_BITS) - BigUint::from(1u8));
        let high: Rep3BigUintShare<P::BaseField> = bin_share >> LIMB_BITS;

        let low = Rep3BigUintShare::new(low.a.clone(), low.b.clone());
        let high = Rep3BigUintShare::new(high.a.clone(), high.b.clone());

        Ok(vec![
            conversion::b2a(&low, net, state).unwrap(),
            conversion::b2a(&high, net, state).unwrap(),
        ])
    }
}
