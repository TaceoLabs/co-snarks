use super::NoirUltraHonkProver;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::PrimeField;
use itertools::izip;
use mpc_core::MpcState;
use mpc_core::protocols::shamir::ShamirState;
use mpc_core::protocols::shamir::network::ShamirNetworkExt;
use mpc_core::protocols::shamir::{
    ShamirPointShare, ShamirPrimeFieldShare, arithmetic, pointshare, poly,
};
use mpc_net::Network;
use num_traits::Zero;
use rayon::prelude::*;

/// A UltraHonk driver using shamir secret sharing
pub struct ShamirUltraHonkDriver;

impl<P: CurveGroup<BaseField: PrimeField>> NoirUltraHonkProver<P> for ShamirUltraHonkDriver {
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type BaseFieldArithmeticShare = ShamirPrimeFieldShare<P::BaseField>;
    type PointShare = ShamirPointShare<P>;
    type BinaryShare = ();
    type State = ShamirState<P::ScalarField>;

    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        state.rand(net)
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
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
        _id: <Self::State as MpcState>::PartyID,
    ) {
        arithmetic::add_assign_public(a, b);
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
        arithmetic::mul_assign_public(shared, public)
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        _id: <Self::State as MpcState>::PartyID,
    ) {
        *share += public
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        public * shared.inner()
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(a, b)
    }

    fn reshare<N: Network>(
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
        arithmetic::mul_vec(a, b, net, state)
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        _id: <Self::State as MpcState>::PartyID,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public)
    }

    fn promote_to_trivial_share(
        _id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(public_value)
    }

    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| <Self as NoirUltraHonkProver<P>>::promote_to_trivial_share(id, *value))
            .collect()
    }

    fn open_point<N: Network>(
        a: Self::PointShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<P> {
        pointshare::open_point(&a, net, state)
    }

    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        pointshare::open_point_many(a, net, state)
    }

    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::open_vec(a, net, state)
    }

    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)> {
        pointshare::open_point_and_field(&a, &b, net, state)
    }

    fn open_point_and_field_many<N: Network>(
        _a: &[Self::PointShare],
        _b: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(Vec<P>, Vec<<P>::ScalarField>)> {
        todo!("implement open_point_and_field_many for ShamirUltraHonkDriver")
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
            eyre::bail!("Cannot compute inverse of zero");
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
        _a: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        panic!("ShamirUltraHonkDriver does not support is_zero_many");
    }

    fn promote_to_trivial_point_share(
        _id: <Self::State as MpcState>::PartyID,
        public_value: P,
    ) -> Self::PointShare {
        pointshare::promote_to_trivial_share(&public_value)
    }

    fn point_is_zero_many<N: Network>(
        _a: &[Self::PointShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::BaseFieldArithmeticShare>> {
        panic!("ShamirUltraHonkDriver does not support point_is_zero_many");
    }

    fn is_zero_many_basefield<N: Network>(
        _a: &[Self::BaseFieldArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::BaseFieldArithmeticShare>> {
        panic!("ShamirUltraHonkDriver does not support is_zero_many");
    }

    fn mul_assign_with_public_basefield(
        shared: &mut Self::BaseFieldArithmeticShare,
        public: <P as CurveGroup>::BaseField,
    ) {
        arithmetic::mul_assign_public(shared, public)
    }

    fn add_assign_public_basefield(
        a: &mut Self::BaseFieldArithmeticShare,
        b: <P as CurveGroup>::BaseField,
        id: <Self::State as MpcState>::PartyID,
    ) {
        arithmetic::add_assign_public(a, b);
    }

    fn add_basefield(
        a: Self::BaseFieldArithmeticShare,
        b: Self::BaseFieldArithmeticShare,
    ) -> Self::BaseFieldArithmeticShare {
        arithmetic::add(a, b)
    }

    fn mul_many_basefield<N: Network>(
        a: &[Self::BaseFieldArithmeticShare],
        b: &[Self::BaseFieldArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::BaseFieldArithmeticShare>> {
        todo!()
        // arithmetic::mul_vec(a, b, net, state)
    }

    fn sub_basefield(
        a: Self::BaseFieldArithmeticShare,
        b: Self::BaseFieldArithmeticShare,
    ) -> Self::BaseFieldArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn scalar_mul<N: Network>(
        a: &Self::PointShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> Self::PointShare {
        todo!()
    }

    fn promote_to_trivial_share_basefield(
        id: <Self::State as MpcState>::PartyID,
        public_value: <P as CurveGroup>::BaseField,
    ) -> Self::BaseFieldArithmeticShare {
        todo!()
    }

    fn scalar_mul_many<N: Network>(
        a: &[Self::PointShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> Vec<Self::PointShare> {
        todo!()
    }

    fn convert_fields(
        a: &[Self::BaseFieldArithmeticShare],
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        todo!()
    }

    fn point_sub(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        todo!()
    }

    fn mul_with_public_basefield(
        public: <P as CurveGroup>::BaseField,
        shared: Self::BaseFieldArithmeticShare,
    ) -> Self::BaseFieldArithmeticShare {
        todo!()
    }

    fn pointshare_to_field_shares<N: Network>(
        point: Self::PointShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(
        Self::BaseFieldArithmeticShare,
        Self::BaseFieldArithmeticShare,
        Self::BaseFieldArithmeticShare,
    )> {
        todo!()
    }

    fn pointshare_to_field_shares_many<N: Network>(
        point: &[Self::PointShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(
        Vec<Self::BaseFieldArithmeticShare>,
        Vec<Self::BaseFieldArithmeticShare>,
        Vec<Self::BaseFieldArithmeticShare>,
    )> {
        todo!()
    }

    fn cmux<N: Network>(
        cond: Self::ArithmeticShare,
        truthy: Self::ArithmeticShare,
        falsy: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        todo!()
    }

    fn add_with_public_basefield(
        public: <P as CurveGroup>::BaseField,
        shared: Self::BaseFieldArithmeticShare,
        id: <Self::State as MpcState>::PartyID,
    ) -> Self::BaseFieldArithmeticShare {
        todo!()
    }

    // fn is_zero_binary_many<N: Network>(
    //     _a: &[Self::BinaryShare],
    //     _net: &N,
    //     _state: &mut Self::State,
    // ) -> eyre::Result<Vec<Self::BinaryShare>> {
    //     panic!("ShamirUltraHonkDriver does not support binary shares");
    // }
}
