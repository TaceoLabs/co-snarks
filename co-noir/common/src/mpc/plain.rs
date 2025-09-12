use super::NoirUltraHonkProver;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::UniformRand;
use ark_poly::DenseUVPolynomial;
use ark_poly::{Polynomial, univariate::DensePolynomial};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::thread_rng;
use rayon::prelude::*;

pub struct PlainUltraHonkDriver;

impl<P: CurveGroup> NoirUltraHonkProver<P> for PlainUltraHonkDriver {
    type ArithmeticShare = P::ScalarField;
    type BaseFieldArithmeticShare = P::BaseField;
    type PointShare = P;
    type State = ();

    fn debug(ele: Self::ArithmeticShare) -> String {
        if ele.is_zero() {
            "0".to_string()
        } else {
            ele.to_string()
        }
    }

    fn rand<N: Network>(_: &N, _: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn sub_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a -= b;
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        debug_assert_eq!(a.len(), b.len());
        a.par_iter_mut().zip(b.par_iter()).for_each(|(a, b)| {
            *a -= b;
        })
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a += b;
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: P::ScalarField,
        _id: <Self::State as MpcState>::PartyID,
    ) {
        *a += b;
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        -a
    }

    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        shared * public
    }

    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField) {
        *shared *= public;
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
        <Self as NoirUltraHonkProver<P>>::mul_with_public(public, shared)
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        debug_assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect()
    }

    fn reshare<N: Network>(
        a: Vec<P::ScalarField>,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        Ok(a)
    }

    fn mul<N: Network>(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a * b)
    }

    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        debug_assert_eq!(a.len(), b.len());
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        _id: <Self::State as MpcState>::PartyID,
    ) -> Self::ArithmeticShare {
        shared + public
    }

    fn promote_to_trivial_share(
        _id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        public_value
    }

    fn promote_to_trivial_shares(
        _id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn open_point<N: Network>(
        a: Self::PointShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<P> {
        Ok(a)
    }

    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        Ok(a.to_vec())
    }

    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        Ok(a.to_vec())
    }

    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)> {
        Ok((a, b))
    }

    fn mul_open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        debug_assert_eq!(a.len(), b.len());
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn inv_many<N: Network>(
        a: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
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

    fn inv_many_in_place<N: Network>(
        a: &mut [Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<()> {
        for a in a.iter_mut() {
            if a.is_zero() {
                eyre::bail!("Cannot invert zero");
            }
            a.inverse_in_place().unwrap();
        }
        Ok(())
    }

    fn inv_many_in_place_leaking_zeros<N: Network>(
        a: &mut [Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<()> {
        for a in a.iter_mut() {
            if !a.is_zero() {
                a.inverse_in_place().unwrap();
            }
        }
        Ok(())
    }

    fn msm_public_points(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        P::msm_unchecked(points, scalars)
    }

    fn eval_poly(coeffs: &[Self::ArithmeticShare], point: P::ScalarField) -> Self::ArithmeticShare {
        // TACEO TODO: here we clone...
        let poly = DensePolynomial::from_coefficients_slice(coeffs);
        poly.evaluate(&point)
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
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut res = Vec::with_capacity(a.len());
        for a in a {
            if a.is_zero() {
                res.push(Self::ArithmeticShare::one());
            } else {
                res.push(Self::ArithmeticShare::zero());
            }
        }
        Ok(res)
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    // Checks if a point share is zero and returns the result as a field share.
    fn is_point_at_infinity_many<N: Network>(
        _points: &[Self::PointShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        unimplemented!()
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    /// Add two point shares: \[c\] = \[a\] + \[b\] and stores the result in \[a\].
    fn add_point_assign(a: &mut Self::PointShare, b: Self::PointShare) {
        *a += &b;
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    /// Multiply a shared point by a shared field element: \[c\] = \[a\] * b.
    fn mul_point_and_scalar<N: Network>(
        point: Self::PointShare,
        field: Self::ArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Self::PointShare> {
        Ok(point * field)
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    /// Given a point share \[P\] returns the shared x and y coordinates, as well as the
    /// point at infinity as base field shares.
    fn point_share_to_fieldshares<N: Network>(
        x: Self::PointShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(
        Self::BaseFieldArithmeticShare,
        Self::BaseFieldArithmeticShare,
        Self::BaseFieldArithmeticShare,
    )> {
        let (x, y, point_at_infinity) = match x.into_affine().xy() {
            Some((x, y)) => (x, y, Self::BaseFieldArithmeticShare::zero()),
            None => (
                Self::BaseFieldArithmeticShare::zero(),
                Self::BaseFieldArithmeticShare::zero(),
                Self::BaseFieldArithmeticShare::one(),
            ),
        };
        Ok((x, y, point_at_infinity))
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    /// Decomposes a shared field element into chunks, which are also represented as shared
    /// field elements. Per field element, the total bit size of the shared chunks is given
    /// by total_bit_size_per_field, whereas each chunk has at most (i.e, the last chunk can
    /// be smaller) decompose_bit_size bits.
    fn decompose_arithmetic<N: Network>(
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut result = Vec::with_capacity(total_bit_size_per_field.div_ceil(decompose_bit_size));
        let big_mask = (BigUint::from(1u64) << total_bit_size_per_field) - BigUint::one();
        let small_mask = (BigUint::from(1u64) << decompose_bit_size) - BigUint::one();
        let mut x: BigUint = input.into();
        x &= &big_mask;
        for _ in 0..total_bit_size_per_field.div_ceil(decompose_bit_size) {
            let chunk = &x & &small_mask;
            x >>= decompose_bit_size;
            result.push(P::ScalarField::from(chunk));
        }
        Ok(result)
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    /// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
    fn cmux<N: Network>(
        cond: Self::ArithmeticShare,
        truthy: Self::ArithmeticShare,
        falsy: Self::ArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        assert!(cond.is_one() || cond.is_zero());
        if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    /// Compares two shared field elements and returns a shared bit indicating whether
    /// lhs <= rhs.
    fn le_public<N: Network>(
        lhs: Self::ArithmeticShare,
        rhs: P::ScalarField,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        if lhs <= rhs {
            Ok(Self::ArithmeticShare::one())
        } else {
            Ok(Self::ArithmeticShare::zero())
        }
    }

    // TODO TACEO: Remove once CoEccOpQueue is generic over a NoirWitnessExtensionProtocol
    // TODO TACEO: Currently only supports LIMB_BITS = 136, i.e. two Bn254::Fr elements per Bn254::Fq element
    /// Converts a base field share into a vector of field shares, where the field shares
    /// represent the limbs of the base field element. Each limb has at most LIMB_BITS bits.
    fn base_field_share_to_field_shares<N: Network, const LIMB_BITS: usize>(
        x: Self::BaseFieldArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        assert_eq!(
            LIMB_BITS, 136,
            "Only LIMB_BITS = 136 is supported, i.e. two Bn254::Fr elements per Bn254::Fq element"
        );
        let as_bigint: BigUint = x
            .to_base_prime_field_elements()
            .into_iter()
            .map(Into::<BigUint>::into)
            .collect_vec()
            .pop()
            .unwrap();

        let low = as_bigint.clone() & ((BigUint::from(1u8) << LIMB_BITS) - BigUint::from(1u8));
        let high = as_bigint >> LIMB_BITS;
        Ok(vec![P::ScalarField::from(low), P::ScalarField::from(high)])
    }
}
