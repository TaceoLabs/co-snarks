//! # Plain Protocol
//!
//! This module contains the reference implementation without MPC. It will be used by the VM for computing on public values and can be used to test MPC circuits.

use std::collections::{HashMap, HashSet};

use crate::{
    traits::{
        CircomWitnessExtensionProtocol, EcMpcProtocol, FFTProvider, FieldShareVecTrait,
        LookupTableProvider, MSMProvider, NoirWitnessExtensionProtocol, PairingEcMpcProtocol,
        PrimeFieldMpcProtocol,
    },
    RngType,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{One, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use eyre::eyre;
use eyre::Result;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use rand::SeedableRng;
use tracing;

/// Transforms a field element into an usize if possible.
macro_rules! to_usize {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        usize::try_from(a.to_u64().ok_or(eyre!("Cannot convert var into u64"))?)?
    }};
}
pub(crate) use to_usize;

macro_rules! bool_comp_op {
    ($driver: expr, $lhs: expr, $op: tt, $rhs: expr) => {{
        let lhs = $driver.val($lhs);
        let rhs = $driver.val($rhs);
       if (lhs $op rhs){
        tracing::trace!("{}{}{} -> 1", $lhs,stringify!($op), $rhs);
        F::one()
       } else {
        tracing::trace!("{}{}{} -> 0", $lhs,stringify!($op), $rhs);
        F::zero()
       }
    }};
}

macro_rules! to_u64 {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a.to_u64().ok_or(eyre!("Cannot convert var into u64"))?
    }};
}

macro_rules! to_bigint {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a
    }};
}

/// The PlainDriver implements implements the MPC traits without MPC. In other words, it implements [PrimeFieldMpcProtocol], [CircomWitnessExtensionProtocol] and can thus be used by the VM to evaluate functions on public values, as well as for testing MPC circuits.
pub struct PlainDriver<F> {
    negative_one: F,
}

impl<F: PrimeField> PlainDriver<F> {
    /// Normally F is split into positive and negative numbers in the range [0, p/2] and [p/2 + 1, p)
    /// However, for comparisons, we want the negative numbers to be "lower" than the positive ones.
    /// Therefore we shift the input by p/2 + 1 to the left, which results in a mapping of [negative, 0, positive] into F.
    /// We can then compare the numbers as if they were unsigned.
    /// While this could be done easier by just comparing the numbers as BigInt, we do it this way because this is easier to replicate in MPC later.
    #[inline(always)]
    pub(crate) fn val(&self, z: F) -> F {
        z - self.negative_one
    }

    #[inline(always)]
    pub(crate) fn is_negative(&self, x: F) -> bool {
        x >= self.negative_one
    }
}

impl<F: PrimeField> Default for PlainDriver<F> {
    fn default() -> Self {
        let modulus = to_bigint!(F::MODULUS);
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        Self {
            negative_one: F::from(modulus / two + one),
        }
    }
}

impl<F: PrimeField> FieldShareVecTrait for Vec<F> {
    type FieldShare = F;

    fn index(&self, index: usize) -> Self::FieldShare {
        self[index].to_owned()
    }

    fn set_index(&mut self, val: Self::FieldShare, index: usize) {
        self[index] = val;
    }

    fn get_len(&self) -> usize {
        self.len()
    }
}

impl<F: PrimeField> PrimeFieldMpcProtocol<F> for PlainDriver<F> {
    type FieldShare = F;
    type FieldShareVec = Vec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        *a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        *a - b
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        *a + b
    }

    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec) {
        a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a -= b);
    }

    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare> {
        Ok(*a * b)
    }

    fn mul_many(
        &mut self,
        a: &[Self::FieldShare],
        b: &[Self::FieldShare],
    ) -> std::io::Result<Vec<Self::FieldShare>> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        *a * b
    }

    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare> {
        if a.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot invert zero",
            ));
        }
        Ok(a.inverse().unwrap())
    }

    fn inv_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<Self::FieldShare>> {
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

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -*a
    }

    fn neg_vec_in_place(&mut self, a: &mut Self::FieldShareVec) {
        for x in a.iter_mut() {
            *x = self.neg(x);
        }
    }

    fn neg_vec_in_place_limit(&mut self, a: &mut Self::FieldShareVec, limit: usize) {
        for x in a.iter_mut().take(limit) {
            *x = self.neg(x);
        }
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        let mut rng = RngType::from_entropy();
        Ok(F::rand(&mut rng))
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        Ok(*a)
    }

    fn open_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<F>> {
        Ok(a.to_vec())
    }

    fn add_vec(&mut self, a: &Self::FieldShareVec, b: &Self::FieldShareVec) -> Self::FieldShareVec {
        a.iter().zip(b.iter()).map(|(a, b)| *a + b).collect()
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn promote_to_trivial_share(&self, public_value: F) -> Self::FieldShare {
        public_value
    }

    fn promote_to_trivial_shares(&self, public_values: &[F]) -> Self::FieldShareVec {
        public_values.to_vec()
    }

    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F) {
        let mut pow = c;
        for c in coeffs.iter_mut() {
            *c *= pow;
            pow *= g;
        }
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(F, usize)],
        public_inputs: &[F],
        private_witness: &Self::FieldShareVec,
    ) -> Self::FieldShare {
        let mut acc = F::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                acc += *coeff * public_inputs[*index];
            } else {
                acc += *coeff * private_witness[*index - public_inputs.len()];
            }
        }
        acc
    }

    fn clone_from_slice(
        &self,
        dst: &mut Self::FieldShareVec,
        src: &Self::FieldShareVec,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    ) {
        assert!(dst.len() >= dst_offset + len);
        assert!(src.len() >= src_offset + len);
        assert!(len > 0);
        dst[dst_offset..dst_offset + len].clone_from_slice(&src[src_offset..src_offset + len]);
    }

    fn mul_open(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> std::io::Result<F> {
        Ok(*a * b)
    }

    fn mul_open_many(
        &mut self,
        a: &[Self::FieldShare],
        b: &[Self::FieldShare],
    ) -> std::io::Result<Vec<F>> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }
}

impl<C: CurveGroup> EcMpcProtocol<C> for PlainDriver<C::ScalarField> {
    type PointShare = C;

    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a + b
    }

    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a - b
    }

    fn add_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare) {
        *a += b;
    }

    fn sub_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare) {
        *a -= b;
    }

    fn add_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        *a += b;
    }

    fn sub_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        *a -= b;
    }

    fn add_assign_points_public_affine(
        &mut self,
        a: &mut Self::PointShare,
        b: &<C as CurveGroup>::Affine,
    ) {
        *a += b;
    }

    fn sub_assign_points_public_affine(
        &mut self,
        a: &mut Self::PointShare,
        b: &<C as CurveGroup>::Affine,
    ) {
        *a -= b;
    }

    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare {
        *a * b
    }

    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &<C>::ScalarField,
    ) -> Self::PointShare {
        *a * b
    }

    fn scalar_mul(
        &mut self,
        a: &Self::PointShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::PointShare> {
        Ok(*a * b)
    }

    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C> {
        Ok(a.to_owned())
    }

    fn open_point_many(&mut self, a: &[Self::PointShare]) -> std::io::Result<Vec<C>> {
        Ok(a.to_vec())
    }
}

impl<P: Pairing> PairingEcMpcProtocol<P> for PlainDriver<P::ScalarField> {
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)> {
        Ok((*a, *b))
    }
}

impl<F: PrimeField> FFTProvider<F> for PlainDriver<F> {
    fn fft<D: ark_poly::EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec {
        domain.fft(&data)
    }

    fn fft_in_place<D: ark_poly::EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareVec,
        domain: &D,
    ) {
        domain.fft_in_place(data);
    }

    fn ifft<D: ark_poly::EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec {
        domain.ifft(data)
    }

    fn ifft_in_place<D: ark_poly::EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareVec,
        domain: &D,
    ) {
        domain.ifft_in_place(data);
    }

    fn evaluate_poly_public(&mut self, poly: Self::FieldShareVec, point: &F) -> Self::FieldShare {
        let poly = DensePolynomial { coeffs: poly };
        poly.evaluate(point)
    }
}

impl<C: CurveGroup> MSMProvider<C> for PlainDriver<C::ScalarField> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: &Self::FieldShareVec,
    ) -> Self::PointShare {
        C::msm_unchecked(points, scalars)
    }
}

impl<F: PrimeField> CircomWitnessExtensionProtocol<F> for PlainDriver<F> {
    type VmType = F;

    fn vm_add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        let result = a + b;
        tracing::debug!("{a}+{b}={result}");
        result
    }

    fn vm_sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        let result = a - b;
        tracing::debug!("{a}-{b}={result}");
        a - b
    }

    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a * b)
    }

    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType {
        -a
    }

    fn vm_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a / b)
    }

    fn vm_pow(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a.pow(b.into_bigint()))
    }

    fn vm_mod(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let a = to_bigint!(a);
        let b = to_bigint!(b);
        Ok(F::from(a % b))
    }

    fn vm_sqrt(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        let sqrt = a.sqrt().ok_or(eyre!("cannot compute sqrt for {a}"))?;
        if self.is_negative(sqrt) {
            Ok(-sqrt)
        } else {
            Ok(sqrt)
        }
    }

    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_u64!(a);
        let rhs = to_u64!(b);
        Ok(F::from(lhs / rhs))
    }

    fn is_zero(&mut self, a: Self::VmType, _: bool) -> Result<bool> {
        Ok(a.is_zero())
    }

    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, <, b))
    }

    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, <=, b))
    }

    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, >, b))
    }

    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, >=, b))
    }

    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        if a == b {
            tracing::trace!("{a}=={b} -> 1");
            Ok(F::one())
        } else {
            tracing::trace!("{a}=={b} -> 0");
            Ok(F::zero())
        }
    }

    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        if a != b {
            tracing::trace!("{a}!={b} -> 1");
            Ok(F::one())
        } else {
            tracing::trace!("{a}!={b} -> 0");
            Ok(F::zero())
        }
    }

    fn vm_shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val >> shift))
    }

    fn vm_shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val << shift))
    }

    fn vm_bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_usize!(a);
        let rhs = to_usize!(b);
        debug_assert!(rhs == 0 || rhs == 1);
        debug_assert!(lhs == 0 || lhs == 1);
        if rhs == 1 && lhs == 1 {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn vm_bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_usize!(a);
        let rhs = to_usize!(b);
        debug_assert!(rhs == 0 || rhs == 1);
        debug_assert!(lhs == 0 || lhs == 1);
        if rhs == 1 || lhs == 1 {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn vm_bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs ^ rhs))
    }

    fn vm_bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs | rhs))
    }

    fn vm_bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs & rhs))
    }

    fn vm_to_index(&mut self, a: Self::VmType) -> Result<usize> {
        Ok(to_usize!(a))
    }
    fn vm_open(&mut self, a: Self::VmType) -> Result<F> {
        Ok(a)
    }

    fn vm_to_share(&self, a: Self::VmType) -> Self::FieldShare {
        a
    }

    fn is_shared(&mut self, _: &Self::VmType) -> Result<bool> {
        Ok(false)
    }

    fn vm_bool_not(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        assert!(a.is_one() || a.is_zero());
        Ok(F::one() - a)
    }

    fn vm_cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> Result<Self::VmType> {
        assert!(cond.is_one() || cond.is_zero());
        if cond.is_one() {
            Ok(truthy)
        } else {
            Ok(falsy)
        }
    }

    fn public_one(&self) -> Self::VmType {
        F::one()
    }
}

impl<F: PrimeField> NoirWitnessExtensionProtocol<F> for PlainDriver<F> {
    type AcvmType = F;

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        a.is_zero()
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        a.is_one()
    }

    fn acvm_add_assign_with_public(&mut self, public: F, secret: &mut Self::AcvmType) {
        *secret += public;
    }

    fn acvm_mul_with_public(
        &mut self,
        public: F,
        secret: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        Ok(secret * public)
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, result: &mut Self::AcvmType) {
        *result += q_l * w_l;
    }

    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        target: &mut Self::AcvmType,
    ) -> eyre::Result<()> {
        *target = c * lhs * rhs;
        Ok(())
    }

    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        Ok(-c / q_l)
    }

    fn read_lut_by_acvm_type(
        &mut self,
        index: &Self::AcvmType,
        lut: &Self::SecretSharedMap,
    ) -> eyre::Result<F> {
        self.get_from_lut(index, lut)
    }

    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        map: &mut Self::SecretSharedMap,
    ) -> eyre::Result<()> {
        self.write_to_lut(index, value, map)
    }

    fn init_lut_by_acvm_type(&mut self, values: Vec<Self::AcvmType>) -> Self::SecretSharedMap {
        self.init_map(values.into_iter().enumerate().map(|(idx, value)| {
            let promoted_idx = self.promote_to_trivial_share(F::from(
                u64::try_from(idx).expect("usize fits into u64"),
            ));
            (promoted_idx, value)
        }))
    }
}

impl<F: PrimeField> LookupTableProvider<F> for PlainDriver<F> {
    // we could check if a Vec<F> impl may be faster. Depends on the size of the LUT..
    type SecretSharedSet = HashSet<F>;

    type SecretSharedMap = HashMap<F, F>;

    fn init_set(
        &self,
        values: impl IntoIterator<Item = Self::FieldShare>,
    ) -> Self::SecretSharedSet {
        values.into_iter().collect::<HashSet<_>>()
    }

    fn contains_set(
        &mut self,
        value: &Self::FieldShare,
        set: &Self::SecretSharedSet,
    ) -> eyre::Result<F> {
        if set.contains(value) {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn init_map(
        &self,
        values: impl IntoIterator<Item = (Self::FieldShare, Self::FieldShare)>,
    ) -> Self::SecretSharedMap {
        values.into_iter().collect::<HashMap<_, _>>()
    }

    fn get_from_lut(&mut self, key: &F, map: &Self::SecretSharedMap) -> eyre::Result<F> {
        Ok(map[key])
    }

    fn write_to_lut(
        &mut self,
        key: F,
        value: F,
        map: &mut Self::SecretSharedMap,
    ) -> eyre::Result<()> {
        if map.insert(key, value).is_none() {
            panic!("we cannot add new keys to the lookup table!")
        }
        Ok(())
    }
}
