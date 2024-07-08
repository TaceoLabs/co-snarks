//! # MPC Traits
//! Contains the traits which need to be implemented by the MPC protocols.

use core::fmt;

use ark_ec::{pairing::Pairing, CurveGroup};
use eyre::Result;

use ark_bls12_381::Fr as Bls12_381_ScalarField;
use ark_bn254::Fr as Bn254_ScalarField;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A trait encompassing basic operations for MPC protocols over prime fields.
pub trait PrimeFieldMpcProtocol<F: PrimeField> {
    /// The type of a share of a field element.
    type FieldShare: Default
        + std::fmt::Debug
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Sync;

    /// The type of a vector of shared field elements.
    type FieldShareVec: From<Vec<Self::FieldShare>>
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Default
        + std::fmt::Debug
        + IntoIterator<Item = Self::FieldShare>
        + Sync;

    /// Add two shares: [c] = [a] + [b]
    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;

    /// Subtract the share b from the share a: [c] = [a] - [b]
    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;

    /// Add a public value a to the share b: [c] = a + [b]
    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare;

    /// Elementwise subtraction of two vectors of shares in place: [a_i] -= [b_i]
    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec);

    /// Multiply two shares: [c] = [a] * [b]. Requires network communication.
    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare>;

    /// Multiply a share b by a public value a: c = a * b.
    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare;

    /// Computes the inverse of a shared value: [b] = [a] ^ -1. Requires network communication.
    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare>;

    /// Negates a shared value: [b] = -[a].
    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare;

    /// Generate a share of a random value. The value is thereby unknown to anyone.
    fn rand(&mut self) -> std::io::Result<Self::FieldShare>;

    /// Reconstructs a shared value: a = Open([a]).
    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F>;

    /// Elementwise multiplication of two vectors of shares: [c_i] = [a_i] * [b_i].
    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec>;

    /// Transforms a public value into a shared value: [a] = a.
    fn promote_to_trivial_share(&self, public_values: F) -> Self::FieldShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: [a_i] = a_i.
    fn promote_to_trivial_shares(&self, public_values: &[F]) -> Self::FieldShareVec;

    /// Computes the [coeffs_i] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F);

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs[i] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
    fn evaluate_constraint(
        &mut self,
        lhs: &[(F, usize)],
        public_inputs: &[F],
        private_witness: &Self::FieldShareVec,
    ) -> Self::FieldShare;

    /// Clones the slice src[src_offset..src_offset + len] to dst[dst_offset..dst_offset + len], where src and dst consist of shared values.
    fn clone_from_slice(
        &self,
        dst: &mut Self::FieldShareVec,
        src: &Self::FieldShareVec,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    );

    /// Prints the shared values-
    fn print(&self, to_print: &Self::FieldShareVec);
}

pub trait CircomWitnessExtensionProtocol<F: PrimeField>: PrimeFieldMpcProtocol<F> {
    type VmType: Clone + Default + fmt::Debug + fmt::Display + From<Self::FieldShare> + From<F>;
    fn vm_add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType;
    fn vm_sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType;
    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    fn vm_pow(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_mod(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_sqrt(&mut self, a: Self::VmType) -> Result<Self::VmType>;

    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType;

    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    fn vm_shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    fn vm_bool_not(&mut self, a: Self::VmType) -> Result<Self::VmType>;
    fn vm_bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> Result<Self::VmType>;

    fn vm_bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;
    fn vm_bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> Result<bool>;
    fn is_shared(&mut self, a: &Self::VmType) -> Result<bool>;

    fn vm_to_index(&mut self, a: Self::VmType) -> Result<usize>;
    fn vm_open(&mut self, a: Self::VmType) -> Result<F>;

    fn vm_to_share(&self, a: Self::VmType) -> Self::FieldShare;

    fn public_one(&self) -> Self::VmType;
    //if default doesn't return the zero element, overwrite this function
    fn public_zero(&self) -> Self::VmType {
        Self::VmType::default()
    }
}

pub trait EcMpcProtocol<C: CurveGroup>: PrimeFieldMpcProtocol<C::ScalarField> {
    type PointShare: CanonicalDeserialize + CanonicalDeserialize + Clone + Sync;
    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;
    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;
    fn add_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare);
    fn sub_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare);
    fn add_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C);
    fn sub_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C);
    fn add_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine);
    fn sub_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine);
    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare;
    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &C::ScalarField,
    ) -> Self::PointShare;
    fn scalar_mul(
        &mut self,
        a: &Self::PointShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::PointShare>;
    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C>;
}

pub trait PairingEcMpcProtocol<P: Pairing>: EcMpcProtocol<P::G1> + EcMpcProtocol<P::G2> {
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)>;
}

pub trait FFTProvider<F: PrimeField + FFTPostProcessing>: PrimeFieldMpcProtocol<F> {
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec;
    fn fft_in_place<D: EvaluationDomain<F>>(&mut self, data: &mut Self::FieldShareVec, domain: &D);
    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec;
    fn ifft_in_place<D: EvaluationDomain<F>>(&mut self, data: &mut Self::FieldShareVec, domain: &D);
}

pub trait MSMProvider<C: CurveGroup>: EcMpcProtocol<C> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: &Self::FieldShareVec,
    ) -> Self::PointShare;
}
/// For BLS12-381, Arkworks FFT returns the vector of size n permuted like this (compared to snarkjs): (0,n-3 mod n, n-2*3 mod n,...,n-3*i mod n,...), so we need to rearrange it
pub trait FFTPostProcessing: PrimeField {
    fn fft_post_processing(_vec: &mut Vec<Self>) {}
}

impl FFTPostProcessing for Bls12_381_ScalarField {
    fn fft_post_processing(vec: &mut Vec<Self>) {
        let n = vec.len();
        let mut temp = vec.clone();
        vec.iter().enumerate().for_each(|(i, &value)| {
            let original_index = (n + n - 3 * i % n) % n;
            temp[original_index] = value;
        });
        vec.copy_from_slice(&temp);
    }
}
impl FFTPostProcessing for Bn254_ScalarField {}
