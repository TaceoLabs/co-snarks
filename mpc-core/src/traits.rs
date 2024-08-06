//! # MPC Traits
//!
//! Contains the traits which need to be implemented by the MPC protocols.

use core::fmt;
use std::sync::LazyLock;

use ark_ec::{pairing::Pairing, CurveGroup};
use eyre::Result;

use ark_bls12_381::Fq as Bls12_381_BaseField;
use ark_bls12_381::Fr as Bls12_381_ScalarField;
use ark_bn254::{Fq as Bn254_BaseField, Fr as Bn254_ScalarField};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

static BN254_INVERSE_R_BASE: LazyLock<Bn254_BaseField> =
    LazyLock::new(|| Bn254_BaseField::from(Bn254_BaseField::R).inverse().unwrap());
static BN254_INVERSE_R_SCALAR: LazyLock<Bn254_ScalarField> = LazyLock::new(|| {
    Bn254_ScalarField::from(Bn254_ScalarField::R)
        .inverse()
        .unwrap()
});

static BL12_381_INVERSE_R_BASE: LazyLock<Bls12_381_BaseField> = LazyLock::new(|| {
    Bls12_381_BaseField::from(Bls12_381_BaseField::R)
        .inverse()
        .unwrap()
});
static BLS12_381_INVERSE_R_SCALAR: LazyLock<Bls12_381_ScalarField> = LazyLock::new(|| {
    Bls12_381_ScalarField::from(Bls12_381_ScalarField::R)
        .inverse()
        .unwrap()
});
pub trait MontgomeryField: PrimeField {
    fn into_montgomery(self) -> Self;
    fn lift_montgomery(self) -> Self;
}

impl MontgomeryField for ark_bn254::Fr {
    fn into_montgomery(self) -> Self {
        self * Self::new_unchecked(Self::R2)
    }

    fn lift_montgomery(self) -> Self {
        self * *BN254_INVERSE_R_SCALAR
    }
}

impl MontgomeryField for ark_bls12_381::Fr {
    fn into_montgomery(self) -> Self {
        self * Self::new_unchecked(Self::R2)
    }

    fn lift_montgomery(self) -> Self {
        self * *BLS12_381_INVERSE_R_SCALAR
    }
}

pub trait MpcToMontgomery<F: MontgomeryField>: PrimeFieldMpcProtocol<F> {
    fn batch_to_montgomery(&self, vec: &Self::FieldShareVec) -> Self::FieldShareVec;
    fn batch_lift_montgomery(&self, vec: &Self::FieldShareVec) -> Self::FieldShareVec;
    fn inplace_batch_to_montgomery(&self, vec: &mut Self::FieldShareVec);
    fn inplace_batch_lift_montgomery(&self, vec: &mut Self::FieldShareVec);
}

/// A trait encompassing basic operations for MPC protocols over prime fields.
pub trait PrimeFieldMpcProtocol<F: PrimeField> {
    /// The type of a share of a field element.
    type FieldShare: Default
        + std::fmt::Debug
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Sync
        + Default;

    /// The type of a vector of shared field elements.
    type FieldShareVec: From<Vec<Self::FieldShare>>
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Default
        + std::fmt::Debug
        + IntoIterator<Item = Self::FieldShare>
        + Sync;

    /// Add two shares: \[c\] = \[a\] + \[b\]
    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;

    /// Add a public value a to the share b: \[c\] = a + \[b\]
    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare;

    /// Elementwise subtraction of two vectors of shares in place: \[a_i\] -= \[b_i\]
    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec);

    ///

    /// Multiply two shares: \[c\] = \[a\] * \[b\]. Requires network communication.
    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare>;

    /// Multiply two shares: \[c\] = \[a\] * \[b\]. Requires network communication.
    fn mul_many(
        &mut self,
        a: &[Self::FieldShare],
        b: &[Self::FieldShare],
    ) -> std::io::Result<Vec<Self::FieldShare>>;

    /// Multiply a share b by a public value a: c = a * \[b\].
    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare;

    /// Convenience method for \[a\] + \[b\] * c
    fn add_mul_public(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
        c: &F,
    ) -> Self::FieldShare {
        let tmp = self.mul_with_public(c, b);
        self.add(a, &tmp)
    }

    /// Convenience method for \[a\] + \[b\] * \[c\]
    fn add_mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
        c: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare> {
        let tmp = self.mul(c, b)?;
        Ok(self.add(a, &tmp))
    }

    /// Computes the inverse of a shared value: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare>;

    /// Computes the inverse of many shared values: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<Self::FieldShare>>;

    /// Negates a shared value: \[b\] = -\[a\].
    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare;

    /// Negates a vector of shared values: \[b\] = -\[a\] for every element in place.
    fn neg_vec_in_place(&mut self, a: &mut Self::FieldShareVec);

    /// Generate a share of a random value. The value is thereby unknown to anyone.
    fn rand(&mut self) -> std::io::Result<Self::FieldShare>;

    /// Reconstructs a shared value: a = Open(\[a\]).
    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F>;

    /// Reconstructs many shared values: a = Open(\[a\]).
    fn open_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<F>>;

    /// Elementwise addition of two vectors of shares: \[c_i\] = \[a_i\] + \[b_i\].
    fn add_vec(&mut self, a: &Self::FieldShareVec, b: &Self::FieldShareVec) -> Self::FieldShareVec;

    /// Elementwise multiplication of two vectors of shares: \[c_i\] = \[a_i\] * \[b_i\].
    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec>;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(&self, public_values: F) -> Self::FieldShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(&self, public_values: &[F]) -> Self::FieldShareVec;

    /// Computes the \[coeffs_i\] *= c * g^i for the coefficients in 0 <= i < coeff.len()
    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F);

    /// Each value of lhs consists of a coefficient c and an index i. This function computes the sum of the coefficients times the corresponding public input or private witness. In other words, an accumulator a is initialized to 0, and for each (c, i) in lhs, a += c * public_inputs\[i\] is computed if i corresponds to a public input, or c * private_witness[i - public_inputs.len()] if i corresponds to a private witness.
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

    /// Returns the shared value at index `index` in the shared vector `sharevec`.
    fn index_sharevec(sharevec: &Self::FieldShareVec, index: usize) -> Self::FieldShare;

    /// Sets the specified value at `index` in the shared vector `sharevec`.
    fn set_index_sharevec(sharevec: &mut Self::FieldShareVec, val: Self::FieldShare, index: usize);

    /// Returns the length of the shared vector `sharevec`.
    fn sharevec_len(sharevec: &Self::FieldShareVec) -> usize;

    /// Returns a secret shared zero value
    fn zero_share() -> Self::FieldShare {
        Self::FieldShare::default()
    }
}

/// A trait representing the MPC operations required for extending the secret-shared Circom witness in MPC. The operations are generic over public and private (i.e., secret-shared) inputs.
pub trait CircomWitnessExtensionProtocol<F: PrimeField>: PrimeFieldMpcProtocol<F> {
    /// A type representing the values encountered during Circom compilation. It should at least containt public field elements and shared values.
    type VmType: Clone + Default + fmt::Debug + fmt::Display + From<Self::FieldShare> + From<F>;

    /// Add two VM-types: c = a + b.
    fn vm_add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType;

    /// Subtract the VM-type b from the VM-type a: c = a - b.
    fn vm_sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType;

    /// Multiply two VM-types: c = a * b.
    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Divide the VM-type a by the VM-type b: c = a / b. In finite fields, this is equivalent to multiplying a by the inverse of b.
    fn vm_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Integer division of the VM-type a by the VM-type b: c = a \ b.
    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute c = a ^ b, where a and b ar VM-types.
    fn vm_pow(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the modulo of the VM-type a by the VM-type b: c = a % b.
    fn vm_mod(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the square root of the VM-type a: c = sqrt(a).
    fn vm_sqrt(&mut self, a: Self::VmType) -> Result<Self::VmType>;

    /// Compute the negation of the VM-type a: c = -a.
    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType;

    /// Compute the less than operation of two VM-types: a < b. Outputs 1 if a < b, 0 otherwise.
    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the less or equal than operation of two VM-types: a <= b. Outputs 1 if a <= b, 0 otherwise.
    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the greater than operation of two VM-types: a > b. Outputs 1 if a > b, 0 otherwise.
    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the greater or equal than operation of two VM-types: a >= b. Outputs 1 if a >= b, 0 otherwise.
    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the equality of two VM-types: a == b. Outputs 1 if a == b, 0 otherwise.
    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Compute the inequality of two VM-types: a != b. Outputs 1 if a != b, 0 otherwise.
    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes the bitwise shift right of the VM-type a by the VM-type b: c = a >> b.
    fn vm_shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes the bitwise shift left of the VM-type a by the VM-type b: c = a << b.
    fn vm_shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes the boolean NOT of the VM-type a, i.e. 1 - a. The value a is expected to either be 0 or 1.
    fn vm_bool_not(&mut self, a: Self::VmType) -> Result<Self::VmType>;

    /// Computes the boolean AND of the VM-types a and b: c = a && b. The values a and b are expected to be either 0 or 1.
    fn vm_bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes the boolean OR of the VM-types a and b: c = a || b. The values a and b are expected to be either 0 or 1.
    fn vm_bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
    fn vm_cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> Result<Self::VmType>;

    /// Computes the bitwise XOR of the VM-types a and b: c = a ^ b.
    fn vm_bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes the bitwise OR of the VM-types a and b: c = a | b.
    fn vm_bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Computes the bitwise AND of the VM-types a and b: c = a & b.
    fn vm_bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType>;

    /// Outputs whether a is zero (true) or not (false). This values is output in plain! Thus, if a is secret shared, the result is opened.
    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> Result<bool>;

    /// Returns whether the VM-type represents a shared value (true) or a public one (false).
    fn is_shared(&mut self, a: &Self::VmType) -> Result<bool>;

    /// Transforms a public field element into a usize if possible.
    fn vm_to_index(&mut self, a: Self::VmType) -> Result<usize>;

    /// Opens the VM-type a. If a is secret shared, it gets reconstructed.
    fn vm_open(&mut self, a: Self::VmType) -> Result<F>;

    /// Transforms a VM-type into a secret-shared value.
    fn vm_to_share(&self, a: Self::VmType) -> Self::FieldShare;

    /// Returns F::one() as a VM-type.
    fn public_one(&self) -> Self::VmType;

    /// Returns F::zero() as a VM-type. The default implementation uses the `Default` trait. If `Default` does not return 0, this function has to be overwritten.
    fn public_zero(&self) -> Self::VmType {
        Self::VmType::default()
    }
}

/// A trait encompassing basic operations for MPC protocols over elliptic curves.
pub trait EcMpcProtocol<C: CurveGroup>: PrimeFieldMpcProtocol<C::ScalarField> {
    /// The type of a share of a elliptic curve point.
    type PointShare: CanonicalDeserialize + CanonicalDeserialize + Clone + Sync;

    /// Add two shared points: \[C\] = \[A\] + \[B\]
    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;

    /// Subtract the shared point B from the shared point A: \[C\] = \[A\] - \[B\]
    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare);

    /// Subtract a shared point B in place from the shared point A: \[A\] -= \[B\]
    fn sub_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare);

    /// Add a public point B to the shared point A in place: \[A\] += B
    fn add_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C);

    /// Subtract a public point B from the shared point A in place: \[A\] -= B
    fn sub_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C);

    /// Add a public affine point B to the shared point A in place: \[A\] += B
    fn add_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine);

    /// Subtract a public affine point B from the shared point A in place: \[A\] -= B
    fn sub_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine);

    /// Multiplies a public point B to the shared point A in place: \[A\] *= B
    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare;

    /// Multiplies a public share b to the shared point A: \[A\] *= b
    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &C::ScalarField,
    ) -> Self::PointShare;

    /// Multiplies a share b to the shared point A: \[A\] *= \[b\]. Requires network communication.
    fn scalar_mul(
        &mut self,
        a: &Self::PointShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::PointShare>;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C>;

    /// Reconstructs many shared points: A = Open(\[A\]).
    fn open_point_many(&mut self, a: &[Self::PointShare]) -> std::io::Result<Vec<C>>;
}

/// A trait representing some MPC operations for pairing based  elliptic curves.
pub trait PairingEcMpcProtocol<P: Pairing>: EcMpcProtocol<P::G1> + EcMpcProtocol<P::G2> {
    /// Opens two points a, b, where a is from G1 and b is from G2.
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)>;
}

/// A trait representing the application of the Fast Fourier Transform (FFT) in MPC.
pub trait FFTProvider<F: PrimeField + FFTPostProcessing>: PrimeFieldMpcProtocol<F> {
    /// Computes the FFT of a vector of shared field elements.
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec;

    /// Computes the FFT of a vector of shared field elements in place.
    fn fft_in_place<D: EvaluationDomain<F>>(&mut self, data: &mut Self::FieldShareVec, domain: &D);

    /// Computes the inverse FFT of a vector of shared field elements.
    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec;

    /// Computes the inverse FFT of a vector of shared field elements in place.
    fn ifft_in_place<D: EvaluationDomain<F>>(&mut self, data: &mut Self::FieldShareVec, domain: &D);
}

/// A trait representing the application of the multi-scalar multiplication (MSM) in MPC.
pub trait MSMProvider<C: CurveGroup>: EcMpcProtocol<C> {
    /// Computes tha mutli-scalar product of a vector of shared values and a vector of public points. In other words, it computes sum_i=0^n-1 [scalars\[i\]] * points\[i\].
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: &Self::FieldShareVec,
    ) -> Self::PointShare;
}

/// Implements a custom post-processor for FFT operations. This is required since for BLS12-381, Arkworks FFT returns the vector of size n permuted like this (compared to snarkjs): (0, n - 3 mod n, n - 2 * 3 mod n, ... ,n - 3 * i mod n,...), so we need to rearrange it.
pub trait FFTPostProcessing: PrimeField {
    /// Allows to specify a function which gets called after each fft/ifft. Per default this function does nothing. However, for BLS12-381, the function needs to rearrange the vector.
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
