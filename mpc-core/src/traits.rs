//! # MPC Traits
//!
//! Contains the traits which need to be implemented by the MPC protocols.

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::fmt;
use eyre::Result;

/// A trait representing the basic operations for handling vectors of shares
pub trait FieldShareVecTrait:
    From<Vec<Self::FieldShare>>
    + IntoIterator<Item = Self::FieldShare>
    + Clone
    + CanonicalSerialize
    + CanonicalDeserialize
    + Default
    + std::fmt::Debug
    + Sync
{
    /// The type of a share of a field element.
    type FieldShare: Default
        + std::fmt::Debug
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Sync
        + Default;

    /// Returns the shared value at index `index` in the shared vector.
    fn index(&self, index: usize) -> Self::FieldShare;

    /// Sets the specified value at `index` in the shared vector.
    fn set_index(&mut self, val: Self::FieldShare, index: usize);

    /// Returns the length of the shared vector.
    fn get_len(&self) -> usize;
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
        + Default
        + PartialEq;

    /// The type of a vector of shared field elements.
    type FieldShareVec: FieldShareVecTrait<FieldShare = Self::FieldShare>;

    /// Add two shares: \[c\] = \[a\] + \[b\]
    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare;

    /// Add a public value a to the share b: \[c\] = a + \[b\]
    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare;

    /// Elementwise subtraction of two vectors of shares in place: \[a_i\] -= \[b_i\]
    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec);

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

    /// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
    /// Implementations should not overwrite this method.
    fn cmux(
        &mut self,
        cond: &Self::FieldShare,
        truthy: &Self::FieldShare,
        falsy: &Self::FieldShare,
    ) -> eyre::Result<Self::FieldShare> {
        let b_min_a = self.sub(truthy, falsy);
        let d = self.mul(cond, &b_min_a)?;
        Ok(self.add(falsy, &d))
    }

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

    /// Convenience method for \[a\] + \[b\] * \[c\]
    fn add_mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
        c: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec> {
        let tmp = self.mul_vec(c, b)?;
        Ok(self.add_vec(a, &tmp))
    }

    /// Computes the inverse of a shared value: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare>;

    /// Computes the inverse of many shared values: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<Self::FieldShare>>;

    /// Computes the inverse of many shared values: \[a\] = \[a\] ^ -1. Requires network communication.
    /// This function ignores the case of one share to be zero and maps it to zero.
    fn inv_many_in_place(&mut self, a: &mut [Self::FieldShare]) -> std::io::Result<()>;

    /// Negates a shared value: \[b\] = -\[a\].
    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare;

    /// Negates a vector of shared values: \[b\] = -\[a\] for every element in place.
    fn neg_vec_in_place(&mut self, a: &mut Self::FieldShareVec);

    /// Negates a vector of shared values: \[b\] = -\[a\] for up to the limit-th element in place.
    fn neg_vec_in_place_limit(&mut self, a: &mut Self::FieldShareVec, limit: usize);

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

    /// Prints a single the shared value
    #[cfg(feature = "dangerous")]
    fn debug_print(&mut self, to_print: &Self::FieldShare) -> std::io::Result<()> {
        let val = self.open(to_print)?;
        if val.is_zero() {
            println!("0");
        } else {
            println!("{}", val);
        }
        Ok(())
    }

    /// Returns a secret shared zero value
    fn zero_share() -> Self::FieldShare {
        Self::FieldShare::default()
    }

    /// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
    fn mul_open(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> std::io::Result<F>;

    /// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
    fn mul_open_many(
        &mut self,
        a: &[Self::FieldShare],
        b: &[Self::FieldShare],
    ) -> std::io::Result<Vec<F>>;
}

/// This is some place holder definition. This will change most likely
pub trait LookupTableProvider<F: PrimeField>: PrimeFieldMpcProtocol<F> {
    /// A LUT for performing membership checks (like `HashSet`). Mostly used for range checks.
    type SecretSharedSet;
    /// An input/output LUT (like `HashMap`).
    type SecretSharedMap;

    /// Initializes a set for membership checks from the provided values.
    fn init_set(&self, values: impl IntoIterator<Item = Self::FieldShare>)
        -> Self::SecretSharedSet;

    /// Checks whether the needle is a member of the provided set.
    ///
    /// # Returns
    /// Returns a secret-shared value. If the reconstructed value is 1, the set
    /// contained the element. Otherwise, shall return secret-shared 0.
    ///
    /// Can fail due to networking problems.
    ///
    fn contains_set(
        &mut self,
        needle: &Self::FieldShare,
        set: &Self::SecretSharedSet,
    ) -> eyre::Result<Self::FieldShare>;

    /// Initializes a map (input/output LUT) from the provided values. The keys and values are
    /// matched from their order of the iterator.
    fn init_map(
        &self,
        values: impl IntoIterator<Item = (Self::FieldShare, Self::FieldShare)>,
    ) -> Self::SecretSharedMap;

    /// Reads a value from the map associated with the provided needle. As we work over secret-shared
    /// values we can not check whether the needle is actually in the set. The caller must ensure that
    /// the key is in the map.
    ///
    /// # Returns
    /// The secret-shared value associated with the needle. A not known needle results in undefined
    /// behaviour.
    ///
    /// Can fail due to networking problems.
    ///
    fn get_from_lut(
        &mut self,
        key: &Self::FieldShare,
        map: &Self::SecretSharedMap,
    ) -> eyre::Result<Self::FieldShare>;

    /// Writes a value to the map.
    ///
    /// **IMPORTANT**: the implementation will NOT add
    /// the key-value pair to the map, if it is not already registered! The implementation
    /// overwrites an existing key, but a not-known key will be ignored.
    ///
    /// #Returns
    /// Can fail due to networking problems.
    fn write_to_lut(
        &mut self,
        index: Self::FieldShare,
        value: Self::FieldShare,
        lut: &mut Self::SecretSharedMap,
    ) -> eyre::Result<()>;
}

/// A trait representing the MPC operations required for extending the secret-shared Noir witness in MPC.
/// The operations are generic over public and private (i.e., secret-shared) inputs.
pub trait NoirWitnessExtensionProtocol<F: PrimeField>:
    PrimeFieldMpcProtocol<F> + LookupTableProvider<F>
{
    /// A type representing the values encountered during Circom compilation. It should at least contain public field elements and shared values.
    type AcvmType: Clone + Default + fmt::Debug + fmt::Display + From<Self::FieldShare> + From<F>;

    /// Returns F::zero() as a ACVM-type. The default implementation uses the `Default` trait. If `Default` does not return 0, this function has to be overwritten.
    fn public_zero() -> Self::AcvmType {
        Self::AcvmType::default()
    }

    /// Checks whether an ACVM-type is public zero.
    fn is_public_zero(a: &Self::AcvmType) -> bool;

    /// Checks whether an ACVM-type is public one.
    fn is_public_one(a: &Self::AcvmType) -> bool;

    /// Adds a public value to an ACVM-type in place: *\[secret\] += public
    fn acvm_add_assign_with_public(&mut self, public: F, secret: &mut Self::AcvmType);

    /// Multiply an ACVM-types with a public value: \[c\] = public * \[secret\].
    fn acvm_mul_with_public(
        &mut self,
        public: F,
        secret: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType>;

    /// Multiply an ACVM-types with a public value and add_assign with result: \[result\] += q_l * \[w_l\].
    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, result: &mut Self::AcvmType);

    /// Multiply two acvm-types and a public value and stores them at target: \[*result\] = c * \[lhs\] * \[rhs\].
    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        target: &mut Self::AcvmType,
    ) -> eyre::Result<()>;

    /// Solves the equation \[q_l\] * w_l + \[c\] = 0, by computing \[-c\]/\[q_l\] and returning the result.
    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType>;

    /// Initializes a new LUT from the provided values. The index shall be the order
    /// of the values in the `Vec`. This is wrapper around the method from the [`LookupTableProvider`] as
    /// we create the table from either public or shared values.
    fn init_lut_by_acvm_type(&mut self, values: Vec<Self::AcvmType>) -> Self::SecretSharedMap;

    /// Wrapper around reading from a LUT by the [`Self::AcvmType`] as this can either be a
    /// public or a shared read.
    fn read_lut_by_acvm_type(
        &mut self,
        index: &Self::AcvmType,
        lut: &Self::SecretSharedMap,
    ) -> eyre::Result<Self::AcvmType>;

    /// Wrapper around writing a value to a LUT. The index and the value can be shared or public.
    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut Self::SecretSharedMap,
    ) -> eyre::Result<()>;
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
pub trait FFTProvider<F: PrimeField>: PrimeFieldMpcProtocol<F> {
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

    /// Evaluates the shared polynomial at the public point
    fn evaluate_poly_public(&mut self, poly: Self::FieldShareVec, point: &F) -> Self::FieldShare;
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
