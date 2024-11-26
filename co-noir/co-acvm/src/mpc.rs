use std::{fmt, io};

use ark_ff::PrimeField;
use co_brillig::mpc::BrilligDriver;
use mpc_core::lut::LookupTableProvider;

pub(super) mod plain;
pub(super) mod rep3;
pub(super) mod shamir; // Does not support everything, but basic circuits can be build using Shamir (co-builder)

/// A trait representing the MPC operations required for extending the secret-shared Noir witness in MPC.
/// The operations are generic over public and private (i.e., secret-shared) inputs.
pub trait NoirWitnessExtensionProtocol<F: PrimeField> {
    type Lookup: LookupTableProvider<F>;
    type ArithmeticShare: Clone;
    /// A type representing the values encountered during Noir compilation. It should at least contain public field elements and shared values.
    type AcvmType: Clone
        + Default
        + fmt::Debug
        + fmt::Display
        + From<Self::ArithmeticShare>
        + From<F>
        + PartialEq
        + Into<<Self::BrilligDriver as BrilligDriver<F>>::BrilligType>;

    type BrilligDriver: BrilligDriver<F>;

    fn init_brillig_driver(&mut self) -> std::io::Result<Self::BrilligDriver>;

    fn from_brillig_result(
        &mut self,
        brillig_result: Vec<<Self::BrilligDriver as BrilligDriver<F>>::BrilligType>,
    ) -> Vec<Self::AcvmType>;

    /// Returns F::zero() as a ACVM-type. The default implementation uses the `Default` trait. If `Default` does not return 0, this function has to be overwritten.
    fn public_zero() -> Self::AcvmType {
        Self::AcvmType::default()
    }

    /// Checks whether an ACVM-type is public zero.
    fn is_public_zero(a: &Self::AcvmType) -> bool;

    /// Checks whether an ACVM-type is public one.
    fn is_public_one(a: &Self::AcvmType) -> bool;

    /// Adds a public value to an ACVM-type in place: *\[target\] += public
    fn acvm_add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType);

    /// Subtracts two ACVM-type values: secret - secret
    fn acvm_sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType;

    /// Multiply an ACVM-types with a public value: \[c\] = public * \[secret\].
    fn acvm_mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType;

    /// Multiply two ACVM-types: \[c\] = \[secret_1\] * \[secret_2\].
    fn acvm_mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> io::Result<Self::AcvmType>;

    /// Negates an ACVM-type inplace: \[a\] = -\[a\].
    fn acvm_negate_inplace(&mut self, a: &mut Self::AcvmType);

    /// Multiply an ACVM-types with a public value and add_assign with result: \[result\] += q_l * \[w_l\].
    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, result: &mut Self::AcvmType);

    fn add_assign(&mut self, lhs: &mut Self::AcvmType, rhs: Self::AcvmType);

    /// Multiply two acvm-types and a public value and stores them at target: \[*result\] = c * \[lhs\] * \[rhs\].
    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
    ) -> io::Result<Self::AcvmType>;

    /// Solves the equation \[q_l\] * w_l + \[c\] = 0, by computing \[-c\]/\[q_l\] and returning the result.
    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType>;

    /// Initializes a new LUT from the provided values. The index shall be the order
    /// of the values in the `Vec`. This is wrapper around the method from the [`LookupTableProvider`] as
    /// we create the table from either public or shared values.
    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as LookupTableProvider<F>>::SecretSharedMap;

    /// Wrapper around reading from a LUT by the [`Self::AcvmType`] as this can either be a
    /// public or a shared read.
    fn read_lut_by_acvm_type(
        &mut self,
        index: &Self::AcvmType,
        lut: &<Self::Lookup as LookupTableProvider<F>>::SecretSharedMap,
    ) -> io::Result<Self::AcvmType>;

    /// Wrapper around writing a value to a LUT. The index and the value can be shared or public.
    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut <Self::Lookup as LookupTableProvider<F>>::SecretSharedMap,
    ) -> io::Result<()>;

    /// Returns true if the value is shared
    fn is_shared(a: &Self::AcvmType) -> bool;

    /// Returns the share if the value is shared
    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare>;

    /// Returns the value if the value is public
    fn get_public(a: &Self::AcvmType) -> Option<F>;

    // TODO do we want this here?
    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> io::Result<Vec<F>>;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare>;

    /// Decompose a shared value into a vector of shared values: \[a\] = a_1 + a_2 + ... + a_n. Each value a_i has at most decompose_bit_size bits, whereas the total bit size of the shares is total_bit_size_per_field. Thus, a_n, might have a smaller bitsize than the other chunks
    fn decompose_arithmetic(
        &mut self,
        input: Self::ArithmeticShare,
        // io_context: &mut IoContext<N>,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>>;

    /// Sorts a vector of shared values in ascending order, only considering the first bitsize bits.
    fn sort(
        &mut self,
        inputs: &[Self::ArithmeticShare],
        bitsize: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>>;
}
