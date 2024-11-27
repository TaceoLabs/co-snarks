//! This modules defines the trait [BrilligDriver]. All MPC protocols
//! that want to run the coBrillig-VM must implement this trait.
//!
//! Additionally, it contains implementations of a replicated secret-sharing
//! MPC protocol to run with the coBrillig-VM. We also provide a plain
//! implementation for debugging purposes.

use std::fmt;

use ark_ff::PrimeField;

mod plain;
mod rep3;
mod shamir;
use brillig::{BitSize, IntegerBitSize};
pub use plain::PlainBrilligDriver;
pub use rep3::Rep3BrilligDriver;
pub use shamir::ShamirBrilligDriver;

pub use plain::PlainBrilligType;
pub use rep3::Rep3BrilligType;
pub use shamir::ShamirBrilligType;

pub(super) mod acir_field_utils {
    use ark_ff::PrimeField;

    pub(super) fn to_u128<F: PrimeField>(val: F) -> u128 {
        let as_bigint = val.into_bigint();
        let limbs = as_bigint.as_ref();

        let mut result = limbs[0] as u128;
        if limbs.len() > 1 {
            let high_limb = limbs[1] as u128;
            result += high_limb << 64;
        }

        result
    }
}

/// A trait representing the MPC operations required for running the coBrillig-VM.
/// The operations are generic over public and private (i.e., secret-shared) inputs.
pub trait BrilligDriver<F: PrimeField> {
    /// A type representing the values encountered during a run of
    /// the coBrillig-VM.
    ///
    /// It should at least contain public and shared values, as well
    /// as integer and field implementations.
    type BrilligType: Clone + Default + fmt::Debug + From<F> + PartialEq;

    /// Casts the provided value to the provided bit size. This includes upcasts
    /// and downcasts between integer types, but also between fields to integers
    /// and vice verca.
    fn cast(
        &mut self,
        src: Self::BrilligType,
        bit_size: BitSize,
    ) -> eyre::Result<Self::BrilligType>;

    /// Tries to convert the provided value to a `usize`. Returns an error
    /// if it is not possible (e.g., is a shared value).
    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize>;

    /// Tries to convert the provided value to a `bool`. Returns an error
    /// if it is not possible (e.g., is a shared value).
    fn try_into_bool(val: Self::BrilligType) -> eyre::Result<bool>;

    /// Creates a new public value from the provided value. The type
    /// of the new value is determined by the provided `bit_size`.
    fn public_value(val: F, bit_size: BitSize) -> Self::BrilligType;

    /// Adds two brillig types.
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Subtracts two brillig types.
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    fn sub(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Multiplies two brillig types.
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Divides two brillig types.
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Performs an integer division on two brillig types.
    ///
    /// This operation returns an error if the provided inputs
    /// are not fields.
    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Boolean not operation on a brillig type.
    ///
    /// This operation returns an error if the provided input
    /// is not a boolean type (BitSize = U1).
    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType>;

    /// Compares two brillig types for equality. The result
    /// is a brillig integer type with bit size 1 (BitSize = U1).
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Checks whether `lhs < rhs`. The result
    /// is a brillig integer type with bit size 1 (BitSize = U1).
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    ///
    /// Similar to Noir's brillig-VM, this method compares fields
    /// by casting them `to u128` and compares the integer values.
    fn lt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType>;

    /// Checks whether `lhs <= rhs`. The result
    /// is a brillig integer type with bit size 1 (BitSize = U1).
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    ///
    /// Similar to Noir's brillig-VM, this method compares fields
    /// by casting them `to u128` and compares the integer values.
    fn le(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.gt(lhs, rhs)?;
        self.not(gt)
    }

    /// Checks whether `lhs > rhs`. The result
    /// is a brillig integer type with bit size 1 (BitSize = U1).
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    ///
    /// Similar to Noir's brillig-VM, this method compares fields
    /// by casting them `to u128` and compares the integer values.
    fn gt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    /// Checks whether `lhs >= rhs`. The result
    /// is a brillig integer type with bit size 1 (BitSize = U1).
    ///
    /// This operation returns an error if the provided inputs
    /// are not the same type.
    ///
    /// Similar to Noir's brillig-VM, this method compares fields
    /// by casting them `to u128` and compares the integer values.
    fn ge(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    /// Converts the provided value to a binary representation, depending
    /// on the provided radix. The amount of elements produced depends on
    /// the provided output size.
    ///
    /// If `bits` is set to `true`, the provided results will be
    /// brillig integer types with bit size 1 (BitSize = U1). Otherwise,
    /// they will be bytes (BitSize = U8).
    ///
    /// This operation returns an error if the provided value
    /// is not a field type. Additionally, it will return an error
    /// if the radix is not BitSize = U32.
    ///
    /// Similar to Noir's brillig-VM, this method compares fields
    /// by casting them to `u128` and compares the integer values.
    fn to_radix(
        &mut self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>>;

    /// Checks whether the provided value is an integer type matching the
    /// provided bit size. Returns an error otherwise.
    fn expect_int(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType>;

    /// Checks whether the provided value is a field type. Returns an
    /// error otherwise.
    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType>;
}
