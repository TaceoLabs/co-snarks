//! Stack-allocated fixed-width unsigned integers used as the backend for
//! binary-domain shares and ring/field interchange.

mod field_uint;
mod ruint_wrapper;

pub use field_uint::FieldUint;
pub use ruint_wrapper::RUint;

/// A common interface for stack-allocated, fixed-width unsigned integer
/// backends used throughout `mpc-core` for binary-domain shares and
/// ring/field interchange.
///
/// Implementors represent an unsigned integer of a fixed bit width with
/// wrapping (mod `2^BITS`) arithmetic semantics.
///
/// Wrapping arithmetic comes from the `num_traits` supertraits
/// (`WrappingAdd`, `WrappingSub`, `WrappingNeg`); the `+`/`-` operators on
/// implementors also wrap.
pub trait UintBackend:
    Copy
    + Clone
    + std::fmt::Debug
    + Default
    + std::fmt::Display
    + Eq
    + Ord
    + std::hash::Hash
    + Send
    + Sync
    + 'static
    + num_traits::Zero
    + num_traits::One
    + num_traits::WrappingAdd
    + num_traits::WrappingSub
    + num_traits::WrappingNeg
    + From<bool>
    + From<u64>
    + std::ops::Not<Output = Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::BitXorAssign
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitAndAssign
    + std::ops::BitOr<Output = Self>
    + std::ops::BitOrAssign
    + std::ops::Shl<usize, Output = Self>
    + std::ops::ShlAssign<usize>
    + std::ops::Shr<usize, Output = Self>
    + std::ops::ShrAssign<usize>
    + ark_serialize::CanonicalSerialize
    + ark_serialize::CanonicalDeserialize
    + serde::Serialize
    + for<'a> serde::Deserialize<'a>
{
    /// The bit width of the integer.
    const BITS: usize;
    /// The number of 64-bit limbs used to represent the integer.
    const LIMBS: usize;
    /// The number of bytes used to represent the integer (`LIMBS * 8`).
    const BYTES: usize;

    /// Returns the number of bits required to represent the value, i.e. the
    /// index of the highest set bit plus one, or `0` if the value is zero.
    fn bit_len(&self) -> usize;
    /// Returns the bit at the given index.
    fn bit(&self, index: usize) -> bool;
    /// Sets the bit at the given index to `value`.
    fn set_bit(&mut self, index: usize, value: bool);
    /// Returns a value with the lowest `k` bits set to one and all other
    /// bits set to zero.
    ///
    /// # Panics
    /// Panics if `k > Self::BITS`.
    fn mask(k: usize) -> Self;
    /// Returns the underlying limbs as a little-endian slice of `u64`.
    fn as_limbs(&self) -> &[u64];
    /// Constructs a value from a slice of little-endian `u64` limbs,
    /// truncating extra limbs or zero-extending if fewer are given.
    fn from_limbs_truncating(limbs: &[u64]) -> Self;
    /// Writes the little-endian byte representation of `self` into `out`.
    ///
    /// # Panics
    /// Panics if `out.len() != Self::BYTES`.
    fn to_le_bytes_into(&self, out: &mut [u8]);
    /// Constructs a value from its little-endian byte representation.
    ///
    /// # Panics
    /// Panics if `bytes.len() != Self::BYTES`.
    fn from_le_bytes(bytes: &[u8]) -> Self;
    /// Samples a uniformly random value with at most `bitlen` bits set.
    fn random_bits<R: rand::Rng>(rng: &mut R, bitlen: usize) -> Self;
    /// Attempts to convert the value into a `usize`, returning `None` if it
    /// does not fit.
    fn try_to_usize(&self) -> Option<usize>;
    /// Converts the value into a `u64`, truncating any higher bits.
    fn to_u64_truncating(&self) -> u64;
}

/// A 256-bit unsigned integer.
pub type U256 = RUint<256, 4>;
/// A 320-bit unsigned integer.
pub type U320 = RUint<320, 5>;
/// A 384-bit unsigned integer.
pub type U384 = RUint<384, 6>;
/// A 512-bit unsigned integer.
pub type U512 = RUint<512, 8>;
/// A 1024-bit unsigned integer.
pub type U1024 = RUint<1024, 16>;
