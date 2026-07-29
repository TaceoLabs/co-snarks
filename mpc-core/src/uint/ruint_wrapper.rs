//! A stack-allocated fixed-width unsigned integer wrapping [`ruint::Uint`].

use crate::protocols::rep3_ring::ring::bit::Bit;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use num_traits::{AsPrimitive, One, WrappingAdd, WrappingMul, WrappingNeg, WrappingSub, Zero};
use ruint::Uint;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, Neg, Not,
    Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

/// A fixed-width unsigned integer with wrapping (mod `2^BITS`) semantics,
/// backed by a stack-allocated [`ruint::Uint`].
///
/// `BITS` must be a non-zero multiple of 64 and `LIMBS == BITS / 64`
/// (enforced at compile time on first use).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RUint<const BITS: usize, const LIMBS: usize>(pub Uint<BITS, LIMBS>);

impl<const BITS: usize, const LIMBS: usize> RUint<BITS, LIMBS> {
    const LAYOUT_OK: () = assert!(
        BITS != 0 && BITS.is_multiple_of(64) && LIMBS * 64 == BITS,
        "RUint requires BITS to be a non-zero multiple of 64 and LIMBS == BITS / 64"
    );

    /// The zero value.
    pub fn zero() -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = Self::LAYOUT_OK;
        Self(Uint::ZERO)
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::Display for RUint<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for limb in self.0.as_limbs().iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        Ok(())
    }
}

// --- conversions ---

impl<const BITS: usize, const LIMBS: usize> From<bool> for RUint<BITS, LIMBS> {
    fn from(v: bool) -> Self {
        Self(Uint::from(v as u64))
    }
}
impl<const BITS: usize, const LIMBS: usize> From<u64> for RUint<BITS, LIMBS> {
    fn from(v: u64) -> Self {
        Self(Uint::from(v))
    }
}
impl<const BITS: usize, const LIMBS: usize> From<u128> for RUint<BITS, LIMBS> {
    fn from(v: u128) -> Self {
        Self(Uint::from(v))
    }
}
impl<const BITS: usize, const LIMBS: usize> TryFrom<RUint<BITS, LIMBS>> for usize {
    type Error = &'static str;
    fn try_from(v: RUint<BITS, LIMBS>) -> Result<Self, Self::Error> {
        v.0.try_into()
            .map_err(|_| "RUint value too large to fit into usize")
    }
}

// --- bit operations (all delegate to ruint, which wraps mod 2^BITS) ---

impl<const BITS: usize, const LIMBS: usize> Not for RUint<BITS, LIMBS> {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

macro_rules! impl_binop {
    ($trait:ident, $fn:ident, $assign_trait:ident, $assign_fn:ident, $op:tt, $assign_op:tt) => {
        impl<const BITS: usize, const LIMBS: usize> $trait for RUint<BITS, LIMBS> {
            type Output = Self;
            fn $fn(self, rhs: Self) -> Self {
                Self(self.0 $op rhs.0)
            }
        }
        impl<const BITS: usize, const LIMBS: usize> $assign_trait for RUint<BITS, LIMBS> {
            fn $assign_fn(&mut self, rhs: Self) {
                self.0 $assign_op rhs.0;
            }
        }
    };
}
impl_binop!(BitXor, bitxor, BitXorAssign, bitxor_assign, ^, ^=);
impl_binop!(BitAnd, bitand, BitAndAssign, bitand_assign, &, &=);
impl_binop!(BitOr, bitor, BitOrAssign, bitor_assign, |, |=);
impl_binop!(Add, add, AddAssign, add_assign, +, +=);
impl_binop!(Sub, sub, SubAssign, sub_assign, -, -=);

impl<const BITS: usize, const LIMBS: usize> Mul for RUint<BITS, LIMBS> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}
impl<const BITS: usize, const LIMBS: usize> Neg for RUint<BITS, LIMBS> {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl<const BITS: usize, const LIMBS: usize> Shl<usize> for RUint<BITS, LIMBS> {
    type Output = Self;
    fn shl(self, rhs: usize) -> Self {
        Self(self.0 << rhs)
    }
}
impl<const BITS: usize, const LIMBS: usize> ShlAssign<usize> for RUint<BITS, LIMBS> {
    fn shl_assign(&mut self, rhs: usize) {
        self.0 <<= rhs;
    }
}
impl<const BITS: usize, const LIMBS: usize> Shr<usize> for RUint<BITS, LIMBS> {
    type Output = Self;
    fn shr(self, rhs: usize) -> Self {
        Self(self.0 >> rhs)
    }
}
impl<const BITS: usize, const LIMBS: usize> ShrAssign<usize> for RUint<BITS, LIMBS> {
    fn shr_assign(&mut self, rhs: usize) {
        self.0 >>= rhs;
    }
}

// --- num-traits ---

impl<const BITS: usize, const LIMBS: usize> Zero for RUint<BITS, LIMBS> {
    fn zero() -> Self {
        Self::zero()
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}
impl<const BITS: usize, const LIMBS: usize> One for RUint<BITS, LIMBS> {
    fn one() -> Self {
        Self(Uint::from(1u64))
    }
}
impl<const BITS: usize, const LIMBS: usize> WrappingAdd for RUint<BITS, LIMBS> {
    fn wrapping_add(&self, v: &Self) -> Self {
        Self(self.0.wrapping_add(v.0))
    }
}
impl<const BITS: usize, const LIMBS: usize> WrappingSub for RUint<BITS, LIMBS> {
    fn wrapping_sub(&self, v: &Self) -> Self {
        Self(self.0.wrapping_sub(v.0))
    }
}
impl<const BITS: usize, const LIMBS: usize> WrappingMul for RUint<BITS, LIMBS> {
    fn wrapping_mul(&self, v: &Self) -> Self {
        Self(self.0 * v.0)
    }
}
impl<const BITS: usize, const LIMBS: usize> WrappingNeg for RUint<BITS, LIMBS> {
    fn wrapping_neg(&self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

// --- serde: tuple of limbs (generic-LIMBS-safe, no allocation) ---

impl<const BITS: usize, const LIMBS: usize> Serialize for RUint<BITS, LIMBS> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tup = serializer.serialize_tuple(LIMBS)?;
        for limb in self.0.as_limbs() {
            tup.serialize_element(limb)?;
        }
        tup.end()
    }
}

impl<'de, const BITS: usize, const LIMBS: usize> Deserialize<'de> for RUint<BITS, LIMBS> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LimbsVisitor<const BITS: usize, const LIMBS: usize>;
        impl<'de, const BITS: usize, const LIMBS: usize> Visitor<'de> for LimbsVisitor<BITS, LIMBS> {
            type Value = RUint<BITS, LIMBS>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "{LIMBS} u64 limbs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut limbs = [0u64; LIMBS];
                for (i, limb) in limbs.iter_mut().enumerate() {
                    *limb = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(RUint(Uint::from_limbs(limbs)))
            }
        }
        deserializer.deserialize_tuple(LIMBS, LimbsVisitor::<BITS, LIMBS>)
    }
}

// --- ark-serialize: flat little-endian bytes, LIMBS * 8 wide ---

impl<const BITS: usize, const LIMBS: usize> CanonicalSerialize for RUint<BITS, LIMBS> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), SerializationError> {
        for limb in self.0.as_limbs() {
            writer.write_all(&limb.to_le_bytes())?;
        }
        Ok(())
    }
    fn serialized_size(&self, _compress: Compress) -> usize {
        LIMBS * 8
    }
}
impl<const BITS: usize, const LIMBS: usize> Valid for RUint<BITS, LIMBS> {
    fn check(&self) -> Result<(), SerializationError> {
        // Every bit pattern is valid because BITS == LIMBS * 64.
        Ok(())
    }
}
impl<const BITS: usize, const LIMBS: usize> CanonicalDeserialize for RUint<BITS, LIMBS> {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        _compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let mut limbs = [0u64; LIMBS];
        let mut buf = [0u8; 8];
        for limb in &mut limbs {
            reader.read_exact(&mut buf)?;
            *limb = u64::from_le_bytes(buf);
        }
        Ok(Self(Uint::from_limbs(limbs)))
    }
}

// --- rand ---

impl<const BITS: usize, const LIMBS: usize> rand::distributions::Distribution<RUint<BITS, LIMBS>>
    for rand::distributions::Standard
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> RUint<BITS, LIMBS> {
        let mut limbs = [0u64; LIMBS];
        for limb in &mut limbs {
            *limb = rng.r#gen();
        }
        RUint(Uint::from_limbs(limbs))
    }
}

// --- AsPrimitive lattice (mirrors the old bespoke U512/U1024 impls) ---

impl<const BITS: usize, const LIMBS: usize> AsPrimitive<Self> for RUint<BITS, LIMBS> {
    fn as_(self) -> Self {
        self
    }
}
impl<const BITS: usize, const LIMBS: usize> AsPrimitive<u128> for RUint<BITS, LIMBS> {
    fn as_(self) -> u128 {
        let limbs = self.0.as_limbs();
        let lo = limbs[0] as u128;
        let hi = if LIMBS > 1 { limbs[1] as u128 } else { 0 };
        (hi << 64) | lo
    }
}
macro_rules! impl_as_primitive_down {
    ($($t:ty),*) => {$(
        impl<const BITS: usize, const LIMBS: usize> AsPrimitive<$t> for RUint<BITS, LIMBS> {
            fn as_(self) -> $t {
                self.0.as_limbs()[0] as $t
            }
        }
    )*};
}
impl_as_primitive_down!(u8, u16, u32, u64);

impl<const BITS: usize, const LIMBS: usize> AsPrimitive<Bit> for RUint<BITS, LIMBS> {
    fn as_(self) -> Bit {
        Bit::new(!self.0.is_zero())
    }
}
macro_rules! impl_as_primitive_up {
    ($($t:ty),*) => {$(
        impl<const BITS: usize, const LIMBS: usize> AsPrimitive<RUint<BITS, LIMBS>> for $t {
            fn as_(self) -> RUint<BITS, LIMBS> {
                RUint(Uint::from(self))
            }
        }
    )*};
}
impl_as_primitive_up!(u8, u16, u32, u64, u128);

impl<const BITS: usize, const LIMBS: usize> AsPrimitive<RUint<BITS, LIMBS>> for Bit {
    fn as_(self) -> RUint<BITS, LIMBS> {
        RUint(Uint::from(self.convert() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uint::{U256, U512};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use num_traits::{One, WrappingAdd, WrappingSub};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn ruint_wrapping_arithmetic() {
        // NOTE: `U256(...)` (tuple-struct call through a type alias) does not
        // compile in Rust even though `U256 = RUint<256, 4>` is a concrete
        // alias; constructing via the underlying `RUint` name instead.
        let max: U256 = RUint(ruint::Uint::MAX);
        let one = U256::one();
        // + is wrapping in ruint
        assert_eq!(max.wrapping_add(&one), U256::zero());
        assert_eq!(U256::zero().wrapping_sub(&one), max);
        assert_eq!(max + one, U256::zero());
    }

    #[test]
    fn ruint_shifts_are_wrapping() {
        let one = U256::one();
        assert_eq!(one << 256, U256::zero());
        assert_eq!(one << 255 >> 255, one);
    }

    #[test]
    fn ruint_display_matches_padded_hex() {
        let v = U256::from(0xabu64);
        assert_eq!(
            v.to_string(),
            "0x00000000000000000000000000000000000000000000000000000000000000ab"
        );
    }

    #[test]
    fn ruint_canonical_serialization_roundtrip_fixed_size() {
        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let v: U512 = rng.r#gen();
        let mut bytes = Vec::new();
        v.serialize_uncompressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64); // flat, no length prefix
        let back = U512::deserialize_uncompressed(&*bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn ruint_serde_roundtrip() {
        let mut rng = ChaCha12Rng::seed_from_u64(43);
        let v: U256 = rng.r#gen();
        let ser = bincode::serialize(&v).unwrap();
        let back: U256 = bincode::deserialize(&ser).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn ruint_as_primitive_roundtrip() {
        use num_traits::AsPrimitive;
        let v: u128 = 0x1122334455667788_99aabbccddeeff00;
        let u: U256 = v.as_();
        let back: u128 = u.as_();
        assert_eq!(v, back);
        let trunc: u8 = u.as_();
        assert_eq!(trunc, 0x00);
    }

    #[test]
    fn ruint_try_into_usize() {
        assert_eq!(usize::try_from(U256::from(17u64)), Ok(17usize));
        let max: U256 = RUint(ruint::Uint::MAX);
        assert!(usize::try_from(max).is_err());
    }
}
