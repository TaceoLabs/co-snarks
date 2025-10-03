//! IntRing
//!
//! Contains the IntRing2k trait that specifies different datatypes for rings Z_{2^k}

use super::bit::Bit;
use num_bigint::BigUint;
use num_traits::ToBytes;
use num_traits::{AsPrimitive, One, WrappingAdd, WrappingMul, WrappingNeg, WrappingSub, Zero};
use ruint::Uint;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};
use std::ops::{ShlAssign, ShrAssign};
use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Neg, Not, Shl, Shr},
};

/// Types implementing this trait can be used as elements of a ring Z_{2^k}
pub trait IntRing2k:
    std::fmt::Display
    + Serialize
    + for<'a> Deserialize<'a>
    + WrappingAdd
    + WrappingSub
    + WrappingMul
    + WrappingNeg
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Not<Output = Self>
    + BitXor<Output = Self>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXorAssign
    + BitAndAssign
    + BitOrAssign
    + From<bool>
    + TryInto<usize, Error: Debug>
    + Copy
    + Debug
    + Zero
    + One
    + Sized
    + Send
    + Sync
    + TryFrom<u128, Error: Debug>
    + TryFrom<u64, Error: Debug>
    + PartialEq
    + PartialOrd
    + 'static
{
    /// Specifies the number of bits in this type
    const K: usize;

    /// Specifies the number of bytes used for storage in this type
    const BYTES: usize;

    /// Reads a value of this type from a reader
    fn from_reader<R: std::io::Read>(reader: R) -> std::io::Result<Self>;

    /// Writes a value of this type to a writer
    fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()>;

    /// Returns the effective number of bits (i.e., how many LSBs are set)
    fn bits(&self) -> usize;

    /// Casts this type to a BigUint
    fn cast_to_biguint(&self) -> BigUint;

    /// Casts a BigUint to this type, removing any excess bits
    /// Thus if the value is larger than this type, it will be truncated
    fn cast_from_biguint(biguint: &BigUint) -> Self;

    /// a += b
    #[inline(always)]
    fn wrapping_add_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_add(rhs);
    }

    /// a -= b
    #[inline(always)]
    fn wrapping_sub_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_sub(rhs);
    }

    /// a = -a
    #[inline(always)]
    fn wrapping_neg_inplace(&mut self) {
        *self = self.wrapping_neg();
    }

    /// a*= b
    #[inline(always)]
    fn wrapping_mul_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_mul(rhs);
    }
}

impl IntRing2k for Bit {
    const K: usize = 1;
    const BYTES: usize = 1;

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&[self.0 as u8])
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Bit::try_from(bytes[0])
    }

    fn bits(&self) -> usize {
        self.0 as usize
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(self.0 as u64)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default().as_()
    }
}

impl IntRing2k for u8 {
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize + 1
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u16 {
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize + 1
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u32 {
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize + 1
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u64 {
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize + 1
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u128 {
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize + 1
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        let mut iter = biguint.iter_u64_digits();
        let x0 = iter.next().unwrap_or_default();
        let x1 = iter.next().unwrap_or_default();
        ((x1 as u128) << 64) | x0 as u128
    }
}

/// 512-bit unsigned integer type
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct U512(pub Uint<512, 8>);

impl fmt::Display for U512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{}",
            hex::encode(self.0.to_be_bytes::<{ U512::BYTES }>())
        )
    }
}

impl Serialize for U512 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.to_le_bytes::<{ Self::BYTES }>();
        serializer.serialize_bytes(&bytes)
    }
}
impl<'de> Deserialize<'de> for U512 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct U512Visitor;

        impl<'de> serde::de::Visitor<'de> for U512Visitor {
            type Value = U512;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != U512::BYTES {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; U512::BYTES];
                arr.copy_from_slice(v);
                Ok(U512(Uint::<512, 8>::from_le_bytes(arr)))
            }
        }

        deserializer.deserialize_bytes(U512Visitor)
    }
}

// Basic conversions
impl From<bool> for U512 {
    fn from(v: bool) -> Self {
        U512(Uint::<512, 8>::from(if v { 1u8 } else { 0u8 }))
    }
}
impl From<u64> for U512 {
    fn from(v: u64) -> Self {
        U512(Uint::<512, 8>::from(v))
    }
}
impl From<u128> for U512 {
    fn from(v: u128) -> Self {
        U512(Uint::<512, 8>::from(v))
    }
}

impl TryFrom<U512> for usize {
    type Error = &'static str;
    fn try_from(v: U512) -> Result<Self, Self::Error> {
        v.0.try_into()
            .map_err(|_| "U512 value too large to fit into usize")
    }
}

// Bit operations
impl BitAnd for U512 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        U512(self.0 & rhs.0)
    }
}
impl BitOr for U512 {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        U512(self.0 | rhs.0)
    }
}
impl BitXor for U512 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        U512(self.0 ^ rhs.0)
    }
}
impl BitAndAssign for U512 {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl BitOrAssign for U512 {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl BitXorAssign for U512 {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Not for U512 {
    type Output = Self;
    fn not(self) -> Self::Output {
        U512(!self.0)
    }
}

impl Shl<usize> for U512 {
    type Output = Self;
    fn shl(self, rhs: usize) -> Self::Output {
        U512(self.0 << rhs)
    }
}
impl Shr<usize> for U512 {
    type Output = Self;
    fn shr(self, rhs: usize) -> Self::Output {
        U512(self.0 >> rhs)
    }
}
impl ShlAssign<usize> for U512 {
    fn shl_assign(&mut self, rhs: usize) {
        self.0 <<= rhs;
    }
}
impl ShrAssign<usize> for U512 {
    fn shr_assign(&mut self, rhs: usize) {
        self.0 >>= rhs;
    }
}

impl Neg for U512 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        U512(-self.0)
    }
}

impl std::ops::Add for U512 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        U512(self.0 + rhs.0)
    }
}
impl std::ops::Sub for U512 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        U512(self.0 - rhs.0)
    }
}
impl std::ops::Mul for U512 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        U512(self.0 * rhs.0)
    }
}

impl WrappingAdd for U512 {
    fn wrapping_add(&self, v: &Self) -> Self {
        U512(self.0 + v.0)
    }
}
impl WrappingSub for U512 {
    fn wrapping_sub(&self, v: &Self) -> Self {
        U512(self.0 - v.0)
    }
}
impl WrappingMul for U512 {
    fn wrapping_mul(&self, v: &Self) -> Self {
        U512(self.0 * v.0)
    }
}
impl WrappingNeg for U512 {
    fn wrapping_neg(&self) -> Self {
        -(*self)
    }
}

impl Zero for U512 {
    fn zero() -> Self {
        U512(Uint::<512, 8>::from(0u8))
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}
impl One for U512 {
    fn one() -> Self {
        U512(Uint::<512, 8>::from(1u8))
    }
}

impl AsPrimitive<U512> for U512 {
    fn as_(self) -> U512 {
        self
    }
}

impl IntRing2k for U512 {
    const K: usize = 512;
    const BYTES: usize = 64;

    fn from_reader<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(U512(Uint::<512, 8>::from_le_bytes(bytes)))
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_le_bytes::<{ Self::BYTES }>())
    }

    fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        self.0.bit_len()
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from_bytes_le(&self.0.to_le_bytes::<{ Self::BYTES }>())
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        let mut bytes = biguint.to_le_bytes();
        bytes.truncate(Self::BYTES);
        let mut arr = [0u8; Self::BYTES];
        arr[..bytes.len()].copy_from_slice(&bytes);
        U512(Uint::<512, 8>::from_le_bytes(arr))
    }
}

impl rand::distributions::Distribution<U512> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> U512 {
        let mut bytes = [0u8; U512::BYTES];
        rng.fill_bytes(&mut bytes);
        U512(Uint::<512, 8>::from_le_bytes(bytes))
    }
}

impl AsPrimitive<u128> for U512 {
    fn as_(self) -> u128 {
        let le = self.0.to_le_bytes::<{ U512::BYTES }>();
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&le[..16]);
        u128::from_le_bytes(arr)
    }
}

impl AsPrimitive<u64> for U512 {
    fn as_(self) -> u64 {
        let le = self.0.to_le_bytes::<{ U512::BYTES }>();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&le[..8]);
        u64::from_le_bytes(arr)
    }
}
impl AsPrimitive<u32> for U512 {
    fn as_(self) -> u32 {
        let le = self.0.to_le_bytes::<{ U512::BYTES }>();
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&le[..4]);
        u32::from_le_bytes(arr)
    }
}

impl AsPrimitive<u16> for U512 {
    fn as_(self) -> u16 {
        let le = self.0.to_le_bytes::<{ U512::BYTES }>();
        let mut arr = [0u8; 2];
        arr.copy_from_slice(&le[..2]);
        u16::from_le_bytes(arr)
    }
}
impl AsPrimitive<u8> for U512 {
    fn as_(self) -> u8 {
        let le = self.0.to_le_bytes::<{ U512::BYTES }>();
        le[0]
    }
}
impl AsPrimitive<Bit> for U512 {
    fn as_(self) -> Bit {
        Bit(!self.0.is_zero())
    }
}

impl AsPrimitive<U512> for u128 {
    fn as_(self) -> U512 {
        U512(Uint::<512, 8>::from(self))
    }
}
impl AsPrimitive<U512> for u64 {
    fn as_(self) -> U512 {
        U512(Uint::<512, 8>::from(self))
    }
}
impl AsPrimitive<U512> for u32 {
    fn as_(self) -> U512 {
        U512(Uint::<512, 8>::from(self))
    }
}
impl AsPrimitive<U512> for u16 {
    fn as_(self) -> U512 {
        U512(Uint::<512, 8>::from(self))
    }
}
impl AsPrimitive<U512> for u8 {
    fn as_(self) -> U512 {
        U512(Uint::<512, 8>::from(self))
    }
}
impl AsPrimitive<U512> for Bit {
    fn as_(self) -> U512 {
        U512(Uint::<512, 8>::from(if self.0 { 1u8 } else { 0u8 }))
    }
}
