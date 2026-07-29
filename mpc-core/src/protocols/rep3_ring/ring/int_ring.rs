//! IntRing
//!
//! Contains the IntRing2k trait that specifies different datatypes for rings Z_{2^k}

use super::bit::Bit;
use crate::uint::{RUint, UintBackend};
use num_bigint::BigUint;
use num_traits::{AsPrimitive, One, WrappingAdd, WrappingMul, WrappingNeg, WrappingSub, Zero};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr},
};

pub use crate::uint::{U512, U1024};

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

    /// Casts this type to a fixed-width uint, zero-extending if the target
    /// is wider and truncating excess bits if it is narrower
    fn cast_to_uint<U: UintBackend>(&self) -> U;

    /// Casts a fixed-width uint to this type, removing any excess bits
    /// Thus if the value is larger than this type, it will be truncated
    fn cast_from_uint<U: UintBackend>(u: &U) -> Self;

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

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from(self.convert())
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        Bit::new(!u.is_zero())
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

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from(*self as u64)
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        u.to_u64_truncating() as Self
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

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from(*self as u64)
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        u.to_u64_truncating() as Self
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

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from(*self as u64)
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        u.to_u64_truncating() as Self
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

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from(*self)
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        u.to_u64_truncating() as Self
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

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from_limbs_truncating(&[*self as u64, (*self >> 64) as u64])
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        let limbs = u.as_limbs();
        let x0 = limbs.first().copied().unwrap_or_default();
        let x1 = limbs.get(1).copied().unwrap_or_default();
        ((x1 as u128) << 64) | x0 as u128
    }
}

impl<const BITS: usize, const LIMBS: usize> IntRing2k for RUint<BITS, LIMBS> {
    const K: usize = BITS;
    const BYTES: usize = LIMBS * 8;

    fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut limbs = [0u64; LIMBS];
        let mut buf = [0u8; 8];
        for limb in &mut limbs {
            reader.read_exact(&mut buf)?;
            *limb = u64::from_le_bytes(buf);
        }
        Ok(Self(ruint::Uint::from_limbs(limbs)))
    }

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        for limb in self.0.as_limbs() {
            writer.write_all(&limb.to_le_bytes())?;
        }
        Ok(())
    }

    fn bits(&self) -> usize {
        self.0.bit_len()
    }

    fn cast_to_biguint(&self) -> BigUint {
        // temporary bridge; removed once all BigUint interchange is ported
        let mut bytes = vec![0u8; <Self as UintBackend>::BYTES];
        <Self as UintBackend>::to_le_bytes_into(self, &mut bytes);
        BigUint::from_bytes_le(&bytes)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        let mut limbs = [0u64; LIMBS];
        for (limb, digit) in limbs.iter_mut().zip(biguint.iter_u64_digits()) {
            *limb = digit;
        }
        Self(ruint::Uint::from_limbs(limbs))
    }

    fn cast_to_uint<U: UintBackend>(&self) -> U {
        U::from_limbs_truncating(<Self as UintBackend>::as_limbs(self))
    }

    fn cast_from_uint<U: UintBackend>(u: &U) -> Self {
        <Self as UintBackend>::from_limbs_truncating(u.as_limbs())
    }
}
