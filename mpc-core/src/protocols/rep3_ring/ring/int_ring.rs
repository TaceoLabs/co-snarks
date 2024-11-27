//! IntRing
//!
//! Contains the IntRing2k trait that specifies different datatypes for rings Z_{2^k}

use super::bit::Bit;
use crate::protocols::rep3::IoResult;
use num_bigint::BigUint;
use num_traits::{AsPrimitive, One, WrappingAdd, WrappingMul, WrappingNeg, WrappingSub, Zero};
use serde::{Deserialize, Serialize};
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
    + Into<u128>
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
    /// Specifies the signed version of this type
    type Signed: Neg<Output = Self::Signed> + From<bool> + AsPrimitive<Self>;

    /// Specifies the number of bits in this type
    const K: usize;

    /// Specifies the number of bytes used for storage in this type
    const BYTES: usize;

    /// Reads a value of this type from a reader
    fn from_reader<R: std::io::Read>(reader: R) -> IoResult<Self>;

    /// Writes a value of this type to a writer
    fn write<W: std::io::Write>(&self, writer: W) -> IoResult<()>;

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
    type Signed = Bit;
    const K: usize = 1;
    const BYTES: usize = 1;

    fn write<W: std::io::Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(&[self.0 as u8])
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> IoResult<Self> {
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
    type Signed = i8;
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> IoResult<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u16 {
    type Signed = i16;
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> IoResult<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u32 {
    type Signed = i32;
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> IoResult<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u64 {
    type Signed = i64;
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> IoResult<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        biguint.iter_u64_digits().next().unwrap_or_default() as Self
    }
}

impl IntRing2k for u128 {
    type Signed = i128;
    const K: usize = Self::BITS as usize;
    const BYTES: usize = Self::K / 8;

    fn write<W: std::io::Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(&self.to_le_bytes())
    }

    fn from_reader<R: std::io::Read>(mut reader: R) -> IoResult<Self> {
        let mut bytes = [0u8; Self::BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_le_bytes(bytes))
    }

    fn bits(&self) -> usize {
        if *self == 0 {
            return 0;
        }
        self.ilog2() as usize
    }

    fn cast_to_biguint(&self) -> BigUint {
        BigUint::from(*self)
    }

    fn cast_from_biguint(biguint: &BigUint) -> Self {
        let mut iter = biguint.iter_u64_digits();
        let x0 = iter.next().unwrap_or_default();
        let x1 = iter.next().unwrap_or_default();
        (x1 as u128) << 64 | x0 as u128
    }
}
