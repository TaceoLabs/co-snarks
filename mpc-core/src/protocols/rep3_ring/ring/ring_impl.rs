//! RingImpl
//!
//! This type is a wrapper for all datatypes implementing the [`IntRing2k`] trait. The purpose is explicitly allowing wrapping arithmetic opearations.

use super::int_ring::IntRing2k;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use num_traits::{One, Zero};
use rand::{
    Rng,
    distributions::{Distribution, Standard},
};
use serde::{Deserialize, Serialize};
use std::{
    mem::ManuallyDrop,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul,
        MulAssign, Neg, Not, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
    },
};

/// The RingElement type is a wrapper for all datatypes implementing the [`IntRing2k`] trait to explicitly allow wrapping arithmetic opearations.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash,
)]
#[serde(bound = "")]
#[repr(transparent)]
pub struct RingElement<T: IntRing2k + std::fmt::Display>(pub T);

impl<T: IntRing2k> RingElement<T> {
    /// Transform a slice of RingElement into a slice of T
    // Safe because RingElement has repr(transparent)
    pub fn convert_slice_rev(vec: &[T]) -> &[Self] {
        // SAFETY: RingElement has repr(transparent)
        unsafe { &*(vec as *const [T] as *const [Self]) }
    }

    /// Transfroms a vector of T into a vector of RingElements
    // Safe because RingElement has repr(transparent)
    pub fn convert_vec_rev(vec: Vec<T>) -> Vec<Self> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: RingElement has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self, me.len(), me.capacity()) }
    }

    /// Unwraps the RingElement into the inner type
    pub fn convert(self) -> T {
        self.0
    }

    /// Returns the effective number of bits (i.e., how many LSBs are set)
    pub fn bits(&self) -> usize {
        self.0.bits()
    }

    fn from_reader<R: std::io::Read>(reader: R) -> std::io::Result<Self> {
        let res = T::from_reader(reader)?;
        Ok(RingElement(res))
    }
    fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
        T::write(&self.0, writer)
    }

    /// Returns the bit at the given index
    pub fn get_bit(&self, index: usize) -> Self {
        RingElement((self.0 >> index) & T::one())
    }
}

impl<T: IntRing2k + std::fmt::Display> std::fmt::Display for RingElement<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl<T: IntRing2k> Add for RingElement<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(&rhs.0))
    }
}

impl<T: IntRing2k> Add<&Self> for RingElement<T> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.wrapping_add(&rhs.0))
    }
}

impl<T: IntRing2k> AddAssign for RingElement<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.0.wrapping_add_assign(&rhs.0)
    }
}

impl<T: IntRing2k> AddAssign<&Self> for RingElement<T> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0.wrapping_add_assign(&rhs.0)
    }
}

impl<T: IntRing2k> Sub for RingElement<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_sub(&rhs.0))
    }
}

impl<T: IntRing2k> Sub<&Self> for RingElement<T> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.wrapping_sub(&rhs.0))
    }
}

impl<T: IntRing2k> SubAssign for RingElement<T> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.wrapping_sub_assign(&rhs.0)
    }
}

impl<T: IntRing2k> SubAssign<&Self> for RingElement<T> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0.wrapping_sub_assign(&rhs.0)
    }
}

impl<T: IntRing2k> Mul<T> for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs))
    }
}

impl<T: IntRing2k> Mul<&T> for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: &T) -> Self::Output {
        Self(self.0.wrapping_mul(rhs))
    }
}

impl<T: IntRing2k> Mul for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs.0))
    }
}

impl<T: IntRing2k> Mul<&Self> for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs.0))
    }
}

impl<T: IntRing2k> MulAssign for RingElement<T> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0.wrapping_mul_assign(&rhs.0)
    }
}

impl<T: IntRing2k> MulAssign<&Self> for RingElement<T> {
    fn mul_assign(&mut self, rhs: &Self) {
        self.0.wrapping_mul_assign(&rhs.0)
    }
}

impl<T: IntRing2k> MulAssign<T> for RingElement<T> {
    fn mul_assign(&mut self, rhs: T) {
        self.0.wrapping_mul_assign(&rhs)
    }
}

impl<T: IntRing2k> MulAssign<&T> for RingElement<T> {
    fn mul_assign(&mut self, rhs: &T) {
        self.0.wrapping_mul_assign(rhs)
    }
}

impl<T: IntRing2k> Zero for RingElement<T> {
    fn zero() -> Self {
        Self(T::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<T: IntRing2k> One for RingElement<T> {
    fn one() -> Self {
        Self(T::one())
    }
}

impl<T: IntRing2k> Neg for RingElement<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.wrapping_neg())
    }
}

impl<T: IntRing2k> Distribution<RingElement<T>> for Standard
where
    Standard: Distribution<T>,
{
    #[inline(always)]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RingElement<T> {
        RingElement(rng.r#gen())
    }
}

impl<T: IntRing2k> Not for RingElement<T> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl<T: IntRing2k> Not for &RingElement<T> {
    type Output = RingElement<T>;

    fn not(self) -> Self::Output {
        RingElement(!self.0)
    }
}

impl<T: IntRing2k> BitXor for RingElement<T> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        RingElement(self.0 ^ rhs.0)
    }
}

impl<T: IntRing2k> BitXor<&Self> for RingElement<T> {
    type Output = Self;

    fn bitxor(self, rhs: &Self) -> Self::Output {
        RingElement(self.0 ^ rhs.0)
    }
}

impl<T: IntRing2k> BitXorAssign for RingElement<T> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<T: IntRing2k> BitXorAssign<&Self> for RingElement<T> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.0 ^= rhs.0;
    }
}

impl<T: IntRing2k> BitOr for RingElement<T> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        RingElement(self.0 | rhs.0)
    }
}

impl<T: IntRing2k> BitOr<&Self> for RingElement<T> {
    type Output = Self;

    fn bitor(self, rhs: &Self) -> Self::Output {
        RingElement(self.0 | rhs.0)
    }
}

impl<T: IntRing2k> BitOrAssign for RingElement<T> {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl<T: IntRing2k> BitOrAssign<&Self> for RingElement<T> {
    fn bitor_assign(&mut self, rhs: &Self) {
        self.0 |= rhs.0;
    }
}

impl<T: IntRing2k> BitAnd for RingElement<T> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        RingElement(self.0 & rhs.0)
    }
}

impl<T: IntRing2k> BitAnd<&Self> for RingElement<T> {
    type Output = Self;

    fn bitand(self, rhs: &Self) -> Self::Output {
        RingElement(self.0 & rhs.0)
    }
}

impl<T: IntRing2k> BitAndAssign for RingElement<T> {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl<T: IntRing2k> BitAndAssign<&Self> for RingElement<T> {
    fn bitand_assign(&mut self, rhs: &Self) {
        self.0 &= rhs.0;
    }
}

impl<T: IntRing2k> Shl<usize> for RingElement<T> {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        if rhs >= T::K {
            RingElement(T::zero())
        } else {
            RingElement(self.0 << rhs)
        }
    }
}

impl<T: IntRing2k> ShlAssign<usize> for RingElement<T> {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs
    }
}

impl<T: IntRing2k> Shr<usize> for RingElement<T> {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        if rhs >= T::K {
            RingElement(T::zero())
        } else {
            RingElement(self.0 >> rhs)
        }
    }
}

impl<T: IntRing2k> ShrAssign<usize> for RingElement<T> {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs
    }
}

impl<T: IntRing2k> CanonicalSerialize for RingElement<T> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        Self::write(self, writer).map_err(ark_serialize::SerializationError::IoError)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        T::BYTES
    }
}

impl<T: IntRing2k> Valid for RingElement<T> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }

    fn batch_check<'a>(
        _batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        Self: 'a,
    {
        Ok(())
    }
}

impl<T: IntRing2k> CanonicalDeserialize for RingElement<T> {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::from_reader(reader).map_err(ark_serialize::SerializationError::IoError)
    }
}

impl<T: IntRing2k> From<T> for RingElement<T> {
    fn from(other: T) -> Self {
        RingElement(other)
    }
}

#[cfg(test)]
mod unsafe_test {
    use super::*;
    use crate::protocols::rep3_ring::ring::bit::Bit;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    const ELEMENTS: usize = 100;

    fn conversion_test<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = ChaCha12Rng::from_entropy();
        let t_vec: Vec<T> = (0..ELEMENTS).map(|_| rng.r#gen()).collect();

        // Convert vec<T> to vec<R<T>>
        let t_conv = RingElement::convert_vec_rev(t_vec.to_owned());
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.0, *b)
        }

        // Convert slice vec<T> to vec<R<T>>
        let t_conv = RingElement::convert_slice_rev(&t_vec);
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.0, *b)
        }
    }

    macro_rules! test_impl {
        ($([$ty:ty,$fn:ident]),*) => ($(
            #[test]
            fn $fn() {
                conversion_test::<$ty>();
            }
        )*)
    }

    test_impl! {
        [Bit, bit_test],
        [u8, u8_test],
        [u16, u16_test],
        [u32, u32_test],
        [u64, u64_test],
        [u128, u128_test]
    }
}
