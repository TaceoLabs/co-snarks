//! # Shamir Shared Field Elements
//!
//! This module contains the implementation of Shamir-shared field elements.

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::Itertools;
use std::mem::ManuallyDrop;

use crate::traits::{Iterable, IterableMut, Viewable, ViewableMut};

/// This type represents a Shamir-shared value. Since a Shamir-share of a field element is a field element, this is a wrapper over a field element.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct ShamirPrimeFieldShare<F: PrimeField> {
    pub(crate) a: F,
}

impl<F: PrimeField> ShamirPrimeFieldShare<F> {
    /// Wraps the field element into a ShamirPrimeFieldShare
    pub fn new(a: F) -> Self {
        Self { a }
    }

    /// Unwraps a ShamirPrimeFieldShare into a field element
    pub fn inner(self) -> F {
        self.a
    }
}

impl<F: PrimeField> std::ops::Add for ShamirPrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { a: self.a + rhs.a }
    }
}

impl<F: PrimeField> std::ops::Add<&ShamirPrimeFieldShare<F>> for ShamirPrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self { a: self.a + rhs.a }
    }
}

impl<F: PrimeField> std::ops::Add<&ShamirPrimeFieldShare<F>> for &'_ ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn add(self, rhs: &ShamirPrimeFieldShare<F>) -> Self::Output {
        ShamirPrimeFieldShare::<F> { a: self.a + rhs.a }
    }
}

impl<F: PrimeField> std::ops::Add<&F> for &'_ ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn add(self, rhs: &F) -> Self::Output {
        Self::Output { a: self.a + rhs }
    }
}

impl<F: PrimeField> std::ops::Add<F> for ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn add(self, rhs: F) -> Self::Output {
        Self::Output { a: self.a + rhs }
    }
}

impl<F: PrimeField> std::ops::Sub for ShamirPrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self { a: self.a - rhs.a }
    }
}

impl<F: PrimeField> std::ops::Sub<&ShamirPrimeFieldShare<F>> for ShamirPrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self { a: self.a - rhs.a }
    }
}

impl<F: PrimeField> std::ops::Sub<&ShamirPrimeFieldShare<F>> for &'_ ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn sub(self, rhs: &ShamirPrimeFieldShare<F>) -> Self::Output {
        ShamirPrimeFieldShare::<F> { a: self.a - rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul for ShamirPrimeFieldShare<F> {
    type Output = Self;

    // Result has higher degree than the inputs
    fn mul(self, rhs: Self) -> Self::Output {
        ShamirPrimeFieldShare::<F> { a: self.a * rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul<&ShamirPrimeFieldShare<F>> for ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    // Result has higher degree than the inputs
    fn mul(self, rhs: &Self) -> Self::Output {
        ShamirPrimeFieldShare::<F> { a: self.a * rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul<&ShamirPrimeFieldShare<F>> for &'_ ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    // Result has higher degree than the inputs
    fn mul(self, rhs: &ShamirPrimeFieldShare<F>) -> Self::Output {
        ShamirPrimeFieldShare::<F> { a: self.a * rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul<&F> for &'_ ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        Self::Output { a: self.a * rhs }
    }
}

impl<F: PrimeField> std::ops::Mul<F> for ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn mul(self, rhs: F) -> Self::Output {
        Self::Output { a: self.a * rhs }
    }
}

impl<F: PrimeField> std::ops::Neg for ShamirPrimeFieldShare<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self { a: -self.a }
    }
}
impl<F: PrimeField> std::ops::Neg for &ShamirPrimeFieldShare<F> {
    type Output = ShamirPrimeFieldShare<F>;

    fn neg(self) -> Self::Output {
        ShamirPrimeFieldShare::<F> { a: -self.a }
    }
}

/// This type represents a vector of Shamir-shared values. Since a Shamir-share of a field element is a field element, this is a wrapper over a vector of field elements.
#[derive(Debug, Clone, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShamirPrimeFieldShareVec<F: PrimeField> {
    pub(crate) a: Vec<F>,
}

impl<F: PrimeField> ShamirPrimeFieldShareVec<F> {
    /// Wraps the vector into a ShamirPrimeFieldShareVec
    pub fn new(a: Vec<F>) -> Self {
        Self { a }
    }

    /// Unwraps a ShamirPrimeFieldShareVec into a vector
    pub fn get_inner(self) -> Vec<F> {
        self.a
    }

    /// Checks whether the wrapped vector is empty.
    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    /// Returns the length of the wrapped vector.
    pub fn len(&self) -> usize {
        self.a.len()
    }
}

impl<F: PrimeField> From<Vec<ShamirPrimeFieldShare<F>>> for ShamirPrimeFieldShareVec<F> {
    fn from(v: Vec<ShamirPrimeFieldShare<F>>) -> Self {
        // TODO: Transparent struct, so can it be coded better?
        let a = v.into_iter().map(|x| x.a).collect();
        Self { a }
    }
}

impl<F: PrimeField> std::ops::Add for ShamirPrimeFieldShareVec<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a.iter().zip(rhs.a).map(|(a, b)| *a + b).collect(),
        }
    }
}

impl<F: PrimeField> IntoIterator for ShamirPrimeFieldShareVec<F> {
    type Item = ShamirPrimeFieldShare<F>;
    type IntoIter = std::vec::IntoIter<ShamirPrimeFieldShare<F>>;

    fn into_iter(self) -> Self::IntoIter {
        // TODO: can we save this collect? cannot name map type directly yet
        self.a
            .into_iter()
            .map(ShamirPrimeFieldShare::new)
            .collect_vec()
            .into_iter()
    }
}

// Conversions
impl<F: PrimeField> ShamirPrimeFieldShare<F> {
    /// Transforms a slice of `ShamirPrimeFieldShare<F>` to a slice of `F`
    // Safe because ShamirPrimeFieldShare has repr(transparent)
    pub fn convert_slice(vec: &[Self]) -> &[F] {
        // SAFETY: ShamirPrimeFieldShare has repr(transparent)
        unsafe { &*(vec as *const [Self] as *const [F]) }
    }

    /// Transforms a vector of `ShamirPrimeFieldShare<F>` to a vector of `F`
    // Safe because ShamirPrimeFieldShare has repr(transparent)
    pub fn convert_vec(vec: Vec<Self>) -> Vec<F> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: ShamirPrimeFieldShare has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut F, me.len(), me.capacity()) }
    }

    /// Transforms a slice of `F` to a slice of `ShamirPrimeFieldShare<F>`
    // Safe because ShamirPrimeFieldShare has repr(transparent)
    pub fn convert_slice_rev(vec: &[F]) -> &[Self] {
        // SAFETY: ShamirPrimeFieldShare has repr(transparent)
        unsafe { &*(vec as *const [F] as *const [Self]) }
    }

    /// Transforms a vector of `F` to a vector of `ShamirPrimeFieldShare<F>`
    // Safe because ShamirPrimeFieldShare has repr(transparent)
    pub fn convert_vec_rev(vec: Vec<F>) -> Vec<Self> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: ShamirPrimeFieldShare has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self, me.len(), me.capacity()) }
    }

    /// Transforms a `ShamirPrimeFieldShare<F>` to `F`
    pub fn convert(self) -> F {
        self.a
    }
}

#[cfg(test)]
mod unsafe_test {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    const ELEMENTS: usize = 100;

    fn conversion_test<F: PrimeField>() {
        let mut rng = ChaCha12Rng::from_entropy();
        let t_vec: Vec<F> = (0..ELEMENTS).map(|_| F::rand(&mut rng)).collect();
        let rt_vec: Vec<ShamirPrimeFieldShare<F>> = (0..ELEMENTS)
            .map(|_| ShamirPrimeFieldShare::new(F::rand(&mut rng)))
            .collect();

        // Convert vec<F> to vec<G<F>>
        let t_conv = ShamirPrimeFieldShare::convert_vec_rev(t_vec.to_owned());
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.a, *b)
        }

        // Convert slice vec<F> to vec<G<F>>
        let t_conv = ShamirPrimeFieldShare::convert_slice_rev(&t_vec);
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.a, *b)
        }

        // Convert vec<G<F>> to vec<F>
        let rt_conv = ShamirPrimeFieldShare::convert_vec(rt_vec.to_owned());
        assert_eq!(rt_conv.len(), rt_vec.len());
        for (a, b) in rt_conv.iter().zip(rt_vec.iter()) {
            assert_eq!(*a, b.a)
        }

        // Convert slice vec<G<F>> to vec<F>
        let rt_conv = ShamirPrimeFieldShare::convert_slice(&rt_vec);
        assert_eq!(rt_conv.len(), rt_vec.len());
        for (a, b) in rt_conv.iter().zip(rt_vec.iter()) {
            assert_eq!(*a, b.a)
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
        [ark_bn254::Fr, bn254_test]
    }
}
pub struct ShamirPrimeFieldShareView<'a, F> {
    pub(crate) a: &'a F,
}

impl<F: PrimeField> Iterable for ShamirPrimeFieldShareVec<F> {
    type Item<'a> = ShamirPrimeFieldShareView<'a, F>;
    type Iter<'a> = ShamirPrimeFieldShareVecIter<'a, F>;

    fn iter<'a>(&'a self) -> Self::Iter<'a> {
        ShamirPrimeFieldShareVecIter { a: self.a.iter() }
    }
}

pub struct ShamirPrimeFieldShareVecIter<'a, F> {
    a: std::slice::Iter<'a, F>,
}

impl<'a, F: PrimeField> Iterator for ShamirPrimeFieldShareVecIter<'a, F> {
    type Item = ShamirPrimeFieldShareView<'a, F>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(ShamirPrimeFieldShareView { a: self.a.next()? })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.a.size_hint()
    }
}

pub struct ShamirPrimeFieldShareViewMut<'a, F> {
    pub(crate) a: &'a mut F,
}

impl<F: PrimeField> IterableMut for ShamirPrimeFieldShareVec<F> {
    type Item<'a> = ShamirPrimeFieldShareViewMut<'a, F>;
    type Iter<'a> = ShamirPrimeFieldShareVecIterMut<'a, F>;

    fn iter_mut<'a>(&'a mut self) -> Self::Iter<'a> {
        ShamirPrimeFieldShareVecIterMut {
            a: self.a.iter_mut(),
        }
    }
}
pub struct ShamirPrimeFieldShareVecIterMut<'a, F> {
    a: std::slice::IterMut<'a, F>,
}

impl<'a, F: PrimeField> Iterator for ShamirPrimeFieldShareVecIterMut<'a, F> {
    type Item = ShamirPrimeFieldShareViewMut<'a, F>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(ShamirPrimeFieldShareViewMut { a: self.a.next()? })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.a.size_hint()
    }
}

impl<F: PrimeField> Viewable for ShamirPrimeFieldShare<F> {
    type Item<'a> = ShamirPrimeFieldShareView<'a, F>;
    fn view<'a>(&'a self) -> ShamirPrimeFieldShareView<'a, F> {
        ShamirPrimeFieldShareView { a: &self.a }
    }
}

impl<F: PrimeField> ViewableMut for ShamirPrimeFieldShare<F> {
    type Item<'a> = ShamirPrimeFieldShareViewMut<'a, F>;
    fn view_mut<'a>(&'a mut self) -> ShamirPrimeFieldShareViewMut<'a, F> {
        ShamirPrimeFieldShareViewMut { a: &mut self.a }
    }
}

impl<'b, F: PrimeField> Viewable for ShamirPrimeFieldShareView<'b, F> {
    type Item<'a> = ShamirPrimeFieldShareView<'a, F> where 'b: 'a;
    fn view<'a>(&'a self) -> ShamirPrimeFieldShareView<'a, F> {
        ShamirPrimeFieldShareView { a: &self.a }
    }
}

impl<'b, F: PrimeField> Viewable for ShamirPrimeFieldShareViewMut<'b, F> {
    type Item<'a> = ShamirPrimeFieldShareView<'a, F> where 'b: 'a;
    fn view<'a>(&'a self) -> ShamirPrimeFieldShareView<'a, F> {
        ShamirPrimeFieldShareView { a: &self.a }
    }
}

impl<'b, F: PrimeField> ViewableMut for ShamirPrimeFieldShareViewMut<'b, F> {
    type Item<'a> = ShamirPrimeFieldShareViewMut<'a, F> where 'b: 'a;
    fn view_mut<'a>(&'a mut self) -> ShamirPrimeFieldShareViewMut<'a, F> {
        ShamirPrimeFieldShareViewMut { a: &mut self.a }
    }
}
