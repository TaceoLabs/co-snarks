//! # Rep3 Shared Field Elements
//!
//! This module contains the implementation of rep3-shared field elements.

use super::id::PartyID;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::Itertools;

/// This type represents a replicated shared value. Since a replicated share of a field element contains additive shares of two parties, this type contains two field elements.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3PrimeFieldShare<F: PrimeField> {
    pub(crate) a: F,
    pub(crate) b: F,
}

impl<F: PrimeField> Rep3PrimeFieldShare<F> {
    /// Constructs the type from two additive shares.
    pub fn new(a: F, b: F) -> Self {
        Self { a, b }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (F, F) {
        (self.a, self.b)
    }

    pub(crate) fn double(&mut self) {
        self.a.double_in_place();
        self.b.double_in_place();
    }

    /// Promotes a public field element to a replicated share by setting the additive share of the party with id=0 and leaving all other shares to be 0. Thus, the replicated shares of party 0 and party 1 are set.
    pub fn promote_from_trivial(val: &F, id: PartyID) -> Self {
        match id {
            PartyID::ID0 => Rep3PrimeFieldShare::new(*val, F::zero()),
            PartyID::ID1 => Rep3PrimeFieldShare::new(F::zero(), *val),
            PartyID::ID2 => Rep3PrimeFieldShare::default(),
        }
    }
}

impl<F: PrimeField> std::ops::Add for Rep3PrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::Add<&Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::Add<&Rep3PrimeFieldShare<F>> for &'_ Rep3PrimeFieldShare<F> {
    type Output = Rep3PrimeFieldShare<F>;

    fn add(self, rhs: &Rep3PrimeFieldShare<F>) -> Self::Output {
        Rep3PrimeFieldShare::<F> {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::AddAssign<&Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    fn add_assign(&mut self, rhs: &Self) {
        self.a += rhs.a;
        self.b += rhs.b;
    }
}

impl<F: PrimeField> std::ops::AddAssign<Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.a += rhs.a;
        self.b += rhs.b;
    }
}

impl<F: PrimeField> std::ops::Sub for Rep3PrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::Sub<&Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::SubAssign<&Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.a -= rhs.a;
        self.b -= rhs.b;
    }
}

impl<F: PrimeField> std::ops::SubAssign<Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    fn sub_assign(&mut self, rhs: Self) {
        self.a -= rhs.a;
        self.b -= rhs.b;
    }
}

impl<F: PrimeField> std::ops::Sub<&Rep3PrimeFieldShare<F>> for &'_ Rep3PrimeFieldShare<F> {
    type Output = Rep3PrimeFieldShare<F>;

    fn sub(self, rhs: &Rep3PrimeFieldShare<F>) -> Self::Output {
        Rep3PrimeFieldShare::<F> {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::Mul for Rep3PrimeFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: Self) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: PrimeField> std::ops::Mul<&Rep3PrimeFieldShare<F>> for Rep3PrimeFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: &Self) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: PrimeField> std::ops::Mul<&Rep3PrimeFieldShare<F>> for &'_ Rep3PrimeFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: &Rep3PrimeFieldShare<F>) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: PrimeField> std::ops::Mul<&F> for &'_ Rep3PrimeFieldShare<F> {
    type Output = Rep3PrimeFieldShare<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: PrimeField> std::ops::Mul<F> for Rep3PrimeFieldShare<F> {
    type Output = Rep3PrimeFieldShare<F>;

    fn mul(self, rhs: F) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: PrimeField> std::ops::MulAssign<F> for Rep3PrimeFieldShare<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.a *= rhs;
        self.b *= rhs;
    }
}

impl<F: PrimeField> std::ops::Neg for Rep3PrimeFieldShare<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            a: -self.a,
            b: -self.b,
        }
    }
}
impl<F: PrimeField> std::ops::Neg for &Rep3PrimeFieldShare<F> {
    type Output = Rep3PrimeFieldShare<F>;

    fn neg(self) -> Self::Output {
        Rep3PrimeFieldShare::<F> {
            a: -self.a,
            b: -self.b,
        }
    }
}

impl<F: PrimeField> ark_ff::Zero for Rep3PrimeFieldShare<F> {
    fn zero() -> Self {
        Self {
            a: F::zero(),
            b: F::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        panic!("Not implemented");
    }
}

/// This type represents a vector of replicated shared value. Since a replicated share of a field element contains additive shares of two parties, this type contains two vectors of field elements.
#[derive(Debug, Clone, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3PrimeFieldShareVec<F: PrimeField> {
    pub a: Vec<F>,
    pub b: Vec<F>,
}

impl<F: PrimeField> Rep3PrimeFieldShareVec<F> {
    /// Constructs the type from two vectors of additive shares.
    pub fn new(a: Vec<F>, b: Vec<F>) -> Self {
        Self { a, b }
    }

    /// Unwraps the type into two vectors of additive shares.
    pub fn get_ab(self) -> (Vec<F>, Vec<F>) {
        (self.a, self.b)
    }

    /// Checks whether the wrapped vectors are empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.a.is_empty(), self.b.is_empty());
        self.a.is_empty()
    }

    /// Returns the length of the wrapped vectors.
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        self.a.len()
    }

    /// Promotes a vector of public field elements to a vector of replicated shares by setting the additive shares of the party with id=0 and leaving all other shares to be 0. Thus, the replicated shares of party 0 and party 1 are set.
    pub fn promote_from_trivial(val: &[F], id: PartyID) -> Self {
        let len = val.len();

        match id {
            PartyID::ID0 => {
                let a = val.to_vec();
                let b = vec![F::zero(); len];
                Self { a, b }
            }
            PartyID::ID1 => {
                let a = vec![F::zero(); len];
                let b = val.to_vec();
                Self { a, b }
            }
            PartyID::ID2 => {
                let a = vec![F::zero(); len];
                let b = vec![F::zero(); len];
                Self { a, b }
            }
        }
    }
}

impl<F: PrimeField> From<Vec<Rep3PrimeFieldShare<F>>> for Rep3PrimeFieldShareVec<F> {
    fn from(v: Vec<Rep3PrimeFieldShare<F>>) -> Self {
        let (a, b): (Vec<F>, Vec<F>) = v.into_iter().map(|share| (share.a, share.b)).unzip();
        Self { a, b }
    }
}

impl<F: PrimeField> std::ops::Add for Rep3PrimeFieldShareVec<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a.iter().zip(rhs.a).map(|(a, b)| *a + b).collect(),
            b: self.b.iter().zip(rhs.b).map(|(a, b)| *a + b).collect(),
        }
    }
}

impl<F: PrimeField> IntoIterator for Rep3PrimeFieldShareVec<F> {
    type Item = Rep3PrimeFieldShare<F>;
    type IntoIter = std::vec::IntoIter<Rep3PrimeFieldShare<F>>;

    fn into_iter(self) -> Self::IntoIter {
        self.a
            .into_iter()
            .zip(self.b)
            .map(|(a, b)| Rep3PrimeFieldShare::<F>::new(a, b))
            // TODO: can we save this collect? cannot name map type directly yet
            .collect_vec()
            .into_iter()
    }
}
