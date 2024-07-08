//! # Rep3 Shared Curve Points
//!
//! This module contains the implementation of rep3-shared curve points.

use super::Rep3PrimeFieldShare;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// This type represents a replicated shared point. Since a replicated share of a point contains additive shares of two parties, this type contains two point.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3PointShare<C: CurveGroup> {
    pub(crate) a: C,
    pub(crate) b: C,
}
impl<C: CurveGroup> Rep3PointShare<C> {
    /// Constructs the type from two additive shares.
    pub fn new(a: C, b: C) -> Self {
        Self { a, b }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (C, C) {
        (self.a, self.b)
    }
}

impl<C: CurveGroup> std::ops::Add for Rep3PointShare<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Add<&Rep3PointShare<C>> for Rep3PointShare<C> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Add<&Rep3PointShare<C>> for &'_ Rep3PointShare<C> {
    type Output = Rep3PointShare<C>;

    fn add(self, rhs: &Rep3PointShare<C>) -> Self::Output {
        Rep3PointShare::<C> {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::AddAssign<&Rep3PointShare<C>> for Rep3PointShare<C> {
    fn add_assign(&mut self, rhs: &Self) {
        self.a += rhs.a;
        self.b += rhs.b;
    }
}

impl<C: CurveGroup> std::ops::Sub for Rep3PointShare<C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Sub<&Rep3PointShare<C>> for Rep3PointShare<C> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}
impl<C: CurveGroup> std::ops::Sub<&Rep3PointShare<C>> for &'_ Rep3PointShare<C> {
    type Output = Rep3PointShare<C>;

    fn sub(self, rhs: &Rep3PointShare<C>) -> Self::Output {
        Rep3PointShare::<C> {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::SubAssign<&Rep3PointShare<C>> for Rep3PointShare<C> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.a -= rhs.a;
        self.b -= rhs.b;
    }
}

impl<C: CurveGroup> std::ops::Mul<&C::ScalarField> for &'_ Rep3PointShare<C> {
    type Output = Rep3PointShare<C>;

    fn mul(self, scalar: &C::ScalarField) -> Self::Output {
        Self::Output {
            a: self.a * scalar,
            b: self.b * scalar,
        }
    }
}

impl<C: CurveGroup> std::ops::Mul<&Rep3PointShare<C>> for &'_ Rep3PrimeFieldShare<C::ScalarField> {
    type Output = C;

    // Local part of mul only
    fn mul(self, rhs: &Rep3PointShare<C>) -> Self::Output {
        rhs.a * self.a + rhs.b * self.a + rhs.a * self.b
    }
}
