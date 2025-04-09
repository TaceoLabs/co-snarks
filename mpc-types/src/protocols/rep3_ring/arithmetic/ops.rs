use crate::protocols::rep3_ring::ring::{int_ring::IntRing2k, ring_impl::RingElement};

use super::types::Rep3RingShare;

impl<T: IntRing2k> std::ops::Add for Rep3RingShare<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Rep3RingShare {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}
impl<T: IntRing2k> std::ops::Add<&Rep3RingShare<T>> for &'_ Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn add(self, rhs: &Rep3RingShare<T>) -> Self::Output {
        Rep3RingShare {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<T: IntRing2k> std::ops::AddAssign<Rep3RingShare<T>> for Rep3RingShare<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.a += rhs.a;
        self.b += rhs.b;
    }
}

impl<T: IntRing2k> std::ops::AddAssign<&Rep3RingShare<T>> for Rep3RingShare<T> {
    fn add_assign(&mut self, rhs: &Rep3RingShare<T>) {
        self.a += rhs.a;
        self.b += rhs.b;
    }
}

impl<T: IntRing2k> std::ops::Sub for Rep3RingShare<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Rep3RingShare {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<T: IntRing2k> std::ops::Sub<&Rep3RingShare<T>> for &'_ Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn sub(self, rhs: &Rep3RingShare<T>) -> Self::Output {
        Rep3RingShare {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<T: IntRing2k> std::ops::SubAssign<Rep3RingShare<T>> for Rep3RingShare<T> {
    fn sub_assign(&mut self, rhs: Self) {
        self.a -= rhs.a;
        self.b -= rhs.b;
    }
}

impl<T: IntRing2k> std::ops::Mul for Rep3RingShare<T> {
    type Output = RingElement<T>;

    // Local part of mul only
    fn mul(self, rhs: Rep3RingShare<T>) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<T: IntRing2k> std::ops::Mul<RingElement<T>> for Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn mul(self, rhs: RingElement<T>) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::Mul<RingElement<T>> for &Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn mul(self, rhs: RingElement<T>) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::Mul<&Rep3RingShare<T>> for &'_ Rep3RingShare<T> {
    type Output = RingElement<T>;

    // Local part of mul only
    fn mul(self, rhs: &Rep3RingShare<T>) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<T: IntRing2k> std::ops::MulAssign<RingElement<T>> for Rep3RingShare<T> {
    fn mul_assign(&mut self, rhs: RingElement<T>) {
        self.a *= rhs;
        self.b *= rhs;
    }
}

impl<T: IntRing2k> std::ops::Neg for Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn neg(self) -> Self::Output {
        Rep3RingShare {
            a: -self.a,
            b: -self.b,
        }
    }
}

impl<T: IntRing2k> ark_ff::Zero for Rep3RingShare<T> {
    fn zero() -> Self {
        Self {
            a: RingElement::zero(),
            b: RingElement::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        panic!("is_zero is not a meaningful operation for Rep3PrimeFieldShare, use interative zero check instead");
    }
}
