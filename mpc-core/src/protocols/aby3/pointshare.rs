use super::Aby3PrimeFieldShare;
use ark_ec::CurveGroup;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aby3PointShare<C: CurveGroup> {
    pub(crate) a: C,
    pub(crate) b: C,
}
impl<C: CurveGroup> Aby3PointShare<C> {
    pub fn new(a: C, b: C) -> Self {
        Self { a, b }
    }

    pub fn ab(self) -> (C, C) {
        (self.a, self.b)
    }
}

impl<C: CurveGroup> std::ops::Add for Aby3PointShare<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Add<&Aby3PointShare<C>> for Aby3PointShare<C> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}
impl<C: CurveGroup> std::ops::Add<&Aby3PointShare<C>> for &'_ Aby3PointShare<C> {
    type Output = Aby3PointShare<C>;

    fn add(self, rhs: &Aby3PointShare<C>) -> Self::Output {
        Aby3PointShare::<C> {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Sub for Aby3PointShare<C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Sub<&Aby3PointShare<C>> for Aby3PointShare<C> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}
impl<C: CurveGroup> std::ops::Sub<&Aby3PointShare<C>> for &'_ Aby3PointShare<C> {
    type Output = Aby3PointShare<C>;

    fn sub(self, rhs: &Aby3PointShare<C>) -> Self::Output {
        Aby3PointShare::<C> {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<C: CurveGroup> std::ops::Mul<&C::ScalarField> for &'_ Aby3PointShare<C> {
    type Output = Aby3PointShare<C>;

    fn mul(self, scalar: &C::ScalarField) -> Self::Output {
        Self::Output {
            a: self.a * scalar,
            b: self.b * scalar,
        }
    }
}

impl<C: CurveGroup> std::ops::Mul<&C> for &Aby3PrimeFieldShare<C::ScalarField> {
    type Output = Aby3PointShare<C>;

    fn mul(self, point: &C) -> Self::Output {
        Self::Output {
            a: point.mul(self.a),
            b: point.mul(self.b),
        }
    }
}

impl<C: CurveGroup> std::ops::Mul<&Aby3PointShare<C>> for &'_ Aby3PrimeFieldShare<C::ScalarField> {
    type Output = C;

    // Local part of mul only
    fn mul(self, rhs: &Aby3PointShare<C>) -> Self::Output {
        rhs.a * self.a + rhs.b * self.a + rhs.a * self.b
    }
}
