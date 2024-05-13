use ark_ec::CurveGroup;

use super::fieldshare::GSZPrimeFieldShare;

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct GSZPointShare<C: CurveGroup> {
    pub(crate) a: C,
}
impl<C: CurveGroup> GSZPointShare<C> {
    pub fn new(a: C) -> Self {
        Self { a }
    }

    pub fn inner(self) -> C {
        self.a
    }
}

impl<C: CurveGroup> std::ops::Add for GSZPointShare<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { a: self.a + rhs.a }
    }
}

impl<C: CurveGroup> std::ops::Add<&GSZPointShare<C>> for GSZPointShare<C> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self { a: self.a + rhs.a }
    }
}

impl<C: CurveGroup> std::ops::Add<&GSZPointShare<C>> for &'_ GSZPointShare<C> {
    type Output = GSZPointShare<C>;

    fn add(self, rhs: &GSZPointShare<C>) -> Self::Output {
        GSZPointShare::<C> { a: self.a + rhs.a }
    }
}

impl<C: CurveGroup> std::ops::AddAssign<&GSZPointShare<C>> for GSZPointShare<C> {
    fn add_assign(&mut self, rhs: &Self) {
        self.a += rhs.a;
    }
}

impl<C: CurveGroup> std::ops::Sub for GSZPointShare<C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self { a: self.a - rhs.a }
    }
}

impl<C: CurveGroup> std::ops::Sub<&GSZPointShare<C>> for GSZPointShare<C> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self { a: self.a - rhs.a }
    }
}
impl<C: CurveGroup> std::ops::Sub<&GSZPointShare<C>> for &'_ GSZPointShare<C> {
    type Output = GSZPointShare<C>;

    fn sub(self, rhs: &GSZPointShare<C>) -> Self::Output {
        GSZPointShare::<C> { a: self.a - rhs.a }
    }
}

impl<C: CurveGroup> std::ops::SubAssign<&GSZPointShare<C>> for GSZPointShare<C> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.a -= rhs.a;
    }
}

impl<C: CurveGroup> std::ops::Mul<&C::ScalarField> for &'_ GSZPointShare<C> {
    type Output = GSZPointShare<C>;

    fn mul(self, scalar: &C::ScalarField) -> Self::Output {
        Self::Output { a: self.a * scalar }
    }
}

impl<C: CurveGroup> std::ops::Mul<&GSZPointShare<C>> for &'_ GSZPrimeFieldShare<C::ScalarField> {
    type Output = GSZPointShare<C>;

    // Result has higher degree than the inputs
    fn mul(self, rhs: &GSZPointShare<C>) -> Self::Output {
        GSZPointShare::<C> { a: rhs.a * self.a }
    }
}
