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
