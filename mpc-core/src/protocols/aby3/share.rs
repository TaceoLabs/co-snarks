use ark_ec::CurveGroup;
use ark_ff::PrimeField;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Aby3PrimeFieldShare<F: PrimeField> {
    pub(crate) a: F,
    pub(crate) b: F,
}
impl<F: PrimeField> Aby3PrimeFieldShare<F> {
    pub fn new(a: F, b: F) -> Self {
        Self { a, b }
    }

    pub fn ab(self) -> (F, F) {
        (self.a, self.b)
    }
}

impl<F: PrimeField> std::ops::Add for Aby3PrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}
impl<F: PrimeField> std::ops::Add<&Aby3PrimeFieldShare<F>> for Aby3PrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}
impl<F: PrimeField> std::ops::Add<&Aby3PrimeFieldShare<F>> for &'_ Aby3PrimeFieldShare<F> {
    type Output = Aby3PrimeFieldShare<F>;

    fn add(self, rhs: &Aby3PrimeFieldShare<F>) -> Self::Output {
        Aby3PrimeFieldShare::<F> {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::Sub for Aby3PrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}
impl<F: PrimeField> std::ops::Sub<&Aby3PrimeFieldShare<F>> for Aby3PrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}
impl<F: PrimeField> std::ops::Sub<&Aby3PrimeFieldShare<F>> for &'_ Aby3PrimeFieldShare<F> {
    type Output = Aby3PrimeFieldShare<F>;

    fn sub(self, rhs: &Aby3PrimeFieldShare<F>) -> Self::Output {
        Aby3PrimeFieldShare::<F> {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: PrimeField> std::ops::Mul for Aby3PrimeFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: Self) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}
impl<F: PrimeField> std::ops::Mul<&Aby3PrimeFieldShare<F>> for Aby3PrimeFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: &Self) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}
impl<F: PrimeField> std::ops::Mul<&Aby3PrimeFieldShare<F>> for &'_ Aby3PrimeFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: &Aby3PrimeFieldShare<F>) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: PrimeField> std::ops::Neg for Aby3PrimeFieldShare<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            a: -self.a,
            b: -self.b,
        }
    }
}
impl<F: PrimeField> std::ops::Neg for &Aby3PrimeFieldShare<F> {
    type Output = Aby3PrimeFieldShare<F>;

    fn neg(self) -> Self::Output {
        Aby3PrimeFieldShare::<F> {
            a: -self.a,
            b: -self.b,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aby3PrimeFieldShareVec<F: PrimeField> {
    a: Vec<F>,
    b: Vec<F>,
}

impl<F: PrimeField> From<Vec<Aby3PrimeFieldShare<F>>> for Aby3PrimeFieldShareVec<F> {
    fn from(v: Vec<Aby3PrimeFieldShare<F>>) -> Self {
        let (a, b): (Vec<F>, Vec<F>) = v.into_iter().map(|share| (share.a, share.b)).unzip();
        Self { a, b }
    }
}

impl<F: PrimeField> std::ops::Add for Aby3PrimeFieldShareVec<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a.iter().zip(rhs.a).map(|(a, b)| *a + b).collect(),
            b: self.b.iter().zip(rhs.b).map(|(a, b)| *a + b).collect(),
        }
    }
}

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
