use ark_ff::PrimeField;
use serde::ser::SerializeSeq;
use serde::{de, Deserialize, Serialize, Serializer};

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

impl<F: PrimeField> std::ops::Mul<&F> for &'_ Aby3PrimeFieldShare<F> {
    type Output = Aby3PrimeFieldShare<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: PrimeField> std::ops::Mul<F> for Aby3PrimeFieldShare<F> {
    type Output = Aby3PrimeFieldShare<F>;

    fn mul(self, rhs: F) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aby3PrimeFieldShareVec<F: PrimeField> {
    #[serde(serialize_with = "serialize_vec::<_, F>")]
    #[serde(deserialize_with = "deserialize_vec::<_, F>")]
    pub(crate) a: Vec<F>,
    #[serde(serialize_with = "serialize_vec::<_, F>")]
    #[serde(deserialize_with = "deserialize_vec::<_, F>")]
    pub(crate) b: Vec<F>,
}

fn serialize_vec<S: Serializer, F: PrimeField>(p: &[F], ser: S) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(2))?;
    for ser in p.iter().map(|x| x.to_string()) {
        seq.serialize_element(&ser)?;
    }
    seq.end()
}
fn deserialize_vec<'de, D, F: PrimeField>(_deserializer: D) -> Result<Vec<F>, D::Error>
where
    D: de::Deserializer<'de>,
{
    todo!()
}

impl<F: PrimeField> Aby3PrimeFieldShareVec<F> {
    pub fn new(a: Vec<F>, b: Vec<F>) -> Self {
        Self { a, b }
    }

    pub fn get_ab(self) -> (Vec<F>, Vec<F>) {
        (self.a, self.b)
    }

    pub fn to_ref(&self) -> Aby3PrimeFieldShareSlice<F> {
        Aby3PrimeFieldShareSlice {
            a: &self.a,
            b: &self.b,
        }
    }

    pub fn to_mut(&mut self) -> Aby3PrimeFieldShareSliceMut<F> {
        Aby3PrimeFieldShareSliceMut {
            a: &mut self.a,
            b: &mut self.b,
        }
    }

    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.a.is_empty(), self.b.is_empty());
        self.a.is_empty()
    }

    pub fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        self.a.len()
    }
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Aby3PrimeFieldShareSlice<'a, F: PrimeField> {
    // Deliberately a &Vec<F> instead of a &[F] since fft_in_place requires it
    pub(crate) a: &'a Vec<F>,
    pub(crate) b: &'a Vec<F>,
}

impl<'a, F: PrimeField> Aby3PrimeFieldShareSlice<'a, F> {
    fn clone_to_vec(&self) -> Aby3PrimeFieldShareVec<F> {
        Aby3PrimeFieldShareVec {
            a: self.a.to_vec(),
            b: self.b.to_vec(),
        }
    }

    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.a.is_empty(), self.b.is_empty());
        self.a.is_empty()
    }

    pub fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        self.a.len()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Aby3PrimeFieldShareSliceMut<'a, F: PrimeField> {
    // Deliberately a &Vec<F> instead of a &[F] since fft_in_place requires it
    pub(crate) a: &'a mut Vec<F>,
    pub(crate) b: &'a mut Vec<F>,
}

impl<'a, F: PrimeField> Aby3PrimeFieldShareSliceMut<'a, F> {
    fn clone_to_vec(&self) -> Aby3PrimeFieldShareVec<F> {
        Aby3PrimeFieldShareVec {
            a: self.a.to_vec(),
            b: self.b.to_vec(),
        }
    }

    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.a.is_empty(), self.b.is_empty());
        self.a.is_empty()
    }

    pub fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        self.a.len()
    }
}

impl<'a, F: PrimeField> From<&'a Aby3PrimeFieldShareVec<F>> for Aby3PrimeFieldShareSlice<'a, F> {
    fn from(value: &'a Aby3PrimeFieldShareVec<F>) -> Self {
        value.to_ref()
    }
}

impl<'a, F: PrimeField> From<&'a mut Aby3PrimeFieldShareVec<F>>
    for Aby3PrimeFieldShareSliceMut<'a, F>
{
    fn from(value: &'a mut Aby3PrimeFieldShareVec<F>) -> Self {
        value.to_mut()
    }
}

impl<F: PrimeField> From<Aby3PrimeFieldShareSlice<'_, F>> for Aby3PrimeFieldShareVec<F> {
    fn from(value: Aby3PrimeFieldShareSlice<F>) -> Self {
        value.clone_to_vec()
    }
}

impl<F: PrimeField> From<Aby3PrimeFieldShareSliceMut<'_, F>> for Aby3PrimeFieldShareVec<F> {
    fn from(value: Aby3PrimeFieldShareSliceMut<F>) -> Self {
        value.clone_to_vec()
    }
}
