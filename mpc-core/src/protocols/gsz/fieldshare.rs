use ark_ff::PrimeField;
use serde::ser::SerializeSeq;
use serde::{de, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct GSZPrimeFieldShare<F: PrimeField> {
    pub(crate) a: F,
}

impl<F: PrimeField> GSZPrimeFieldShare<F> {
    pub fn new(a: F) -> Self {
        Self { a }
    }

    pub fn inner(self) -> F {
        self.a
    }
}

impl<F: PrimeField> std::ops::Add for GSZPrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { a: self.a + rhs.a }
    }
}

impl<F: PrimeField> std::ops::Add<&GSZPrimeFieldShare<F>> for GSZPrimeFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self { a: self.a + rhs.a }
    }
}

impl<F: PrimeField> std::ops::Add<&GSZPrimeFieldShare<F>> for &'_ GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    fn add(self, rhs: &GSZPrimeFieldShare<F>) -> Self::Output {
        GSZPrimeFieldShare::<F> { a: self.a + rhs.a }
    }
}

impl<F: PrimeField> std::ops::Sub for GSZPrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self { a: self.a - rhs.a }
    }
}

impl<F: PrimeField> std::ops::Sub<&GSZPrimeFieldShare<F>> for GSZPrimeFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self { a: self.a - rhs.a }
    }
}

impl<F: PrimeField> std::ops::Sub<&GSZPrimeFieldShare<F>> for &'_ GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    fn sub(self, rhs: &GSZPrimeFieldShare<F>) -> Self::Output {
        GSZPrimeFieldShare::<F> { a: self.a - rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul for GSZPrimeFieldShare<F> {
    type Output = Self;

    // Result has higher degree than the inputs
    fn mul(self, rhs: Self) -> Self::Output {
        GSZPrimeFieldShare::<F> { a: self.a * rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul<&GSZPrimeFieldShare<F>> for GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    // Result has higher degree than the inputs
    fn mul(self, rhs: &Self) -> Self::Output {
        GSZPrimeFieldShare::<F> { a: self.a * rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul<&GSZPrimeFieldShare<F>> for &'_ GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    // Result has higher degree than the inputs
    fn mul(self, rhs: &GSZPrimeFieldShare<F>) -> Self::Output {
        GSZPrimeFieldShare::<F> { a: self.a * rhs.a }
    }
}

impl<F: PrimeField> std::ops::Mul<&F> for &'_ GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        Self::Output { a: self.a * rhs }
    }
}

impl<F: PrimeField> std::ops::Mul<F> for GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    fn mul(self, rhs: F) -> Self::Output {
        Self::Output { a: self.a * rhs }
    }
}

impl<F: PrimeField> std::ops::Neg for GSZPrimeFieldShare<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self { a: -self.a }
    }
}
impl<F: PrimeField> std::ops::Neg for &GSZPrimeFieldShare<F> {
    type Output = GSZPrimeFieldShare<F>;

    fn neg(self) -> Self::Output {
        GSZPrimeFieldShare::<F> { a: -self.a }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GSZPrimeFieldShareVec<F: PrimeField> {
    #[serde(serialize_with = "serialize_vec::<_, F>")]
    #[serde(deserialize_with = "deserialize_vec::<_, F>")]
    pub(crate) a: Vec<F>,
}

fn serialize_vec<S: Serializer, F: PrimeField>(p: &[F], ser: S) -> Result<S::Ok, S::Error> {
    // TODO check this
    let mut seq = ser.serialize_seq(Some(1))?;
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

impl<F: PrimeField> GSZPrimeFieldShareVec<F> {
    pub fn new(a: Vec<F>) -> Self {
        Self { a }
    }

    pub fn get_inner(self) -> Vec<F> {
        self.a
    }

    pub fn to_ref(&self) -> GSZPrimeFieldShareSlice<F> {
        GSZPrimeFieldShareSlice { a: &self.a }
    }

    pub fn to_mut(&mut self) -> GSZPrimeFieldShareSliceMut<F> {
        GSZPrimeFieldShareSliceMut { a: &mut self.a }
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    pub fn len(&self) -> usize {
        self.a.len()
    }
}

impl<F: PrimeField> From<Vec<GSZPrimeFieldShare<F>>> for GSZPrimeFieldShareVec<F> {
    fn from(v: Vec<GSZPrimeFieldShare<F>>) -> Self {
        // TODO: Transparent struct, so can it be coded better?
        let a = v.into_iter().map(|x| x.a).collect();
        Self { a }
    }
}

impl<F: PrimeField> std::ops::Add for GSZPrimeFieldShareVec<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a.iter().zip(rhs.a).map(|(a, b)| *a + b).collect(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GSZPrimeFieldShareSlice<'a, F: PrimeField> {
    // Deliberately a &Vec<F> instead of a &[F] since fft_in_place requires it
    pub(crate) a: &'a Vec<F>,
}

impl<'a, F: PrimeField> GSZPrimeFieldShareSlice<'a, F> {
    fn clone_to_vec(&self) -> GSZPrimeFieldShareVec<F> {
        GSZPrimeFieldShareVec { a: self.a.to_vec() }
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    pub fn len(&self) -> usize {
        self.a.len()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GSZPrimeFieldShareSliceMut<'a, F: PrimeField> {
    // Deliberately a &Vec<F> instead of a &[F] since fft_in_place requires it
    pub(crate) a: &'a mut Vec<F>,
}

impl<'a, F: PrimeField> GSZPrimeFieldShareSliceMut<'a, F> {
    fn clone_to_vec(&self) -> GSZPrimeFieldShareVec<F> {
        GSZPrimeFieldShareVec { a: self.a.to_vec() }
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    pub fn len(&self) -> usize {
        self.a.len()
    }
}

impl<'a, F: PrimeField> From<&'a GSZPrimeFieldShareVec<F>> for GSZPrimeFieldShareSlice<'a, F> {
    fn from(value: &'a GSZPrimeFieldShareVec<F>) -> Self {
        value.to_ref()
    }
}

impl<'a, F: PrimeField> From<&'a mut GSZPrimeFieldShareVec<F>>
    for GSZPrimeFieldShareSliceMut<'a, F>
{
    fn from(value: &'a mut GSZPrimeFieldShareVec<F>) -> Self {
        value.to_mut()
    }
}

impl<F: PrimeField> From<GSZPrimeFieldShareSlice<'_, F>> for GSZPrimeFieldShareVec<F> {
    fn from(value: GSZPrimeFieldShareSlice<F>) -> Self {
        value.clone_to_vec()
    }
}

impl<F: PrimeField> From<GSZPrimeFieldShareSliceMut<'_, F>> for GSZPrimeFieldShareVec<F> {
    fn from(value: GSZPrimeFieldShareSliceMut<F>) -> Self {
        value.clone_to_vec()
    }
}
