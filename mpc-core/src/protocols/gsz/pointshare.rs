use std::mem::ManuallyDrop;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::fieldshare::GSZPrimeFieldShare;

#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
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

// Conversions
impl<C: CurveGroup> GSZPointShare<C> {
    /// Safe because GSZPointShare has repr(transparent)
    pub fn convert_slice(vec: &[Self]) -> &[C] {
        // SAFETY: GSZPointShare has repr(transparent)
        unsafe { &*(vec as *const [Self] as *const [C]) }
    }

    /// Safe because GSZPointShare has repr(transparent)
    pub fn convert_vec(vec: Vec<Self>) -> Vec<C> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: GSZPointShare has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut C, me.len(), me.capacity()) }
    }

    /// Safe because GSZPointShare has repr(transparent)
    pub fn convert_slice_rev(vec: &[C]) -> &[Self] {
        // SAFETY: GSZPointShare has repr(transparent)
        unsafe { &*(vec as *const [C] as *const [Self]) }
    }

    /// Safe because GSZPointShare has repr(transparent)
    pub fn convert_vec_rev(vec: Vec<C>) -> Vec<Self> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: GSZPointShare has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self, me.len(), me.capacity()) }
    }

    pub fn convert(self) -> C {
        self.a
    }
}

#[cfg(test)]
mod unsafe_test {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    const ELEMENTS: usize = 100;

    fn conversion_test<C: CurveGroup>() {
        let mut rng = ChaCha12Rng::from_entropy();
        let t_vec: Vec<C> = (0..ELEMENTS).map(|_| C::rand(&mut rng)).collect();
        let rt_vec: Vec<GSZPointShare<C>> = (0..ELEMENTS)
            .map(|_| GSZPointShare::new(C::rand(&mut rng)))
            .collect();

        // Convert vec<C> to vec<G<C>>
        let t_conv = GSZPointShare::convert_vec_rev(t_vec.to_owned());
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.a, *b)
        }

        // Convert slice vec<C> to vec<G<C>>
        let t_conv = GSZPointShare::convert_slice_rev(&t_vec);
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.a, *b)
        }

        // Convert vec<G<C>> to vec<C>
        let rt_conv = GSZPointShare::convert_vec(rt_vec.to_owned());
        assert_eq!(rt_conv.len(), rt_vec.len());
        for (a, b) in rt_conv.iter().zip(rt_vec.iter()) {
            assert_eq!(*a, b.a)
        }

        // Convert slice vec<G<C>> to vec<C>
        let rt_conv = GSZPointShare::convert_slice(&rt_vec);
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
        [ark_bn254::G1Projective, bn254_test]
    }
}
