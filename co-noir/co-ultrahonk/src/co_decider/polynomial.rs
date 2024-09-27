use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::{
    fmt::Debug,
    ops::{Index, IndexMut},
};
use ultrahonk::prelude::Polynomial;

pub(crate) struct SharedPolynomial<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) coefficients: Vec<T::FieldShare>,
}

impl<T, P: Pairing> SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub fn new(coefficients: Vec<T::FieldShare>) -> Self {
        Self { coefficients }
    }

    pub(crate) fn promote_poly(driver: &T, poly: Polynomial<P::ScalarField>) -> Self {
        // TODO remove the FieldShareVec
        let coefficients: T::FieldShareVec = driver.promote_to_trivial_shares(poly.as_ref());
        let coefficients = coefficients.into_iter().collect();
        Self { coefficients }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T::FieldShare> {
        self.coefficients.iter()
    }

    pub(crate) fn add_assign_slice(&mut self, driver: &mut T, other: &[T::FieldShare]) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(other.iter()) {
            *des = driver.add(des, src);
        }
    }

    pub(crate) fn add_scaled_slice(
        &mut self,
        driver: &mut T,
        src: &[T::FieldShare],
        scalar: &P::ScalarField,
    ) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(src.iter()) {
            let tmp = driver.mul_with_public(scalar, src);
            *des = driver.add(des, &tmp);
        }
    }

    pub(crate) fn add_scaled(
        &mut self,
        driver: &mut T,
        src: &SharedPolynomial<T, P>,
        scalar: &P::ScalarField,
    ) {
        self.add_scaled_slice(driver, &src.coefficients, scalar);
    }

    pub(crate) fn add_scaled_slice_public(
        &mut self,
        driver: &mut T,
        src: &[P::ScalarField],
        scalar: &P::ScalarField,
    ) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(src.iter()) {
            let tmp = *scalar * src;
            *des = driver.add_with_public(&tmp, des);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.coefficients.len()
    }

    // Can only shift by 1
    pub(crate) fn shifted(&self) -> &[T::FieldShare] {
        assert!(!self.coefficients.is_empty());
        &self.coefficients[1..]
    }
}

impl<T, P: Pairing> Clone for SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn clone(&self) -> Self {
        Self {
            coefficients: self.coefficients.clone(),
        }
    }
}

impl<T, P: Pairing> Default for SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn default() -> Self {
        Self {
            coefficients: Default::default(),
        }
    }
}

impl<T, P: Pairing> Debug for SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPolynomial")
            .field("coefficients", &self.coefficients)
            .finish()
    }
}
impl<T, P: Pairing> AsRef<[T::FieldShare]> for SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn as_ref(&self) -> &[T::FieldShare] {
        &self.coefficients
    }
}
impl<T, P: Pairing> Index<usize> for SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    type Output = T::FieldShare;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coefficients[index]
    }
}
impl<T, P: Pairing> IndexMut<usize> for SharedPolynomial<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coefficients[index]
    }
}
