use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::fmt::Debug;
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
    pub(crate) fn promote_poly(driver: &T, poly: Polynomial<P::ScalarField>) -> Self {
        // TODO remove the FieldShareVec
        let coefficients: T::FieldShareVec = driver.promote_to_trivial_shares(poly.as_ref());
        let coefficients = coefficients.into_iter().collect();
        Self { coefficients }
    }

    pub fn add_assign_slice(&mut self, driver: &mut T, other: &[T::FieldShare]) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(other.iter()) {
            *des = driver.add(des, src);
        }
    }

    pub fn add_scaled_slice(
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

    pub fn add_scaled_slice_public(
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

    // Can only shift by 1
    pub fn shifted(&self) -> &[T::FieldShare] {
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
