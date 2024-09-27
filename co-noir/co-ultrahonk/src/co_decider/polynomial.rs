use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;
use ultrahonk::prelude::Polynomial;

#[derive(Clone, Debug, Default)]
pub struct SharedPolynomial<T, P: Pairing>
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

    pub fn add_scaled_slice(
        &mut self,
        driver: &mut T,
        src: &[T::FieldShare],
        scalar: &P::ScalarField,
    ) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(src.iter()) {
            let tmp = driver.mul_with_public(scalar, &src);
            *des = driver.add(des, &tmp);
        }
    }
}
