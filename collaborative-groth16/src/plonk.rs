//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use eyre::Result;
use mpc_core::traits::{FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol};
use std::marker::PhantomData;

struct Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    b: [T::FieldShare; 10],
}

impl<T, P: Pairing> Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new() -> Self {
        Self {
            b: core::array::from_fn(|_| T::FieldShare::default()),
        }
    }

    fn random_b(&mut self, driver: &mut T) -> Result<()> {
        for b in self.b.iter_mut() {
            *b = driver.rand()?;
        }

        Ok(())
    }
}

/// A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CollaborativePlonk<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P: Pairing> CollaborativePlonk<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    /// Creates a new [CollaborativePlonk] protocol with a given MPC driver.
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    fn blind_coefficients(
        poly: &<T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec,
        coeff: &[<T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShare],
    ) {
        // let res_len = poly.len() + coeff.len();
    }

    fn compute_wire_polynomials(&mut self) -> Result<()> {
        let n8 = (P::ScalarField::MODULUS_BIT_SIZE + 7) / 8;

        let num_constraints = 10; // TODO get num constraints from zkey once merged

        let mut buffer_a = Vec::with_capacity(num_constraints);
        let mut buffer_b = Vec::with_capacity(num_constraints);
        let mut buffer_c = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            // TODO read the buffers
        }

        // TODO batch to montgomery in MPC?

        let buffer_a = <T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec::from(buffer_a);
        let buffer_b = <T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec::from(buffer_b);
        let buffer_c = <T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec::from(buffer_c);

        // Compute the coefficients of the wire polynomials a(X), b(X) and c(X) from A,B & C buffers
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let poly_a = self.driver.ifft(&buffer_a, &domain1);
        let poly_b = self.driver.ifft(&buffer_b, &domain1);
        let poly_c = self.driver.ifft(&buffer_c, &domain1);

        // Compute extended evaluations of a(X), b(X) and c(X) polynomials
        let domain2 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints * 4)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let eval_a = self.driver.fft(poly_a.to_owned(), &domain2);
        let eval_b = self.driver.fft(poly_b.to_owned(), &domain2);
        let eval_c = self.driver.fft(poly_c.to_owned(), &domain2);

        todo!();
        Ok(())
    }

    fn round1(&mut self) -> Result<()> {
        // STEP 1.1 - Generate random blinding scalars (b0, ..., b10) \in F_p
        let mut challenges = Box::new(Challenges::<T, P>::new());
        challenges.random_b(&mut self.driver)?;

        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        self.compute_wire_polynomials()?;

        Ok(())
    }
}
