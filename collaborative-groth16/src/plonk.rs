//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

use crate::groth16::SharedWitness;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use circom_types::plonk::ZKey;
use eyre::Result;
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use std::marker::PhantomData;

type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;
type PointShare<T, C> = <T as EcMpcProtocol<C>>::PointShare;

struct Proof<P: Pairing> {
    commit_a: P::G1,
    commit_b: P::G1,
    commit_c: P::G1,
}

struct Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    b: [T::FieldShare; 10],
}

struct WirePolyOutput<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    poly_a: FieldShareVec<T, P>,
    poly_b: FieldShareVec<T, P>,
    poly_c: FieldShareVec<T, P>,
    eval_a: FieldShareVec<T, P>,
    eval_b: FieldShareVec<T, P>,
    eval_c: FieldShareVec<T, P>,
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
        &mut self,
        poly: &FieldShareVec<T, P>,
        coeff: &[FieldShare<T, P>],
    ) -> Vec<FieldShare<T, P>> {
        let mut res = poly.clone().into_iter().collect::<Vec<_>>();
        for (p, c) in res.iter_mut().zip(coeff.iter()) {
            *p = self.driver.sub(p, c);
        }
        res.extend_from_slice(coeff);
        res
    }

    fn compute_wire_polynomials(
        &mut self,
        challenges: &Challenges<T, P>,
        zkey: &ZKey<P>,
        private_witness: SharedWitness<T, P>,
    ) -> Result<WirePolyOutput<T, P>> {
        let n8 = (P::ScalarField::MODULUS_BIT_SIZE + 7) / 8;
        let num_constraints = zkey.n_constraints;

        let mut buffer_a = Vec::with_capacity(num_constraints);
        let mut buffer_b = Vec::with_capacity(num_constraints);
        let mut buffer_c = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            buffer_a.push(T::index_sharevec(&private_witness.witness, zkey.map_a[i]));
            buffer_b.push(T::index_sharevec(&private_witness.witness, zkey.map_b[i]));
            buffer_c.push(T::index_sharevec(&private_witness.witness, zkey.map_c[i]));
        }

        // TODO batch to montgomery in MPC?

        let buffer_a = FieldShareVec::<T, P>::from(buffer_a);
        let buffer_b = FieldShareVec::<T, P>::from(buffer_b);
        let buffer_c = FieldShareVec::<T, P>::from(buffer_c);

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

        let poly_a = self.blind_coefficients(&poly_a, &challenges.b[..2]);
        let poly_b = self.blind_coefficients(&poly_b, &challenges.b[2..4]);
        let poly_c = self.blind_coefficients(&poly_c, &challenges.b[4..6]);

        if poly_a.len() > zkey.domain_size + 2
            || poly_b.len() > zkey.domain_size + 2
            || poly_c.len() > zkey.domain_size + 2
        {
            return Err(SynthesisError::PolynomialDegreeTooLarge.into());
        }

        // TODO return what is required

        Ok(WirePolyOutput {
            poly_a: poly_a.into(),
            poly_b: poly_b.into(),
            poly_c: poly_c.into(),
            eval_a,
            eval_b,
            eval_c,
        })
    }

    fn round1(
        &mut self,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        private_witness: SharedWitness<T, P>,
    ) -> Result<WirePolyOutput<T, P>> {
        // STEP 1.1 - Generate random blinding scalars (b0, ..., b10) \in F_p
        let mut challenges = Box::new(Challenges::<T, P>::new());
        challenges.random_b(&mut self.driver)?;

        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        let outp = self.compute_wire_polynomials(&challenges, zkey, private_witness)?;

        // STEP 1.3 - Compute [a]_1, [b]_1, [c]_1
        let commit_a =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &outp.poly_a);
        let commit_b =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &outp.poly_b);
        let commit_c =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &outp.poly_c);

        // TODO parallelize
        proof.commit_a = self.driver.open_point(&commit_a)?;
        proof.commit_b = self.driver.open_point(&commit_b)?;
        proof.commit_c = self.driver.open_point(&commit_c)?;

        Ok(outp)
    }
}
