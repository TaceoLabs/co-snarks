use ark_ec::pairing::Pairing;
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::SynthesisError;
use circom_types::{
    plonk::ZKey,
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};
use collaborative_groth16::groth16::SharedWitness;
use eyre::{Ok, Result};
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

use crate::{
    types::{PolyEval, WirePolyOutput},
    FieldShareVec, Round,
};
use ark_poly::EvaluationDomain;

pub(super) struct Round1Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    b: [T::FieldShare; 11],
}

pub(super) struct Round1Proof<P: Pairing> {
    commit_a: P::G1,
    commit_b: P::G1,
    commit_c: P::G1,
}

impl<T, P: Pairing> Round1Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) fn random(driver: &mut T) -> Result<Self> {
        let mut b = core::array::from_fn(|_| T::FieldShare::default());
        for mut x in b.iter_mut() {
            *x = driver.rand()?;
        }
        Ok(Self { b })
    }

    fn deterministic() -> Result<Self> {
        let b = core::array::from_fn(|_| T::FieldShare::default());
        Ok(Self { b })
    }
}

impl<T, P: Pairing> Round<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing + CircomArkworksPrimeFieldBridge,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
{
    fn compute_wire_polynomials(
        driver: &mut T,
        challenges: &Round1Challenges<T, P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
    ) -> Result<WirePolyOutput<T, P>> {
        let num_constraints = zkey.n_constraints;

        let mut buffer_a = Vec::with_capacity(num_constraints);
        let mut buffer_b = Vec::with_capacity(num_constraints);
        let mut buffer_c = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            buffer_a.push(Self::get_witness(
                driver,
                private_witness,
                zkey,
                zkey.map_a[i],
            ));
            buffer_b.push(Self::get_witness(
                driver,
                private_witness,
                zkey,
                zkey.map_b[i],
            ));
            buffer_c.push(Self::get_witness(
                driver,
                private_witness,
                zkey,
                zkey.map_c[i],
            ));
        }
        println!("HELOOOOOOOOOOOOOO");

        // TODO batch to montgomery in MPC?

        let buffer_a = FieldShareVec::<T, P>::from(buffer_a);
        let buffer_b = FieldShareVec::<T, P>::from(buffer_b);
        let buffer_c = FieldShareVec::<T, P>::from(buffer_c);

        // Compute the coefficients of the wire polynomials a(X), b(X) and c(X) from A,B & C buffers
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let poly_a = driver.ifft(&buffer_a, &domain1);
        let poly_b = driver.ifft(&buffer_b, &domain1);
        let poly_c = driver.ifft(&buffer_c, &domain1);

        // Compute extended evaluations of a(X), b(X) and c(X) polynomials
        let domain2 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints * 4)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let eval_a = driver.fft(poly_a.to_owned(), &domain2);
        let eval_b = driver.fft(poly_b.to_owned(), &domain2);
        let eval_c = driver.fft(poly_c.to_owned(), &domain2);

        let poly_a = Self::blind_coefficients(driver, &poly_a, &challenges.b[..2]);
        let poly_b = Self::blind_coefficients(driver, &poly_b, &challenges.b[2..4]);
        let poly_c = Self::blind_coefficients(driver, &poly_c, &challenges.b[4..6]);

        if poly_a.len() > zkey.domain_size + 2
            || poly_b.len() > zkey.domain_size + 2
            || poly_c.len() > zkey.domain_size + 2
        {
            return Err(SynthesisError::PolynomialDegreeTooLarge.into());
        }

        Ok(WirePolyOutput {
            buffer_a,
            buffer_b,
            buffer_c,
            poly_eval_a: PolyEval {
                poly: poly_a.into(),
                eval: eval_a,
            },
            poly_eval_b: PolyEval {
                poly: poly_b.into(),
                eval: eval_b,
            },
            poly_eval_c: PolyEval {
                poly: poly_c.into(),
                eval: eval_c,
            },
        })
    }

    pub(super) fn round1(
        driver: &mut T,
        challenges: Round1Challenges<T, P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
    ) -> Result<Self> {
        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        let outp = Self::compute_wire_polynomials(driver, &challenges, zkey, private_witness)?;

        // STEP 1.3 - Compute [a]_1, [b]_1, [c]_1
        let commit_a =
            MSMProvider::<P::G1>::msm_public_points(driver, &zkey.p_tau, &outp.poly_eval_a.poly);
        let commit_b =
            MSMProvider::<P::G1>::msm_public_points(driver, &zkey.p_tau, &outp.poly_eval_b.poly);
        let commit_c =
            MSMProvider::<P::G1>::msm_public_points(driver, &zkey.p_tau, &outp.poly_eval_c.poly);

        // TODO parallelize
        let proof = Round1Proof::<P> {
            commit_a: EcMpcProtocol::<P::G1>::open_point(driver, &commit_a)?,
            commit_b: EcMpcProtocol::<P::G1>::open_point(driver, &commit_b)?,
            commit_c: EcMpcProtocol::<P::G1>::open_point(driver, &commit_c)?,
        };
        Ok(Round::Round2 { challenges, proof })
    }
}

#[cfg(test)]
pub mod tests {
    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::{groth16::witness::Witness, plonk::ZKey};
    use collaborative_groth16::groth16::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;

    use crate::Round;

    use super::Round1Challenges;

    #[test]
    fn test_round1_multiplier2() {
        let mut driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader =
            BufReader::new(File::open("../test_vectors/Plonk/bn254/multiplier2.zkey").unwrap());
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file = File::open("../test_vectors/Plonk/bn254/multiplier2_wtns.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: vec![witness.values[0], witness.values[1]],
            witness: vec![witness.values[2], witness.values[3]],
        };

        let round1 = Round::<PlainDriver<ark_bn254::Fr>, Bn254>::Round1 {
            challenges: Round1Challenges::deterministic().unwrap(),
        };
        let round2 = round1.next_round(&mut driver, &zkey, &witness).unwrap();
    }
}
