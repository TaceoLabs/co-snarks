use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;
use circom_types::plonk::ZKey;
use collaborative_groth16::groth16::SharedWitness;
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, MontgomeryField, MpcToMontgomery,
    PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

use crate::{
    types::{PolyEval, WirePolyOutput},
    Domains, FieldShareVec, PlonkProofError, PlonkProofResult, PlonkWitness, Round,
};

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
    pub(super) fn random(driver: &mut T) -> PlonkProofResult<Self> {
        let mut b = core::array::from_fn(|_| T::FieldShare::default());
        for mut x in b.iter_mut() {
            *x = driver.rand()?;
        }
        Ok(Self { b })
    }

    fn deterministic() -> Self {
        Self {
            b: core::array::from_fn(|_| T::FieldShare::default()),
        }
    }
}

impl<T, P: Pairing> Round<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>
        + MpcToMontgomery<P::ScalarField>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing + MontgomeryField,
{
    fn compute_wire_polynomials(
        driver: &mut T,
        domains: &Domains<P>,
        challenges: &Round1Challenges<T, P>,
        zkey: &ZKey<P>,
        witness: &PlonkWitness<T, P>,
    ) -> PlonkProofResult<WirePolyOutput<T, P>> {
        let num_constraints = zkey.n_constraints;

        let mut buffer_a = Vec::with_capacity(num_constraints);
        let mut buffer_b = Vec::with_capacity(num_constraints);
        let mut buffer_c = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            buffer_a.push(Self::get_witness(driver, witness, zkey, zkey.map_a[i])?);
            buffer_b.push(Self::get_witness(driver, witness, zkey, zkey.map_b[i])?);
            buffer_c.push(Self::get_witness(driver, witness, zkey, zkey.map_c[i])?);
        }

        // we could do that also during loop but this is more readable
        // it may be even faster as this way it is better for the cache
        let mut buffer_a = FieldShareVec::<T, P>::from(buffer_a);
        let mut buffer_b = FieldShareVec::<T, P>::from(buffer_b);
        let mut buffer_c = FieldShareVec::<T, P>::from(buffer_c);
        driver.inplace_batch_to_montgomery(&mut buffer_a);
        driver.inplace_batch_to_montgomery(&mut buffer_b);
        driver.inplace_batch_to_montgomery(&mut buffer_c);

        // Compute the coefficients of the wire polynomials a(X), b(X) and c(X) from A,B & C buffers
        let poly_a = driver.ifft(&buffer_a, &domains.constraint_domain4);
        let poly_b = driver.ifft(&buffer_b, &domains.constraint_domain4);
        let poly_c = driver.ifft(&buffer_c, &domains.constraint_domain4);

        // Compute extended evaluations of a(X), b(X) and c(X) polynomials
        let eval_a = driver.fft(poly_a.to_owned(), &domains.constraint_domain16);
        let eval_b = driver.fft(poly_b.to_owned(), &domains.constraint_domain16);
        let eval_c = driver.fft(poly_c.to_owned(), &domains.constraint_domain16);

        let poly_a = Self::blind_coefficients(driver, &poly_a, &challenges.b[..2]);
        let poly_b = Self::blind_coefficients(driver, &poly_b, &challenges.b[2..4]);
        let poly_c = Self::blind_coefficients(driver, &poly_c, &challenges.b[4..6]);

        if poly_a.len() > zkey.domain_size + 2
            || poly_b.len() > zkey.domain_size + 2
            || poly_c.len() > zkey.domain_size + 2
        {
            return Err(PlonkProofError::PolynomialDegreeTooLarge);
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
        domains: Domains<P>,
        challenges: Round1Challenges<T, P>,
        zkey: &ZKey<P>,
        private_witness: PlonkWitness<T, P>,
    ) -> PlonkProofResult<Self> {
        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        let wire_polys =
            Self::compute_wire_polynomials(driver, &domains, &challenges, zkey, &private_witness)?;

        let poly_a_msm = driver.batch_lift_montgomery(&wire_polys.poly_eval_a.poly);
        let poly_b_msm = driver.batch_lift_montgomery(&wire_polys.poly_eval_b.poly);
        let poly_c_msm = driver.batch_lift_montgomery(&wire_polys.poly_eval_c.poly);
        // STEP 1.3 - Compute [a]_1, [b]_1, [c]_1
        let commit_a = MSMProvider::<P::G1>::msm_public_points(driver, &zkey.p_tau, &poly_a_msm);
        let commit_b = MSMProvider::<P::G1>::msm_public_points(driver, &zkey.p_tau, &poly_b_msm);
        let commit_c = MSMProvider::<P::G1>::msm_public_points(driver, &zkey.p_tau, &poly_c_msm);

        let opened = driver.open_point_many(&[commit_a, commit_b, commit_c])?;
        debug_assert_eq!(opened.len(), 3);

        let proof = Round1Proof::<P> {
            commit_a: opened[0],
            commit_b: opened[1],
            commit_c: opened[2],
        };
        Ok(Round::Round2 {
            domains,
            challenges,
            proof,
            wire_polys,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::{groth16::witness::Witness, plonk::ZKey};
    use collaborative_groth16::groth16::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;

    use crate::{Domains, Round};

    use super::Round1Challenges;
    use ark_ec::pairing::Pairing;
    use num_traits::Zero;
    use std::str::FromStr;

    macro_rules! g1_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    #[test]
    fn test_round1_multiplier2() {
        let mut driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader =
            BufReader::new(File::open("../test_vectors/Plonk/bn254/multiplier2.zkey").unwrap());
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file = File::open("../test_vectors/Plonk/bn254/multiplier2_wtns.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: vec![ark_bn254::Fr::zero(), witness.values[1]],
            witness: vec![witness.values[2], witness.values[3]],
        };

        let round1 = Round::<PlainDriver<ark_bn254::Fr>, Bn254>::Round1 {
            domains: Domains::new(&zkey).unwrap(),
            challenges: Round1Challenges::deterministic(),
            witness: witness.into(),
        };
        if let Round::Round2 {
            domains: _,
            challenges: _,
            wire_polys: _,
            proof,
        } = round1.next_round(&mut driver, &zkey).unwrap()
        {
            assert_eq!(
                proof.commit_a,
                g1_from_xy!(
                    "11327846795108164597862108116687480895455059329060212270066696945088464241533",
                    "7776921762549167800422434926003437762844064920522926970325762760653252429454"
                )
            );
            assert_eq!(
                proof.commit_b,
                g1_from_xy!(
                    "9372062747415722277840039329560395993406167602129326436042470958833003216581",
                    "6239816658778119701714344686030767774838449997864231134074073775429258788922"
                )
            );
            assert_eq!(
                proof.commit_c,
                g1_from_xy!(
                    "18369440326418436791793675139620567534336152462051746333537337326721235970210",
                    "4920943776359951362683576214248080938368830299813420492592037643095097935073"
                )
            );
        } else {
            panic!("must be round2 after round1");
        }
    }
}
