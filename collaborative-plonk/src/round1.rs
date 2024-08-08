use ark_ec::pairing::Pairing;
use circom_types::plonk::ZKey;
use collaborative_groth16::groth16::SharedWitness;
use mpc_core::traits::{
    FFTPostProcessing, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

use crate::{
    plonk_utils, round2::Round2, types::PolyEval, Domains, FieldShare, FieldShareVec, PlonkData,
    PlonkProofError, PlonkProofResult, PlonkWitness,
};
/*

*/
pub(super) struct Round1<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    pub(super) driver: T,
    pub(super) domains: Domains<P>,
    pub(super) challenges: Round1Challenges<T, P>,
    pub(super) data: PlonkData<T, P>,
}

pub(super) struct Round1Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) b: [T::FieldShare; 11],
}

pub(super) struct Round1Proof<P: Pairing> {
    pub(super) commit_a: P::G1,
    pub(super) commit_b: P::G1,
    pub(super) commit_c: P::G1,
}
pub(super) struct Round1Polys<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) buffer_a: FieldShareVec<T, P>,
    pub(super) buffer_b: FieldShareVec<T, P>,
    pub(super) buffer_c: FieldShareVec<T, P>,
    pub(super) a: PolyEval<T, P>,
    pub(super) b: PolyEval<T, P>,
    pub(super) c: PolyEval<T, P>,
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

    #[cfg(test)]
    pub(super) fn deterministic(driver: &mut T) -> Self {
        use num_traits::One;
        Self {
            b: core::array::from_fn(|_| driver.promote_to_trivial_share(P::ScalarField::one())),
        }
    }
}

impl<T, P: Pairing> Round1<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing,
{
    fn compute_wire_polynomials(
        driver: &mut T,
        domains: &Domains<P>,
        challenges: &Round1Challenges<T, P>,
        zkey: &ZKey<P>,
        witness: &PlonkWitness<T, P>,
    ) -> PlonkProofResult<Round1Polys<T, P>> {
        let num_constraints = zkey.n_constraints;

        let mut buffer_a = vec![FieldShare::<T, P>::default(); zkey.domain_size];
        let mut buffer_b = vec![FieldShare::<T, P>::default(); zkey.domain_size];
        let mut buffer_c = vec![FieldShare::<T, P>::default(); zkey.domain_size];

        for i in 0..num_constraints {
            buffer_a[i] = plonk_utils::get_witness(driver, witness, zkey, zkey.map_a[i])?;
            buffer_b[i] = plonk_utils::get_witness(driver, witness, zkey, zkey.map_b[i])?;
            buffer_c[i] = plonk_utils::get_witness(driver, witness, zkey, zkey.map_c[i])?;
        }

        // we could do that also during loop but this is more readable
        // it may be even faster as this way it is better for the cache
        let buffer_a = FieldShareVec::<T, P>::from(buffer_a);
        let buffer_b = FieldShareVec::<T, P>::from(buffer_b);
        let buffer_c = FieldShareVec::<T, P>::from(buffer_c);

        // Compute the coefficients of the wire polynomials a(X), b(X) and c(X) from A,B & C buffers
        let poly_a = driver.ifft(&buffer_a, &domains.domain);
        let poly_b = driver.ifft(&buffer_b, &domains.domain);
        let poly_c = driver.ifft(&buffer_c, &domains.domain);

        // Compute extended evaluations of a(X), b(X) and c(X) polynomials
        let eval_a = driver.fft(poly_a.to_owned(), &domains.extended_domain);
        let eval_b = driver.fft(poly_b.to_owned(), &domains.extended_domain);
        let eval_c = driver.fft(poly_c.to_owned(), &domains.extended_domain);

        let poly_a = plonk_utils::blind_coefficients::<T, P>(driver, &poly_a, &challenges.b[..2]);
        let poly_b = plonk_utils::blind_coefficients::<T, P>(driver, &poly_b, &challenges.b[2..4]);
        let poly_c = plonk_utils::blind_coefficients::<T, P>(driver, &poly_c, &challenges.b[4..6]);

        if poly_a.len() > zkey.domain_size + 2
            || poly_b.len() > zkey.domain_size + 2
            || poly_c.len() > zkey.domain_size + 2
        {
            return Err(PlonkProofError::PolynomialDegreeTooLarge);
        }

        Ok(Round1Polys {
            buffer_a,
            buffer_b,
            buffer_c,
            a: PolyEval {
                poly: poly_a.into(),
                eval: eval_a,
            },
            b: PolyEval {
                poly: poly_b.into(),
                eval: eval_b,
            },
            c: PolyEval {
                poly: poly_c.into(),
                eval: eval_c,
            },
        })
    }

    fn calculate_additions(
        driver: &mut T,
        witness: SharedWitness<T, P>,
        zkey: &ZKey<P>,
    ) -> PlonkProofResult<PlonkWitness<T, P>> {
        //TODO calculate additions
        //set first element to zero as it is not used
        let mut witness = PlonkWitness::new(witness, zkey.n_additions);

        for addition in zkey.additions.iter() {
            let witness1 = plonk_utils::get_witness(
                driver,
                &witness,
                zkey,
                addition.signal_id1.try_into().expect("u32 fits into usize"),
            )?;
            let witness2 = plonk_utils::get_witness(
                driver,
                &witness,
                zkey,
                addition.signal_id2.try_into().expect("u32 fits into usize"),
            )?;

            let f1 = driver.mul_with_public(&addition.factor1, &witness1);
            let f2 = driver.mul_with_public(&addition.factor2, &witness2);
            let result = driver.add(&f1, &f2);
            witness.addition_witness.push(result);
        }
        Ok(witness)
    }

    pub(super) fn init_round(
        mut driver: T,
        zkey: ZKey<P>,
        private_witness: SharedWitness<T, P>,
    ) -> PlonkProofResult<Self> {
        //set first element to zero as it is not used
        let plonk_witness = Self::calculate_additions(&mut driver, private_witness, &zkey)?;

        Ok(Self {
            challenges: Round1Challenges::random(&mut driver)?,
            driver,
            domains: Domains::new(zkey.domain_size)?,
            data: PlonkData {
                witness: plonk_witness,
                zkey,
            },
        })
    }

    pub(super) fn round1(self) -> PlonkProofResult<Round2<T, P>> {
        let Self {
            mut driver,
            domains,
            challenges,
            mut data,
        } = self;
        let witness = &data.witness;
        let zkey = &data.zkey;
        let p_tau = &zkey.p_tau;

        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        let polys =
            Self::compute_wire_polynomials(&mut driver, &domains, &challenges, zkey, witness)?;

        // STEP 1.3 - Compute [a]_1, [b]_1, [c]_1
        let commit_a = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &p_tau[..T::sharevec_len(&polys.a.poly)],
            &polys.a.poly,
        );
        let commit_b = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &p_tau[..T::sharevec_len(&polys.b.poly)],
            &polys.b.poly,
        );
        let commit_c = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &p_tau[..T::sharevec_len(&polys.c.poly)],
            &polys.c.poly,
        );

        let opened = driver.open_point_many(&[commit_a, commit_b, commit_c])?;
        debug_assert_eq!(opened.len(), 3);

        let proof = Round1Proof::<P> {
            commit_a: opened[0],
            commit_b: opened[1],
            commit_c: opened[2],
        };
        //when we are done, we remove the leading zero of the public inputs
        data.witness.public_inputs = data.witness.public_inputs[1..].to_vec();
        Ok(Round2 {
            driver,
            domains,
            challenges,
            proof,
            polys,
            data,
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

    use super::{Round1, Round1Challenges};
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
        let mut reader = BufReader::new(
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2_wtns.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: vec![ark_bn254::Fr::zero(), witness.values[1]],
            witness: vec![witness.values[2], witness.values[3]],
        };
        let challenges = Round1Challenges::deterministic(&mut driver);
        let mut round1 = Round1::init_round(driver, zkey, witness).unwrap();
        round1.challenges = challenges;
        let round2 = round1.round1().unwrap();
        assert_eq!(
            round2.proof.commit_a,
            g1_from_xy!(
                "3388598946998037934523247214958481082013443546016537275698814746665095654011",
                "16418302496354878039048280340533375731194422868622884330371991683673050823927"
            )
        );
        assert_eq!(
            round2.proof.commit_b,
            g1_from_xy!(
                "13049912696015027105906326615100790685802699797933384361100854080401912076778",
                "10378643755673287533327241708901786955592525369489297709043438653533861197932"
            )
        );
        assert_eq!(
            round2.proof.commit_c,
            g1_from_xy!(
                "21886373095085320996754257372559726802002159951253295441999131091936518950332",
                "12906740162362256844913813683120863430935708683114986453107641385068771252717"
            )
        );
    }
}
