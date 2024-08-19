use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use circom_types::plonk::ZKey;
use co_circom_snarks::SharedWitness;
use mpc_core::traits::{
    FFTProvider, FieldShareVecTrait, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

use crate::{
    plonk_utils,
    round2::Round2,
    types::{Domains, PlonkData, PlonkWitness, PolyEval},
    FieldShare, FieldShareVec, PlonkProofError, PlonkProofResult,
};

// Round 1 of https://eprint.iacr.org/2019/953.pdf (page 28)
pub(super) struct Round1<'a, T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
{
    pub(super) driver: T,
    pub(super) domains: Domains<P::ScalarField>,
    pub(super) challenges: Round1Challenges<T, P>,
    pub(super) data: PlonkDataRound1<'a, T, P>,
}

pub(super) struct PlonkDataRound1<'a, T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    witness: PlonkWitness<T, P>,
    zkey: &'a ZKey<P>,
}

impl<'a, T, P: Pairing> From<PlonkDataRound1<'a, T, P>> for PlonkData<'a, T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn from(mut data: PlonkDataRound1<'a, T, P>) -> Self {
        //when we are done, we remove the leading zero of the public inputs
        data.witness.public_inputs = data.witness.public_inputs[1..].to_vec();
        Self {
            witness: data.witness,
            zkey: data.zkey,
        }
    }
}

pub(super) struct Round1Challenges<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
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
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) buffer_a: FieldShareVec<T, P>,
    pub(super) buffer_b: FieldShareVec<T, P>,
    pub(super) buffer_c: FieldShareVec<T, P>,
    pub(super) a: PolyEval<T, P>,
    pub(super) b: PolyEval<T, P>,
    pub(super) c: PolyEval<T, P>,
}

impl<P: Pairing> std::fmt::Display for Round1Proof<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "Round1Proof(a: {}, b: {}, c: {})",
            self.commit_a.into_affine(),
            self.commit_b.into_affine(),
            self.commit_c.into_affine()
        )
    }
}

impl<T, P: Pairing> Round1Challenges<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) fn random(driver: &mut T) -> PlonkProofResult<Self> {
        let mut b = core::array::from_fn(|_| T::FieldShare::default());
        for x in b.iter_mut() {
            *x = driver.rand()?;
        }
        Ok(Self { b })
    }

    #[cfg(test)]
    pub(super) fn deterministic(driver: &mut T) -> Self {
        Self {
            b: core::array::from_fn(|i| {
                driver.promote_to_trivial_share(P::ScalarField::from(i as u64))
            }),
        }
    }
}

// Round 1 of https://eprint.iacr.org/2019/953.pdf (page 28)
impl<'a, T, P: Pairing> Round1<'a, T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
{
    // Essentially the fft of the trace columns
    fn compute_wire_polynomials(
        driver: &mut T,
        domains: &Domains<P::ScalarField>,
        challenges: &Round1Challenges<T, P>,
        zkey: &ZKey<P>,
        witness: &PlonkWitness<T, P>,
    ) -> PlonkProofResult<Round1Polys<T, P>> {
        tracing::debug!("computing wire polynomials...");
        let num_constraints = zkey.n_constraints;

        let mut buffer_a = Vec::with_capacity(zkey.domain_size);
        let mut buffer_b = Vec::with_capacity(zkey.domain_size);
        let mut buffer_c = Vec::with_capacity(zkey.domain_size);

        for i in 0..num_constraints {
            buffer_a.push(plonk_utils::get_witness(
                driver,
                witness,
                zkey,
                zkey.map_a[i],
            )?);
            buffer_b.push(plonk_utils::get_witness(
                driver,
                witness,
                zkey,
                zkey.map_b[i],
            )?);
            buffer_c.push(plonk_utils::get_witness(
                driver,
                witness,
                zkey,
                zkey.map_c[i],
            )?);
        }
        buffer_a.resize(zkey.domain_size, FieldShare::<T, P>::default());
        buffer_b.resize(zkey.domain_size, FieldShare::<T, P>::default());
        buffer_c.resize(zkey.domain_size, FieldShare::<T, P>::default());

        // we could do that also during loop but this is more readable
        // it may be even faster as this way it is better for the cache
        let buffer_a = FieldShareVec::<T, P>::from(buffer_a);
        let buffer_b = FieldShareVec::<T, P>::from(buffer_b);
        let buffer_c = FieldShareVec::<T, P>::from(buffer_c);

        tracing::debug!("iffts for buffers..");
        // Compute the coefficients of the wire polynomials a(X), b(X) and c(X) from A,B & C buffers
        let poly_a = driver.ifft(&buffer_a, &domains.domain);
        let poly_b = driver.ifft(&buffer_b, &domains.domain);
        let poly_c = driver.ifft(&buffer_c, &domains.domain);

        tracing::debug!("ffts for evals..");
        // Compute extended evaluations of a(X), b(X) and c(X) polynomials
        let eval_a = driver.fft(poly_a.to_owned(), &domains.extended_domain);
        let eval_b = driver.fft(poly_b.to_owned(), &domains.extended_domain);
        let eval_c = driver.fft(poly_c.to_owned(), &domains.extended_domain);

        tracing::debug!("blinding coefficients");
        let poly_a = plonk_utils::blind_coefficients::<T, P>(driver, &poly_a, &challenges.b[..2]);
        let poly_b = plonk_utils::blind_coefficients::<T, P>(driver, &poly_b, &challenges.b[2..4]);
        let poly_c = plonk_utils::blind_coefficients::<T, P>(driver, &poly_c, &challenges.b[4..6]);

        if poly_a.len() > zkey.domain_size + 2
            || poly_b.len() > zkey.domain_size + 2
            || poly_c.len() > zkey.domain_size + 2
        {
            return Err(PlonkProofError::PolynomialDegreeTooLarge);
        }
        tracing::debug!("computing wire polys done!");
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

    // Calculate the witnesses for the additions, since they are not part of the SharedWitness
    fn calculate_additions(
        driver: &mut T,
        witness: SharedWitness<T, P>,
        zkey: &ZKey<P>,
    ) -> PlonkProofResult<PlonkWitness<T, P>> {
        tracing::debug!("calculating addition {} constraints...", zkey.n_additions);
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
        tracing::debug!("additions done!");
        Ok(witness)
    }

    pub(super) fn init_round(
        mut driver: T,
        zkey: &'a ZKey<P>,
        private_witness: SharedWitness<T, P>,
    ) -> PlonkProofResult<Self> {
        let plonk_witness = Self::calculate_additions(&mut driver, private_witness, zkey)?;

        Ok(Self {
            challenges: Round1Challenges::random(&mut driver)?,
            driver,
            domains: Domains::new(zkey.domain_size)?,
            data: PlonkDataRound1 {
                witness: plonk_witness,
                zkey,
            },
        })
    }

    // Round 1 of https://eprint.iacr.org/2019/953.pdf (page 28)
    pub(super) fn round1(self) -> PlonkProofResult<Round2<'a, T, P>> {
        let Self {
            mut driver,
            domains,
            challenges,
            data,
        } = self;
        let witness = &data.witness;
        let zkey = &data.zkey;
        let p_tau = &zkey.p_tau;

        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        let polys =
            Self::compute_wire_polynomials(&mut driver, &domains, &challenges, zkey, witness)?;

        tracing::debug!("committing to polys (MSMs)");
        // STEP 1.3 - Compute [a]_1, [b]_1, [c]_1
        let commit_a = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &p_tau[..polys.a.poly.get_len()],
            &polys.a.poly,
        );
        let commit_b = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &p_tau[..polys.b.poly.get_len()],
            &polys.b.poly,
        );
        let commit_c = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &p_tau[..polys.c.poly.get_len()],
            &polys.c.poly,
        );

        let opened = driver.open_point_many(&[commit_a, commit_b, commit_c])?;

        let proof = Round1Proof::<P> {
            commit_a: opened[0],
            commit_b: opened[1],
            commit_c: opened[2],
        };
        tracing::debug!("round1 result: {proof}");
        Ok(Round2 {
            driver,
            domains,
            challenges,
            proof,
            polys,
            data: data.into(),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use ark_ec::CurveGroup;
    use std::{fs::File, io::BufReader};

    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use circom_types::plonk::ZKey;
    use co_circom_snarks::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;

    use super::{Round1, Round1Challenges};
    use ark_ec::pairing::Pairing;
    use circom_types::Witness;
    use std::str::FromStr;

    macro_rules! g1_bn254_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    macro_rules! g1_bls12_381_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bls12_381::Bls12_381 as Pairing>::G1Affine::new(
                ark_bls12_381::Fq::from_str($x).unwrap(),
                ark_bls12_381::Fq::from_str($y).unwrap(),
            )
        };
    }

    #[test]
    fn test_round1_multiplier2() {
        let mut driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../../test_vectors/Plonk/bn254/multiplier2/witness.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: witness.values[..=zkey.n_public].to_vec(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };
        let challenges = Round1Challenges::deterministic(&mut driver);
        let mut round1 = Round1::init_round(driver, &zkey, witness).unwrap();
        round1.challenges = challenges;
        let round2 = round1.round1().unwrap();
        assert_eq!(
            round2.proof.commit_a,
            g1_bn254_from_xy!(
                "17605081043163307645214588229802469503664729145403357283635330564965670333858",
                "6586266374304386912414685272642968153787280144323447197846781700256409557611"
            )
        );
        assert_eq!(
            round2.proof.commit_b,
            g1_bn254_from_xy!(
                "5630355441221157622116381279042400483431873694148526624610332736752309357481",
                "459435968793897134848228876468434334542717512356212242962101833939899171644"
            )
        );
        assert_eq!(
            round2.proof.commit_c,
            g1_bn254_from_xy!(
                "15206827023183180947877311390140741127921188782225553575654415094642569639438",
                "14970166502897037710457760872123795383312785044242798403684409588772714154874"
            )
        );
    }

    #[test]
    fn test_round1_poseidon_bls12_381() {
        let mut driver = PlainDriver::<ark_bls12_381::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../../test_vectors/Plonk/bls12_381/poseidon/circuit.zkey").unwrap(),
        );
        let zkey = ZKey::<Bls12_381>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../../test_vectors/Plonk/bls12_381/poseidon/witness.wtns").unwrap();
        let witness = Witness::<ark_bls12_381::Fr>::from_reader(witness_file).unwrap();

        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bls12_381::Fr>, Bls12_381> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };

        let challenges = Round1Challenges::deterministic(&mut driver);
        let mut round1 = Round1::init_round(driver, &zkey, witness).unwrap();
        round1.challenges = challenges;
        let round2 = round1.round1().unwrap();
        assert_eq!(
            round2.proof.commit_a.into_affine(),
            g1_bls12_381_from_xy!(
                "1998528185362278337803945478659945086542519630073413629642105010067028189206141975508238821825915421715338325238864",
                "436066057394619309469331627881449668678557518497178283348448576242129245895320288313540996356612092203769711134939"
            )
        );
        assert_eq!(
            round2.proof.commit_b,
            g1_bls12_381_from_xy!(
                "905523078516729029387874920505888326057985585766807058529621596028494573503715980387105934346404133401227192848784",
                "817813208457279034981972137280354075285704598923875006670861630006742541882069169563142367502699866422101983374962"
            )
        );
        assert_eq!(
            round2.proof.commit_c,
            g1_bls12_381_from_xy!(
                "2045702311111033155343546707999313330868835292331631548140598745513449880984849831136790392158415943067742290277175",
                "2263708941732971465915801396733005622347769540424301431567098497278413189155761949973582649025461644335372679621757"
            )
        );
    }
}
