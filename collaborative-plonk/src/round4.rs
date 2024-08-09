use crate::{
    round3::{FinalPolys, Round3Challenges, Round3Proof},
    round5::Round5,
    types::Keccak256Transcript,
    Domains, PlonkData, PlonkProofResult,
};
use ark_ec::pairing::Pairing;
use mpc_core::traits::{
    FFTPostProcessing, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

// Round 4 of https://eprint.iacr.org/2019/953.pdf (page 29)
pub(super) struct Round4<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    pub(super) driver: T,
    pub(super) domains: Domains<P::ScalarField>,
    pub(super) challenges: Round3Challenges<T, P>,
    pub(super) proof: Round3Proof<P>,
    pub(super) polys: FinalPolys<T, P>,
    pub(super) data: PlonkData<T, P>,
}
pub(super) struct Round4Challenges<P: Pairing> {
    pub(super) beta: P::ScalarField,
    pub(super) gamma: P::ScalarField,
    pub(super) alpha: P::ScalarField,
    pub(super) xi: P::ScalarField,
}
impl<P: Pairing> Round4Challenges<P> {
    fn new<T>(round3_challenges: Round3Challenges<T, P>, xi: P::ScalarField) -> Self
    where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        Self {
            beta: round3_challenges.beta,
            gamma: round3_challenges.gamma,
            alpha: round3_challenges.alpha,
            xi,
        }
    }
}

pub(super) struct Round4Proof<P: Pairing> {
    pub(super) commit_a: P::G1,
    pub(super) commit_b: P::G1,
    pub(super) commit_c: P::G1,
    pub(super) commit_z: P::G1,
    pub(super) commit_t1: P::G1,
    pub(super) commit_t2: P::G1,
    pub(super) commit_t3: P::G1,
    pub(super) eval_a: P::ScalarField,
    pub(super) eval_b: P::ScalarField,
    pub(super) eval_c: P::ScalarField,
    pub(super) eval_zw: P::ScalarField,
    pub(super) eval_s1: P::ScalarField,
    pub(super) eval_s2: P::ScalarField,
}

impl<P: Pairing> Round4Proof<P> {
    fn new(
        round3_proof: Round3Proof<P>,
        eval_a: P::ScalarField,
        eval_b: P::ScalarField,
        eval_c: P::ScalarField,
        eval_zw: P::ScalarField,
        eval_s1: P::ScalarField,
        eval_s2: P::ScalarField,
    ) -> Self {
        Self {
            commit_a: round3_proof.commit_a,
            commit_b: round3_proof.commit_b,
            commit_c: round3_proof.commit_c,
            commit_z: round3_proof.commit_z,
            commit_t1: round3_proof.commit_t1,
            commit_t2: round3_proof.commit_t2,
            commit_t3: round3_proof.commit_t3,
            eval_a,
            eval_b,
            eval_c,
            eval_zw,
            eval_s1,
            eval_s2,
        }
    }
}

// Round 4 of https://eprint.iacr.org/2019/953.pdf (page 29)
impl<T, P: Pairing> Round4<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing,
{
    // Round 4 of https://eprint.iacr.org/2019/953.pdf (page 29)
    pub(super) fn round4(self) -> PlonkProofResult<Round5<T, P>> {
        let Self {
            mut driver,
            domains,
            challenges,
            proof,
            polys,
            data,
        } = self;
        // STEP 4.1 - Compute evaluation challenge xi \in F_p
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(challenges.alpha);
        transcript.add_point(proof.commit_t1.into());
        transcript.add_point(proof.commit_t2.into());
        transcript.add_point(proof.commit_t3.into());
        let xi = transcript.get_challenge();
        let xiw = xi * domains.root_of_unity_pow;
        let challenges = Round4Challenges::new(challenges, xi);
        let eval_a = driver.evaluate_poly_public(polys.a.poly.to_owned(), &challenges.xi);
        let eval_b = driver.evaluate_poly_public(polys.b.poly.to_owned(), &challenges.xi);
        let eval_c = driver.evaluate_poly_public(polys.c.poly.to_owned(), &challenges.xi);
        let eval_z = driver.evaluate_poly_public(polys.z.poly.to_owned(), &xiw);

        let opened = driver.open_many(&[eval_a, eval_b, eval_c, eval_z])?;

        let eval_a = opened[0];
        let eval_b = opened[1];
        let eval_c = opened[2];
        let eval_zw = opened[3];

        let eval_s1 = data.zkey.s1_poly.evaluate(&challenges.xi);
        let eval_s2 = data.zkey.s2_poly.evaluate(&challenges.xi);
        let proof = Round4Proof::new(proof, eval_a, eval_b, eval_c, eval_zw, eval_s1, eval_s2);

        Ok(Round5 {
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

    use crate::round1::{Round1, Round1Challenges};

    use num_traits::Zero;
    use std::str::FromStr;
    #[test]
    fn test_round4_multiplier2() {
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
        let round3 = round2.round2().unwrap();
        let round4 = round3.round3().unwrap();
        let round5 = round4.round4().unwrap();
        assert_eq!(
            round5.proof.eval_a,
            ark_bn254::Fr::from_str(
                "3430011786334600582765929780190661183634261934757573328619865380969138236677"
            )
            .unwrap()
        );
        assert_eq!(
            round5.proof.eval_b,
            ark_bn254::Fr::from_str(
                "1699629075446766397944461918145382951019648391577272303690098939545886956042"
            )
            .unwrap()
        );
        assert_eq!(
            round5.proof.eval_c,
            ark_bn254::Fr::from_str(
                "2192737627010718547267566060343416780409706320863686367548472523096522236916"
            )
            .unwrap()
        );
        assert_eq!(
            round5.proof.eval_zw,
            ark_bn254::Fr::from_str(
                "11737693650123103476561659162132287707878231403214559741701695144617250521467"
            )
            .unwrap()
        );
        assert_eq!(
            round5.proof.eval_s1,
            ark_bn254::Fr::from_str(
                "16983004294970120469188027322411312724876163529574499048548162072264083360228"
            )
            .unwrap()
        );
        assert_eq!(
            round5.proof.eval_s2,
            ark_bn254::Fr::from_str(
                "19681695700163968683700376354652917952592916721995393420603324391456988690751"
            )
            .unwrap()
        );
    }
}
