use crate::{
    round1::{Round1Challenges, Round1Proof},
    round2::{Round2Challenges, Round2Polys, Round2Proof},
    round3::{Round3Challenges, Round3Polys, Round3Proof},
    types::{Keccak256Transcript, PolyEval},
    Domains, FieldShareVec, PlonkData, PlonkProofError, PlonkProofResult, Round,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::GeneralEvaluationDomain;
use circom_types::{
    groth16::{public_input, zkey},
    plonk::ZKey,
};
use collaborative_groth16::groth16::CollaborativeGroth16;
use mpc_core::traits::EcMpcProtocol;
use mpc_core::traits::{
    FFTPostProcessing, FFTProvider, MSMProvider, MontgomeryField, MpcToMontgomery,
    PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use num_traits::One;
use num_traits::Zero;
pub(super) struct Round4Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) b: [T::FieldShare; 11],
    pub(crate) beta: P::ScalarField,
    pub(crate) gamma: P::ScalarField,
    pub(crate) alpha: P::ScalarField,
    pub(crate) alpha2: P::ScalarField,
    pub(crate) xi: P::ScalarField,
}

pub(super) struct Round4Polys<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) buffer_a: FieldShareVec<T, P>,
    pub(crate) buffer_b: FieldShareVec<T, P>,
    pub(crate) buffer_c: FieldShareVec<T, P>,
    pub(crate) poly_eval_a: PolyEval<T, P>,
    pub(crate) poly_eval_b: PolyEval<T, P>,
    pub(crate) poly_eval_c: PolyEval<T, P>,
    pub(crate) z: PolyEval<T, P>,
    pub(crate) t1: FieldShareVec<T, P>,
    pub(crate) t2: FieldShareVec<T, P>,
    pub(crate) t3: FieldShareVec<T, P>,
}
impl<T, P: Pairing> Round4Polys<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(polys: Round3Polys<T, P>) -> Self {
        Self {
            buffer_a: polys.buffer_a,
            buffer_b: polys.buffer_b,
            buffer_c: polys.buffer_c,
            poly_eval_a: polys.poly_eval_a,
            poly_eval_b: polys.poly_eval_b,
            poly_eval_c: polys.poly_eval_c,
            z: polys.z,
            t1: polys.t1,
            t2: polys.t2,
            t3: polys.t3,
        }
    }
}

impl<T, P: Pairing> Round4Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(round3_challenges: Round3Challenges<T, P>, xi: P::ScalarField) -> Self {
        Self {
            b: round3_challenges.b,
            beta: round3_challenges.beta,
            gamma: round3_challenges.gamma,
            alpha: round3_challenges.alpha,
            alpha2: round3_challenges.alpha2,
            xi,
        }
    }
}

pub(super) struct Round4Proof<P: Pairing> {
    pub(crate) commit_a: P::G1,
    pub(crate) commit_b: P::G1,
    pub(crate) commit_c: P::G1,
    pub(crate) commit_z: P::G1,
    pub(crate) commit_t1: P::G1,
    pub(crate) commit_t2: P::G1,
    pub(crate) commit_t3: P::G1,
}

impl<P: Pairing> Round4Proof<P> {
    fn new(round3_proof: Round3Proof<P>) -> Self {
        Self {
            commit_a: round3_proof.commit_a,
            commit_b: round3_proof.commit_b,
            commit_c: round3_proof.commit_c,
            commit_z: round3_proof.commit_z,
            commit_t1: round3_proof.commit_t1,
            commit_t2: round3_proof.commit_t1,
            commit_t3: round3_proof.commit_t1,
        }
    }
}

impl<T, P: Pairing> Round<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing,
{
    pub(super) fn round4(
        driver: &mut T,
        domains: Domains<P>,
        challenges: Round3Challenges<T, P>,
        proof: Round3Proof<P>,
        polys: Round3Polys<T, P>,
        data: PlonkData<T, P>,
    ) -> PlonkProofResult<Self> {
        // STEP 4.1 - Compute evaluation challenge xi \in F_p
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(challenges.alpha);
        transcript.add_point(proof.commit_t1.into());
        transcript.add_point(proof.commit_t2.into());
        transcript.add_point(proof.commit_t3.into());
        let xi = transcript.get_challenge();
        let challenges = Round4Challenges::new(challenges, xi);
        todo!()
    }
}

#[cfg(test)]
pub mod tests {

    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::{groth16::witness::Witness, plonk::ZKey};
    use collaborative_groth16::groth16::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;

    use crate::{Domains, PlonkData, Round};
    macro_rules! g1_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    use super::Round1Challenges;
    use ark_ec::pairing::Pairing;
    use num_traits::Zero;
    use std::str::FromStr;
    #[test]
    fn test_round4_multiplier2() {
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
            challenges: Round1Challenges::deterministic(&mut driver),
            data: PlonkData {
                witness: witness.into(),
                zkey,
            },
        };
        let round2 = round1.next_round(&mut driver).unwrap();
        let round3 = round2.next_round(&mut driver).unwrap();
        let round4 = round3.next_round(&mut driver).unwrap();
        if let Round::Round5 {
            domains,
            challenges,
            proof,
            polys,
            data,
        } = round4.next_round(&mut driver).unwrap()
        {
        } else {
            panic!("must be round5 after round4");
        }
    }
}
