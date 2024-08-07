use crate::{
    round1::{Round1Challenges, Round1Proof},
    round2::{Round2Challenges, Round2Polys, Round2Proof},
    round3::{Round3Challenges, Round3Polys, Round3Proof},
    round4::{Round4Challenges, Round4Polys, Round4Proof},
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
pub(super) struct Round5Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    b: [T::FieldShare; 11],
    beta: P::ScalarField,
    gamma: P::ScalarField,
    alpha: P::ScalarField,
    alpha2: P::ScalarField,
}

pub(super) struct Round5Polys<T, P: Pairing>
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
impl<T, P: Pairing> Round5Polys<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(polys: Round4Polys<T, P>) -> Self {
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

impl<T, P: Pairing> Round5Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(
        round4_challenges: Round4Challenges<T, P>,
        alpha: P::ScalarField,
        alpha2: P::ScalarField,
    ) -> Self {
        Self {
            b: round4_challenges.b,
            beta: round4_challenges.beta,
            gamma: round4_challenges.gamma,
            alpha: round4_challenges.alpha,
            alpha2: round4_challenges.alpha2,
        }
    }
}

pub(super) struct Round5Proof<P: Pairing> {
    pub(crate) commit_a: P::G1,
    pub(crate) commit_b: P::G1,
    pub(crate) commit_c: P::G1,
    pub(crate) commit_z: P::G1,
    pub(crate) commit_t1: P::G1,
    pub(crate) commit_t2: P::G1,
    pub(crate) commit_t3: P::G1,
}

impl<P: Pairing> Round5Proof<P> {
    fn new(round4_proof: Round4Proof<P>) -> Self {
        Self {
            commit_a: round4_proof.commit_a,
            commit_b: round4_proof.commit_b,
            commit_c: round4_proof.commit_c,
            commit_z: round4_proof.commit_z,
            commit_t1: round4_proof.commit_t1,
            commit_t2: round4_proof.commit_t1,
            commit_t3: round4_proof.commit_t1,
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
    pub(super) fn round5(
        driver: &mut T,
        domains: Domains<P>,
        challenges: Round4Challenges<T, P>,
        proof: Round4Proof<P>,
        polys: Round4Polys<T, P>,
        data: PlonkData<T, P>,
    ) -> PlonkProofResult<Self> {
        todo!()
    }
}
