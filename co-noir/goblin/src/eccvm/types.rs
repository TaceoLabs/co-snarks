#![expect(unused)]
use ark_ec::CurveGroup;
use co_builder::HonkProofResult;
use co_builder::{
    TranscriptFieldType,
    prelude::{Polynomial, ProverCrs},
};
use ultrahonk::{
    plain_prover_flavour::PlainProverFlavour,
    prelude::{
        AllEntities, RelationParameters, SmallSubgroupIPAProver, Transcript, TranscriptHasher,
    },
};

pub(crate) struct ProverMemory<P: CurveGroup, L: PlainProverFlavour> {
    pub(crate) polys: AllEntities<Vec<P::ScalarField>, L>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField, L>,
}

pub(crate) struct TranslationData<P: CurveGroup> {
    // M(X) whose Lagrange coefficients are given by (m_0 || m_1 || ... || m_{NUM_TRANSLATION_EVALUATIONS-1} || 0 || ... || 0)
    pub concatenated_polynomial_lagrange: Polynomial<P::ScalarField>,

    // M(X) + Z_H(X) * R(X), where R(X) is a random polynomial of length = WITNESS_MASKING_TERM_LENGTH
    pub masked_concatenated_polynomial: Polynomial<P::ScalarField>,
}
impl<P: CurveGroup> TranslationData<P> {
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>>(
        translation_polynomials: &[&Polynomial<P::ScalarField>],
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
    ) -> Self {
        todo!()
    }

    pub fn compute_small_ipa_prover<
        H: TranscriptHasher<TranscriptFieldType>,
        // R: rand::Rng + rand::CryptoRng,
    >(
        &mut self,
        evaluation_challenge_x: P::ScalarField,
        batching_challenge_v: P::ScalarField,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<SmallSubgroupIPAProver<P>> {
        todo!()
    }
}
