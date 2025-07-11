use crate::{
    decider::{types::VerifierMemory, verifier::DeciderVerifier},
    oink::verifier::OinkVerifier,
    prelude::TranscriptFieldType,
    prover::UltraHonk,
    transcript::{Transcript, TranscriptHasher},
    types::HonkProof,
};
use co_builder::prelude::{HonkCurve, VerifyingKey, ZeroKnowledge};

pub(crate) type HonkVerifyResult<T> = std::result::Result<T, eyre::Report>;

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> UltraHonk<P, H> {
    pub fn verify(
        honk_proof: HonkProof<TranscriptFieldType>,
        public_inputs: &[TranscriptFieldType],
        verifying_key: &VerifyingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("UltraHonk verification");
        let honk_proof = honk_proof.insert_public_inputs(public_inputs.to_vec());

        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        let oink_verifier = OinkVerifier::default();
        let oink_result = oink_verifier.verify(verifying_key, &mut transcript)?;

        let circuit_size = verifying_key.circuit_size;
        let crs = verifying_key.crs;

        let mut memory = VerifierMemory::from_memory_and_key(oink_result, verifying_key);
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);
        let decider_verifier = DeciderVerifier::new(memory);
        decider_verifier.verify(circuit_size, &crs, transcript, has_zk)
    }
}
