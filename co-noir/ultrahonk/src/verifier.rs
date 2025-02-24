use crate::{
    decider::{
        types::{
            VerifierMemory, BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK,
        },
        verifier::DeciderVerifier,
    },
    oink::verifier::OinkVerifier,
    prelude::TranscriptFieldType,
    prover::{UltraHonk, ZeroKnowledge},
    transcript::{Transcript, TranscriptHasher},
    types::HonkProof,
};
use co_builder::prelude::{HonkCurve, VerifyingKey};

pub(crate) type HonkVerifyResult<T> = std::result::Result<T, eyre::Report>;

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> UltraHonk<P, H> {
    pub fn verify(
        honk_proof: HonkProof<TranscriptFieldType>,
        verifying_key: VerifyingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("UltraHonk verification");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        let oink_verifier = OinkVerifier::default();
        let oink_result = oink_verifier.verify(&verifying_key, &mut transcript)?;

        let cicruit_size = verifying_key.circuit_size;
        let crs = verifying_key.crs;

        let mut memory = VerifierMemory::from_memory_and_key(oink_result, verifying_key);
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);
        if has_zk == ZeroKnowledge::No {
            let decider_verifier =
                DeciderVerifier::<_, _, BATCHED_RELATION_PARTIAL_LENGTH>::new(memory);
            decider_verifier.verify(cicruit_size, &crs, transcript, has_zk)
        } else {
            let decider_verifier =
                DeciderVerifier::<_, _, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::new(memory);
            decider_verifier.verify(cicruit_size, &crs, transcript, has_zk)
        }
    }
}
