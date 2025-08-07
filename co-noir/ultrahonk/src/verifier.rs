use crate::{
    decider::{types::VerifierMemory, verifier::DeciderVerifier},
    oink::verifier::OinkVerifier,
    plain_prover_flavour::PlainProverFlavour,
    prover::UltraHonk,
    transcript::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
    types::HonkProof,
};
use co_builder::prelude::{HonkCurve, VerifyingKey, ZeroKnowledge};

pub(crate) type HonkVerifyResult<T> = std::result::Result<T, eyre::Report>;

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> UltraHonk<P, H, L>
{
    pub fn verify(
        honk_proof: HonkProof<TranscriptFieldType>,
        public_inputs: &[TranscriptFieldType],
        verifying_key: &VerifyingKey<P, L>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("UltraHonk verification");
        let honk_proof = honk_proof.insert_public_inputs(public_inputs.to_vec());

        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        let oink_verifier = OinkVerifier::<P, H, _>::default();
        let oink_result = oink_verifier.verify(verifying_key, &mut transcript)?;

        let circuit_size = verifying_key.circuit_size;
        let crs = verifying_key.crs;

        let mut memory = VerifierMemory::from_memory_and_key(oink_result, verifying_key);
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript);
        let decider_verifier = DeciderVerifier::new(memory);
        decider_verifier.verify(circuit_size, &crs, transcript, has_zk)
    }
}
