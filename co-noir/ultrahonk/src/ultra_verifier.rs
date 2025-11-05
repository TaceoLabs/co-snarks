use ark_ec::pairing::Pairing;
use co_builder::prelude::VerifyingKey;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use noir_types::HonkProof;

use crate::{
    CONST_PROOF_SIZE_LOG_N,
    decider::{decider_verifier::DeciderVerifier, types::VerifierMemory},
    oink::oink_verifier::OinkVerifier,
    ultra_prover::UltraHonk,
};

pub(crate) type HonkVerifyResult<T> = std::result::Result<T, eyre::Report>;

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> UltraHonk<C, H> {
    pub fn verify<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        honk_proof: HonkProof<H::DataType>,
        public_inputs: &[H::DataType],
        verifying_key: &VerifyingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("UltraHonk verification");
        let honk_proof = honk_proof.insert_public_inputs(public_inputs.to_vec());

        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        let oink_verifier = OinkVerifier::new("".to_string());
        let oink_result = oink_verifier.verify(verifying_key, &mut transcript)?;

        let log_circuit_size = verifying_key.inner_vk.log_circuit_size;
        let crs = verifying_key.crs;

        let mut memory = VerifierMemory::from_memory_and_key(oink_result, verifying_key);
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_circuit_size as usize
        };
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript, virtual_log_n);
        let decider_verifier = DeciderVerifier::new(memory);
        decider_verifier.verify::<P>(
            log_circuit_size
                .try_into()
                .expect("log circuit size fits in u32"),
            &crs,
            transcript,
            has_zk,
            virtual_log_n,
        )
    }
}
