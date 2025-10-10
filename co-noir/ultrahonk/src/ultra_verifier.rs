use crate::{
    decider::{decider_verifier::DeciderVerifier, types::VerifierMemory},
    oink::oink_verifier::OinkVerifier,
    plain_prover_flavour::PlainProverFlavour,
    ultra_prover::UltraHonk,
};
use ark_ec::pairing::Pairing;
use co_builder::prelude::VerifyingKey;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::transcript::{Transcript, TranscriptHasher};
use co_noir_common::types::ZeroKnowledge;
use noir_types::HonkProof;

pub(crate) type HonkVerifyResult<T> = std::result::Result<T, eyre::Report>;

impl<
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> UltraHonk<C, H, L>
{
    pub fn verify<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        honk_proof: HonkProof<TranscriptFieldType>,
        public_inputs: &[TranscriptFieldType],
        verifying_key: &VerifyingKey<P, L>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("UltraHonk verification");
        let honk_proof = honk_proof.insert_public_inputs(public_inputs.to_vec());

        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        let oink_verifier = OinkVerifier::<C, H, _>::default();
        let oink_result = oink_verifier.verify(verifying_key, &mut transcript)?;

        let circuit_size = verifying_key.circuit_size;
        let crs = verifying_key.crs;

        let mut memory = VerifierMemory::from_memory_and_key(oink_result, verifying_key);
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript);
        let decider_verifier = DeciderVerifier::new(memory);
        decider_verifier.verify::<P>(circuit_size, &crs, transcript, has_zk)
    }
}
