use crate::{
    decider::{prover::Decider, types::ProverMemory},
    oink::prover::Oink,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
    types::HonkProof,
    CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::pairing::Pairing;
use co_builder::{
    prelude::{HonkCurve, ProvingKey, ZeroKnowledge},
    HonkProofResult,
};
use std::marker::PhantomData;

pub struct UltraHonk<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> {
    phantom_data: PhantomData<P>,
    phantom_hasher: PhantomData<H>,
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> UltraHonk<P, H> {
    pub(crate) fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> Vec<P::ScalarField> {
        tracing::trace!("generate gate challenges");

        let mut gate_challenges: Vec<<P as Pairing>::ScalarField> =
            Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for idx in 0..CONST_PROOF_SIZE_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{}", idx));
            gate_challenges.push(chall);
        }
        gate_challenges
    }

    pub fn prove(
        proving_key: ProvingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("UltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = Oink::new(has_zk);
        let oink_result = oink.prove(&proving_key, &mut transcript)?;

        let crs = proving_key.crs;
        let cicruit_size = proving_key.circuit_size;

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);

        let decider = Decider::new(memory, has_zk);
        decider.prove(cicruit_size, &crs, transcript)
    }
}
