use co_builder::prelude::{PAIRING_POINT_ACCUMULATOR_SIZE, ProvingKey};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use noir_types::HonkProof;
use std::marker::PhantomData;

use crate::decider::decider_prover::Decider;
use crate::{CONST_PROOF_SIZE_LOG_N, decider::types::ProverMemory, oink::oink_prover::Oink};

pub struct UltraHonk<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> {
    phantom_data: PhantomData<P>,
    phantom_hasher: PhantomData<H>,
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> UltraHonk<P, H> {
    pub(crate) fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> Vec<P::ScalarField> {
        tracing::trace!("generate gate challenges");

        let mut gate_challenges: Vec<P::ScalarField> = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for idx in 0..CONST_PROOF_SIZE_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{idx}"));
            gate_challenges.push(chall);
        }
        gate_challenges
    }

    pub fn prove(
        mut proving_key: ProvingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<(HonkProof<TranscriptFieldType>, Vec<TranscriptFieldType>)> {
        tracing::trace!("UltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = Oink::new(has_zk);
        let oink_result = oink.prove(&mut proving_key, &mut transcript)?;

        let crs = proving_key.crs;
        let cicruit_size = proving_key.circuit_size;

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript);

        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let decider = Decider::new(memory, has_zk);
        let proof = decider.prove(cicruit_size, &crs, transcript)?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}
