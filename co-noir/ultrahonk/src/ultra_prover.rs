use co_noir_common::{
    constants::PAIRING_POINT_ACCUMULATOR_SIZE,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    keys::{plain_proving_key::PlainProvingKey, verification_key::VerifyingKeyBarretenberg},
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

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> UltraHonk<C, H> {
    pub(crate) fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        virtual_log_n: usize,
    ) -> Vec<C::ScalarField> {
        tracing::trace!("generate gate challenges");

        transcript
            .get_powers_of_challenge::<C>("Sumcheck:gate_challenge".to_string(), virtual_log_n)
    }

    #[expect(clippy::type_complexity)]
    pub fn prove(
        mut proving_key: PlainProvingKey<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        tracing::trace!("UltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = Oink::new(has_zk);
        let oink_result = oink.prove(&mut proving_key, &mut transcript, verifying_key)?;

        let crs = proving_key.crs;
        let cicruit_size = proving_key.circuit_size;

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        let log_dyadic_circuit_size = proving_key.circuit_size.next_power_of_two().ilog2() as usize;

        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_dyadic_circuit_size
        };

        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript, virtual_log_n);

        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let decider = Decider::new(memory, has_zk);
        let proof = decider.prove(cicruit_size, &crs, transcript, virtual_log_n)?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}
