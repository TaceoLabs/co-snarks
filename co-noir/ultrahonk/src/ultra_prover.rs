use crate::{
    CONST_PROOF_SIZE_LOG_N,
    decider::{decider_prover::Decider, types::ProverMemory},
    oink::oink_prover::Oink,
    plain_prover_flavour::PlainProverFlavour,
};
use ark_ec::pairing::Pairing;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, PAIRING_POINT_ACCUMULATOR_SIZE, ProvingKey, ZeroKnowledge},
    prover_flavour::Flavour,
};
use common::HonkProof;
use common::transcript::{Transcript, TranscriptFieldType, TranscriptHasher};
use std::marker::PhantomData;

pub struct UltraHonk<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> {
    phantom_data: PhantomData<(P, H, L)>,
}

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> UltraHonk<P, H, L>
{
    pub(crate) fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> Vec<P::ScalarField> {
        tracing::trace!("generate gate challenges");

        let mut gate_challenges: Vec<<P as Pairing>::ScalarField> =
            Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for idx in 0..CONST_PROOF_SIZE_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{idx}"));
            gate_challenges.push(chall);
        }
        gate_challenges
    }

    pub fn prove(
        mut proving_key: ProvingKey<P, L>,
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
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);

        let num_public_inputs = if L::FLAVOUR == Flavour::Ultra {
            proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE
        } else {
            proving_key.num_public_inputs
        };
        let decider = Decider::new(memory, has_zk);
        let proof = decider.prove(cicruit_size, &crs, transcript)?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}
