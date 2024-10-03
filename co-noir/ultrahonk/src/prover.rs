use crate::{
    decider::{prover::Decider, types::ProverMemory},
    honk_curve::HonkCurve,
    oink::prover::Oink,
    poseidon2::poseidon2_bn254::POSEIDON2_BN254_T4_PARAMS,
    transcript::{TranscriptFieldType, TranscriptType},
    types::{HonkProof, ProvingKey},
    CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::pairing::Pairing;
use std::{io, marker::PhantomData};

pub type HonkProofResult<T> = std::result::Result<T, HonkProofError>;

/// The errors that may arise during the computation of a HONK proof.
#[derive(Debug, thiserror::Error)]
pub enum HonkProofError {
    /// Indicates that the witness is too small for the provided circuit.
    #[error("Cannot index into witness {0}")]
    CorruptedWitness(usize),
    /// Indicates that the crs is too small
    #[error("CRS too small")]
    CrsTooSmall,
    /// The proof has too little elements
    #[error("Proof too small")]
    ProofTooSmall,
    /// Invalid proof length
    #[error("Invalid proof length")]
    InvalidProofLength,
    #[error(transparent)]
    IOError(#[from] io::Error),
}

pub struct UltraHonk<P: HonkCurve<TranscriptFieldType>> {
    phantom_data: PhantomData<P>,
}

impl<P: HonkCurve<TranscriptFieldType>> UltraHonk<P> {
    pub(crate) fn generate_gate_challenges(transcript: &mut TranscriptType) -> Vec<P::ScalarField> {
        tracing::trace!("generate gate challenges");

        let mut gate_challenges: Vec<<P as Pairing>::ScalarField> =
            Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for idx in 0..CONST_PROOF_SIZE_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{}", idx));
            gate_challenges.push(chall);
        }
        gate_challenges
    }

    pub fn prove(proving_key: ProvingKey<P>) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("UltraHonk prove");

        let mut transcript = TranscriptType::new(&POSEIDON2_BN254_T4_PARAMS);

        let oink = Oink::default();
        let oink_result = oink.prove(&proving_key, &mut transcript)?;

        let cicruit_size = proving_key.circuit_size;
        let crs = proving_key.crs;

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);

        let decider = Decider::new(memory);
        decider.prove(cicruit_size, &crs, transcript)
    }
}
