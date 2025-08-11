use std::vec;

use ark_ff::PrimeField;
use co_builder::{flavours::mega_flavour::MegaFlavour, prelude::{HonkCurve, ProverCrs}, HonkProofResult};
use common::{transcript::{Transcript, TranscriptFieldType, TranscriptHasher}, HonkProof};
use goblin::Goblin;
use protogalaxy::protogalaxy_prover::{ProtogalaxyProver, CONST_PG_LOG_N};
use ultrahonk::{decider::types::ProverMemory, oink::oink_prover::Oink, prelude::{ProvingKey, ZeroKnowledge}};
use ark_ff::AdditiveGroup;

pub enum QueueType {
    Oink, 
    Protogalaxy,
}

pub struct VerifierInputs<F: PrimeField> {
    proof: HonkProof<F>,
    merge_proof: HonkProof<F>,
    
    queue_type: QueueType,
}

pub struct ClientIVC<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub goblin: Goblin<C, H>,
    pub accumulator_prover_memory: ProverMemory<C, MegaFlavour>,
    pub accumulator: ProvingKey<C, MegaFlavour>,
    pub initialized: bool,
    pub commitment_key: ProverCrs<C>,
}

impl<C, H> ClientIVC<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub fn accumulate(mut self, mut next_key: ProvingKey<C, MegaFlavour>) -> HonkProofResult<()> {

        let merge_proof = self.goblin.merge_prover.construct_proof(&self.commitment_key);

        // TODO CESAR: Handle overflow

        if !self.initialized {
            let oink = Oink::<C, H, MegaFlavour>::new(ZeroKnowledge::No);
            let mut transcript = Transcript::new();
            let oink_memory = oink.prove(&mut next_key, &mut transcript)?;

            self.accumulator_prover_memory = ProverMemory::from_memory_and_polynomials(oink_memory, next_key.polynomials);
            self.initialized = true;
            self.accumulator_prover_memory.gate_challenges = vec![C::ScalarField::ZERO; CONST_PG_LOG_N];
            // TODO CESAR: Verification key and verification queue
        } else {
            let protogalaxy = ProtogalaxyProver::<C, H, MegaFlavour>::new();
            let (proof, target_sum) = protogalaxy.prove(
                &mut self.accumulator,
                &mut self.accumulator_prover_memory,
                vec![next_key]
            )?;
            // TODO CESAR: Verification key and verification queue
        }

        
        todo!("Implement accumulation logic")

    }
}