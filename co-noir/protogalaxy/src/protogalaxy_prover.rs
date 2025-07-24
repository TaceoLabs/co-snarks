use ark_ec::pairing::Pairing;
use co_builder::{prelude::ProvingKey, prover_flavour::ProverFlavour, HonkProofResult, TranscriptFieldType};

pub struct ProtogalaxyProver {}

pub struct FoldingResult<P, L> 
where 
    P: Pairing,
    L: ProverFlavour,
{
    pub proof: HonkProofResult<TranscriptFieldType>,
    pub proving_key: ProvingKey<P, L>,
}

impl ProtogalaxyProver {
    pub fn prove<P: Pairing, L: ProverFlavour>(
        &self,
        proving_keys: &Vec<ProvingKey<P, L>>,
    ) -> FoldingResult<P, L> {
        let max_circuit_size = proving_keys.iter().map(|pk| pk.circuit_size).max().unwrap_or(0);
    }
}