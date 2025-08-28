use ark_ff::PrimeField;
use crate::serialize::Serialize;

pub type TranscriptFieldType = ark_bn254::Fr;
pub type TranscriptFieldTypeGrumpkin = ark_grumpkin::Fr;
pub type HonkProofResult<T> = std::result::Result<T, HonkProofError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: PrimeField> {
    proof: Vec<F>,
}

impl<F: PrimeField> HonkProof<F> {
    pub fn new(proof: Vec<F>) -> Self {
        Self { proof }
    }

    pub fn inner(self) -> Vec<F> {
        self.proof
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        Serialize::to_buffer(&self.proof, false)
    }

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let res = Serialize::from_buffer(buf, false)?;
        Ok(Self::new(res))
    }

    pub fn separate_proof_and_public_inputs(self, num_public_inputs: usize) -> (Self, Vec<F>) {
        let (public_inputs, proof) = self.proof.split_at(num_public_inputs);
        (Self::new(proof.to_vec()), public_inputs.to_vec())
    }

    pub fn insert_public_inputs(self, public_inputs: Vec<F>) -> Self {
        let mut proof = public_inputs;
        proof.extend(self.proof.to_owned());
        Self::new(proof)
    }
}


/// The errors that may arise during the computation of a HONK proof.
#[derive(Debug, thiserror::Error)]
pub enum HonkProofError {
    /// Indicates that the witness is too small for the provided circuit.
    #[error("Cannot index into witness {0}")]
    CorruptedWitness(usize),
    /// Indicates that the crs is too small
    #[error("CRS too small")]
    CrsTooSmall,
    /// The proof has too few elements
    #[error("Proof too small")]
    ProofTooSmall,
    /// Invalid proof length
    #[error("Invalid proof length")]
    InvalidProofLength,
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,
    /// Corrupted Key
    #[error("Corrupted Key")]
    CorruptedKey,
    /// Expected Public Witness, Shared received
    #[error("Expected Public Witness, Shared received")]
    ExpectedPublicWitness,
    /// Gemini evaluation challenge is in the SmallSubgroup
    #[error("Gemini evaluation challenge is in the SmallSubgroup.")]
    GeminiSmallSubgroup,
    /// The Subgroup for the FFT domain is too large
    #[error("Too large Subgroup")]
    LargeSubgroup,
    /// Any other error
    #[error(transparent)]
    Other(#[from] eyre::Report),
}
