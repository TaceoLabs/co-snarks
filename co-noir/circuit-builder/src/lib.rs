mod acir_format;
mod builder;
mod crs;
mod honk_curve;
pub mod mpc;
#[allow(unused)] // TODO remove later
mod plookup;
mod polynomial;
mod polynomial_types;
pub mod prelude;
mod proving_key;
mod serialize;
#[allow(unused)] // TODO remove later
mod types;
mod utils;
mod verification_key;

pub type TranscriptFieldType = ark_bn254::Fr;
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
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
