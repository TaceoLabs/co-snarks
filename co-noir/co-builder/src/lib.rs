#![warn(clippy::iter_over_hash_type)]

pub(crate) mod acir_format;
pub(crate) mod builder;
pub(crate) mod crs;
pub(crate) mod honk_curve;
pub(crate) mod honk_recursion_constraint;
pub(crate) mod keys;
pub(crate) mod polynomials;
pub mod prelude;
pub(crate) mod serialize;
pub(crate) mod transcript;
pub(crate) mod types;
pub(crate) mod utils;

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
    /// Gemini evaluation challenge is in the SmallSubgroup
    #[error("Gemini evaluation challenge is in the SmallSubgroup.")]
    GeminiSmallSubgroup,
    /// The Subgroup for the FFT domain is too large
    #[error("Too large Subgroup")]
    LargeSubgroup,
}
