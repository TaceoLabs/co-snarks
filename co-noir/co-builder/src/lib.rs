#![warn(clippy::iter_over_hash_type)]

use noir_types::ProgramArtifact;

use crate::prelude::AcirFormat;

pub(crate) mod acir_format;
pub(crate) mod crs;
pub mod flavours;
pub(crate) mod honk_curve;
pub(crate) mod keys;
pub mod polynomials;
pub mod prelude;
pub mod prover_flavour;
pub(crate) mod serialize;
pub(crate) mod transcript;
pub(crate) mod types;
pub(crate) mod ultra_builder;
pub(crate) mod utils;

pub type TranscriptFieldType = ark_bn254::Fr;
pub type TranscriptFieldTypeGrumpkin = ark_grumpkin::Fr;
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

pub fn get_constraint_system_from_artifact(
    program_artifact: &ProgramArtifact,
    honk_recusion: bool,
) -> AcirFormat<ark_bn254::Fr> {
    let circuit = program_artifact.bytecode.functions[0].to_owned();
    AcirFormat::circuit_serde_to_acir_format(circuit, honk_recusion)
}

pub fn constraint_system_from_reader(
    reader: impl std::io::Read,
    honk_recusion: bool,
) -> eyre::Result<AcirFormat<ark_bn254::Fr>> {
    let program_artifact = noir_types::program_artifact_from_reader(reader)?;
    Ok(get_constraint_system_from_artifact(
        &program_artifact,
        honk_recusion,
    ))
}
