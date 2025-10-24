#![warn(clippy::iter_over_hash_type)]

use noir_types::ProgramArtifact;

use crate::prelude::AcirFormat;

pub(crate) mod acir_format;
pub(crate) mod keys;
pub mod polynomials;
pub mod prelude;
pub mod types;
pub(crate) mod ultra_builder;

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
