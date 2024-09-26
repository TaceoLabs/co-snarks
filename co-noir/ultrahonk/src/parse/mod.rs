pub(crate) mod acir_format;
pub(crate) mod builder;
pub(crate) mod crs;
pub(crate) mod plookup;
pub(crate) mod proving_key;
pub mod types;

use acir::{circuit::Circuit, native_types::WitnessStack, FieldElement};
use acir_format::AcirFormat;
use noirc_artifacts::program::ProgramArtifact;
use std::io;

fn read_circuit_from_file(path: &str) -> io::Result<Circuit<FieldElement>> {
    let program = std::fs::read_to_string(path)?;
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)?;
    Ok(program_artifact.bytecode.functions[0].to_owned())
}

fn read_witness_stack_from_file(path: &str) -> io::Result<WitnessStack<FieldElement>> {
    let witness_stack = std::fs::read(path)?;
    WitnessStack::try_from(witness_stack.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn get_constraint_system_from_file(
    path: &str,
    honk_recusion: bool,
) -> io::Result<AcirFormat<ark_bn254::Fr>> {
    let circuit = read_circuit_from_file(path)?;
    let constraint_system = AcirFormat::circuit_serde_to_acir_format(circuit, honk_recusion);
    Ok(constraint_system)
}

pub fn get_witness_from_file(path: &str) -> io::Result<Vec<ark_bn254::Fr>> {
    let mut witness_stack = read_witness_stack_from_file(path)?;
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;
    let witness = AcirFormat::witness_map_to_witness_vector(witness_map);
    Ok(witness)
}
