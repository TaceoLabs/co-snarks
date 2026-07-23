//! The circom "front half": parsing, type checking, and VCP/circuit construction.
//!
//! This mirrors the front half of the old `circom-mpc-compiler` crate almost verbatim —
//! everything up to (but not including) the bytecode lowering, which lives in the crate's
//! (private) `codegen` module.
use crate::CompilerConfig;
use crate::SimplificationLevel;
use ark_ff::{BigInteger, PrimeField};
use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags, VCP},
    hir::very_concrete_program::Wire,
    intermediate_representation::ir_interface::SizeOption,
};
use circom_constraint_generation::BuildConfig;
use circom_program_structure::{
    ast::SignalType, error_definition::Report, program_archive::ProgramArchive,
};
use circom_type_analysis::check_types;
use circom_types::traits::CircomArkworksPairingBridge;
use eyre::{Result, bail, eyre};
use std::{collections::HashMap, path::Path};

/// Output signal name -> (offset, size) within the (public) witness/signal layout.
pub type OutputMapping = HashMap<String, (usize, usize)>;

/// Runs the circom parser and type checker on `file`, producing a [`ProgramArchive`].
pub(crate) fn get_program_archive<P>(file: &Path, config: &CompilerConfig) -> Result<ProgramArchive>
where
    P: CircomArkworksPairingBridge,
{
    let field = P::ScalarField::MODULUS;
    let field_dig = circom_compiler::num_bigint::BigInt::from_bytes_be(
        circom_compiler::num_bigint::Sign::Plus,
        field.to_bytes_be().as_slice(),
    );
    match circom_parser::run_parser(
        file.display().to_string(),
        &config.version,
        config.link_library.clone(),
        &field_dig,
        false,
    ) {
        Ok((mut program_archive, warnings)) => {
            Report::print_reports(&warnings, &program_archive.file_library);
            match check_types::check_types(&mut program_archive) {
                Ok(warnings) => {
                    Report::print_reports(&warnings, &program_archive.file_library);
                    Ok(program_archive)
                }
                Err(errors) => {
                    Report::print_reports(&errors, &program_archive.file_library);
                    bail!("Error during type checking");
                }
            }
        }
        Err((file_lib, errors)) => {
            Report::print_reports(&errors, &file_lib);
            bail!("Error during compilation");
        }
    }
}

fn get_output_mapping(vcp: &VCP) -> OutputMapping {
    let mut output_mappings = HashMap::new();
    let initial_node = vcp.get_main_id();
    let main = &vcp.templates[initial_node];
    for s in &main.wires {
        if let Wire::TSignal(s) = s
            && s.xtype == SignalType::Output
        {
            output_mappings.insert(s.name.clone(), (s.dag_local_id, s.size));
        }
        // TODO: Can buses be outputs?
    }
    output_mappings
}

/// Runs constraint generation over `program_archive`, producing the circom-compiler
/// [`CircomCircuit`] representation together with the main component's [`OutputMapping`].
pub fn build<P>(
    program_archive: ProgramArchive,
    config: &CompilerConfig,
) -> Result<(CircomCircuit, OutputMapping)>
where
    P: CircomArkworksPairingBridge,
{
    let build_config = BuildConfig {
        no_rounds: if let SimplificationLevel::O2(r) = config.simplification {
            r
        } else {
            0
        },
        flag_json_sub: false,
        json_substitutions: String::new(),
        flag_s: config.simplification == SimplificationLevel::O1,
        flag_f: config.simplification == SimplificationLevel::O0,
        flag_p: false,
        flag_verbose: config.verbose,
        flag_old_heuristics: false,
        inspect_constraints: config.inspect,
        prime: P::get_circom_name(),
    };
    let (_, vcp) = circom_constraint_generation::build_circuit(program_archive, build_config)
        .map_err(|_| eyre!("cannot build vcp"))?;
    let output_mapping = get_output_mapping(&vcp);

    let flags = CompilationFlags {
        main_inputs_log: false,
        wat_flag: false,
        constraint_assert_disabled_flag: false,
        no_asm_flag: false,
    };
    Ok((
        CircomCircuit::build(vcp, flags, &config.version),
        output_mapping,
    ))
}

/// Sums up the size of a [`SizeOption`] (a single value, or a set of alternative sizes
/// for a run-time-conditional access).
pub(crate) fn get_size_from_size_option(size_option: &SizeOption) -> usize {
    match size_option {
        SizeOption::Single(v) => *v,
        SizeOption::Multiple(v) => v
            .iter()
            .map(|x| {
                // second value is the size
                x.1
            })
            .sum(),
    }
}
