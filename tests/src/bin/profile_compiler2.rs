//! Corpus census for register-VM compiler batching opportunities.
//!
//! With no arguments this scans every top-level circuit in `test_vectors` and the
//! co-SNARK benchmark corpus. Additional positional arguments replace those roots.
//! `--static-only` skips KAT/input-driven taint execution.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm2::accel::{MpcAccelerator, MpcAcceleratorConfig};
use circom_mpc_vm2::drivers::taint::{Taint, TaintDriver};
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::profile::{dynamic_batchability, static_batchability};
use circom_mpc_vm2::program::{CompiledProgram, InputInfo, VMConfig};
use eyre::{bail, Result, WrapErr};
use num_bigint::BigUint;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const BENCHMARK_ROOT: &str = "../benchmarks-co-snarks/circom";

fn main() -> Result<()> {
    let mut static_only = false;
    let mut roots = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "--static-only" {
            static_only = true;
        } else {
            roots.push(PathBuf::from(arg));
        }
    }
    if roots.is_empty() {
        roots.push(PathBuf::from("test_vectors"));
        roots.push(PathBuf::from(BENCHMARK_ROOT));
    }

    let mut circuits = Vec::new();
    for root in &roots {
        discover_circuits(root, &mut circuits)?;
    }
    circuits.sort();
    circuits.dedup();
    let discovered = circuits.len();

    println!(
        "circuit,instructions,scalar_vectorizable,existing_vector_calls,existing_vector_lanes,adjacent_saved_static,block_saved_static,created_components,input_sub_sites,interactive_calls,scalar_vectorizable_dynamic,mul_dynamic,bool_and_dynamic,eq_dynamic,neq_dynamic,adjacent_saved_dynamic,block_saved_dynamic"
    );
    let mut compiled = 0usize;
    let mut dynamically_profiled = 0usize;
    for circuit in circuits {
        let program = match CoCircomCompiler::<Bn254>::parse(&circuit, compiler_config(&circuit)) {
            Ok(program) => program,
            Err(error) => {
                eprintln!("skip compile {}: {error:#}", circuit.display());
                continue;
            }
        };
        compiled += 1;
        let static_report = static_batchability(&program);
        let dynamic = if static_only {
            None
        } else if let Some(input_path) = find_input(&circuit) {
            match profile_dynamic(&program, &input_path) {
                Ok(report) => {
                    dynamically_profiled += 1;
                    Some(report)
                }
                Err(error) => {
                    eprintln!(
                        "skip trace {} with {}: {error:#}",
                        circuit.display(),
                        input_path.display()
                    );
                    None
                }
            }
        } else {
            None
        };

        let path = serde_json::to_string(&circuit.display().to_string())?;
        let adjacent_static = static_report
            .adjacent_calls_before
            .saturating_sub(static_report.adjacent_calls_after);
        let block_static = static_report
            .block_calls_before
            .saturating_sub(static_report.block_calls_after);
        if let Some(dynamic) = dynamic {
            println!(
                "{path},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                static_report.instructions,
                static_report.vectorizable_scalar_calls,
                static_report.existing_vector_calls,
                static_report.existing_vector_lanes,
                adjacent_static,
                block_static,
                static_report.created_components,
                static_report.input_sub_sites,
                dynamic.interactive_calls,
                dynamic.vectorizable_scalar_calls,
                dynamic.vectorizable_scalar_by_op.mul,
                dynamic.vectorizable_scalar_by_op.bool_and,
                dynamic.vectorizable_scalar_by_op.eq,
                dynamic.vectorizable_scalar_by_op.neq,
                dynamic
                    .adjacent_calls_before
                    .saturating_sub(dynamic.adjacent_calls_after),
                dynamic
                    .block_calls_before
                    .saturating_sub(dynamic.block_calls_after),
            );
        } else {
            println!(
                "{path},{},{},{},{},{},{},{},{},,,,,,,,,",
                static_report.instructions,
                static_report.vectorizable_scalar_calls,
                static_report.existing_vector_calls,
                static_report.existing_vector_lanes,
                adjacent_static,
                block_static,
                static_report.created_components,
                static_report.input_sub_sites,
            );
        }
    }
    eprintln!(
        "profiled {compiled}/{discovered} compiled circuit(s), {dynamically_profiled} with taint inputs"
    );
    Ok(())
}

fn discover_circuits(path: &Path, circuits: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path
            .extension()
            .is_some_and(|extension| extension == "circom")
            && source_has_main(path)?
        {
            circuits.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path).wrap_err_with(|| format!("read {}", path.display()))? {
        discover_circuits(&entry?.path(), circuits)?;
    }
    Ok(())
}

fn source_has_main(path: &Path) -> Result<bool> {
    let source = fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let mut tokens = source.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "component"
            && tokens
                .next()
                .is_some_and(|next| next == "main" || next.starts_with("main{"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn compiler_config(circuit: &Path) -> CompilerConfig {
    let mut config = CompilerConfig::release();
    if let Some(parent) = circuit.parent() {
        config.link_library.push(parent.to_path_buf());
        for local_lib in [parent.join("BN254/lib"), parent.join("bn254/lib")] {
            if local_lib.is_dir() {
                config.link_library.push(local_lib);
            }
        }
    }
    if let Some(root) = circuit
        .ancestors()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some("WitnessExtension"))
    {
        config.link_library.push(root.join("tests/libs"));
    }
    config
}

fn find_input(circuit: &Path) -> Option<PathBuf> {
    let parent = circuit.parent()?;
    let mut candidates = vec![parent.join("BN254/input.json"), parent.join("input.json")];
    if let Some(kat) = witness_extension_kat_input(circuit) {
        candidates.push(kat);
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn witness_extension_kat_input(circuit: &Path) -> Option<PathBuf> {
    let tests = circuit.parent()?;
    if tests.file_name()?.to_str()? != "tests"
        || tests.parent()?.file_name()?.to_str()? != "WitnessExtension"
    {
        return None;
    }
    Some(
        tests
            .parent()?
            .join("kats")
            .join(circuit.file_stem()?)
            .join("input0.json"),
    )
}

fn profile_dynamic(
    program: &CompiledProgram<Fr>,
    input_path: &Path,
) -> Result<circom_mpc_vm2::profile::DynamicBatchability> {
    let json: serde_json::Value = serde_json::from_reader(
        fs::File::open(input_path).wrap_err_with(|| format!("open {}", input_path.display()))?,
    )?;
    let input = build_flat_input(&json, &program.main_input_list)?;
    if input.len() != program.main_inputs {
        bail!(
            "input has {} values but program expects {}",
            input.len(),
            program.main_inputs
        );
    }

    let mut driver = TaintDriver::<Fr>::profiling();
    {
        let accelerator_config = MpcAcceleratorConfig::default();
        let config = VMConfig {
            accelerator: accelerator_config,
            ..VMConfig::default()
        };
        let accelerator = MpcAccelerator::from_config(accelerator_config);
        let mut machine =
            Machine::new_with_accelerator(program, &mut driver, config, &accelerator)?;
        let start = 1 + program.main_outputs;
        for (slot, value) in machine.signals[start..start + program.main_inputs]
            .iter_mut()
            .zip(input)
        {
            *slot = Taint {
                val: value,
                shared: true,
            };
        }
        machine.run_main()?;
    }
    Ok(dynamic_batchability(
        program,
        driver
            .interaction_profile()
            .expect("profiling driver always has a profile"),
    ))
}

fn build_flat_input(json: &serde_json::Value, layout: &[InputInfo]) -> Result<Vec<Fr>> {
    let object = json
        .as_object()
        .ok_or_else(|| eyre::eyre!("input JSON is not an object"))?;
    let mut result = Vec::new();
    if object.len() == 1 {
        flatten_field(object.values().next().unwrap(), &mut result)?;
    } else {
        for input in layout {
            let value = object
                .get(&input.name)
                .ok_or_else(|| eyre::eyre!("input JSON is missing {:?}", input.name))?;
            let before = result.len();
            flatten_field(value, &mut result)?;
            if result.len() - before != input.size {
                bail!(
                    "input {:?} has {} values but layout expects {}",
                    input.name,
                    result.len() - before,
                    input.size
                );
            }
        }
    }
    Ok(result)
}

fn flatten_field(value: &serde_json::Value, result: &mut Vec<Fr>) -> Result<()> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                flatten_field(value, result)?;
            }
        }
        serde_json::Value::String(value) => result.push(parse_field(value)?),
        serde_json::Value::Number(value) => result.push(parse_field(&value.to_string())?),
        serde_json::Value::Bool(value) => result.push(Fr::from(u64::from(*value))),
        other => bail!("unsupported input value {other}"),
    }
    Ok(())
}

fn parse_field(value: &str) -> Result<Fr> {
    let (negative, magnitude) = value
        .strip_prefix('-')
        .map_or((false, value), |magnitude| (true, magnitude));
    let parsed = if let Some(hex) = magnitude.strip_prefix("0x") {
        let value = BigUint::parse_bytes(hex.as_bytes(), 16)
            .ok_or_else(|| eyre::eyre!("invalid hexadecimal field element"))?;
        Fr::from_le_bytes_mod_order(&value.to_bytes_le())
    } else {
        Fr::from_str(magnitude).map_err(|_| eyre::eyre!("invalid field element"))?
    };
    Ok(if negative { -parsed } else { parsed })
}
