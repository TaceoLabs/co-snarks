use std::{fs::File, io::BufReader};

use ark_ff::PrimeField;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm::mpc_vm::VMConfig;
use co_circom_snarks::{BatchedSharedInput, SharedInput};
use co_noir::Bn254;
use num_bigint::BigUint;
use num_traits::Num as _;
use rand::{thread_rng, Rng};
use tests::test_utils;

#[test]
fn batched_add_1() -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let add_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/multiplier2.circom");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&add_circuit, compiler_config)?;

    let batch_size = 1;
    let mut rng = thread_rng();
    let mut batch = Vec::with_capacity(1);
    let mut should_witness = Vec::with_capacity(1);
    for _ in 0..batch_size {
        let mut shared_input = SharedInput::default();
        shared_input.add_shared_input("a".to_string(), vec![rng.gen::<ark_bn254::Fr>()]);
        shared_input.add_shared_input("b".to_string(), vec![rng.gen::<ark_bn254::Fr>()]);
        batch.push(shared_input.clone());
        let parsed = parsed.clone();
        let current_wtns = parsed
            .to_plain_vm(VMConfig::default())
            .run(shared_input)?
            .into_shared_witness();
        should_witness.push(current_wtns);
    }

    let is_wts = parsed
        .to_batched_plain_vm(VMConfig::default(), batch_size)
        .run(BatchedSharedInput::try_from(batch.clone())?)?
        .into_shared_witness()
        .unbatch();
    assert_eq!(is_wts, should_witness);
    Ok(())
}

#[test]
fn batched_add_100() -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let add_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/multiplier2.circom");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&add_circuit, compiler_config)?;

    let batch_size = 100;
    let mut rng = thread_rng();
    let mut batch = Vec::with_capacity(batch_size);
    let mut should_witness = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let mut shared_input = SharedInput::default();
        shared_input.add_shared_input("a".to_string(), vec![rng.gen::<ark_bn254::Fr>()]);
        shared_input.add_shared_input("b".to_string(), vec![rng.gen::<ark_bn254::Fr>()]);
        batch.push(shared_input.clone());
        let parsed = parsed.clone();
        let current_wtns = parsed
            .to_plain_vm(VMConfig::default())
            .run(shared_input)?
            .into_shared_witness();
        should_witness.push(current_wtns);
    }

    let is_wts = parsed
        .to_batched_plain_vm(VMConfig::default(), batch_size)
        .run(BatchedSharedInput::try_from(batch.clone())?)?
        .into_shared_witness()
        .unbatch();
    assert_eq!(is_wts, should_witness);
    Ok(())
}

#[test]
fn batched_chacha20_1() -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let chacha_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/chacha20.circom");
    let input = format!("{root}/../test_vectors/WitnessExtension/kats/chacha20/input0.json");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

    let public_inputs =
        CoCircomCompiler::<Bn254>::get_public_inputs(&chacha_circuit, compiler_config).unwrap();

    let batch_size = 1;

    let input_file = BufReader::new(File::open(input)?);
    let input_json: serde_json::Map<String, serde_json::Value> =
        serde_json::from_reader(input_file).unwrap();
    let mut shared_input = SharedInput::default();
    for (k, v) in input_json {
        let parsed_vals = if v.is_array() {
            test_utils::parse_array::<ark_bn254::Fr>(&v).unwrap()
        } else {
            vec![test_utils::parse_field::<ark_bn254::Fr>(&v).unwrap()]
        };
        if public_inputs.contains(&k) {
            shared_input.add_public_input(k, parsed_vals);
        } else {
            shared_input.add_shared_input(k, parsed_vals);
        }
    }

    let should_witness = parsed
        .clone()
        .to_plain_vm(VMConfig::default())
        .run(shared_input.clone())?
        .into_shared_witness();

    let is_wts = parsed
        .to_batched_plain_vm(VMConfig::default(), batch_size)
        .run(BatchedSharedInput::try_from(vec![
            shared_input;
            batch_size
        ])?)?
        .into_shared_witness()
        .unbatch();
    assert!(is_wts.into_iter().all(|is| is == should_witness));

    Ok(())
}

#[test]
fn batched_chacha20_30() -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let chacha_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/chacha20.circom");
    let input = format!("{root}/../test_vectors/WitnessExtension/kats/chacha20/input0.json");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

    let public_inputs =
        CoCircomCompiler::<Bn254>::get_public_inputs(&chacha_circuit, compiler_config).unwrap();

    let batch_size = 30;

    let input_file = BufReader::new(File::open(input)?);
    let input_json: serde_json::Map<String, serde_json::Value> =
        serde_json::from_reader(input_file).unwrap();
    let mut shared_input = SharedInput::default();
    for (k, v) in input_json {
        let parsed_vals = if v.is_array() {
            test_utils::parse_array::<ark_bn254::Fr>(&v).unwrap()
        } else {
            vec![test_utils::parse_field::<ark_bn254::Fr>(&v).unwrap()]
        };
        if public_inputs.contains(&k) {
            shared_input.add_public_input(k, parsed_vals);
        } else {
            shared_input.add_shared_input(k, parsed_vals);
        }
    }

    let should_witness = parsed
        .clone()
        .to_plain_vm(VMConfig::default())
        .run(shared_input.clone())?
        .into_shared_witness();

    let is_wts = parsed
        .to_batched_plain_vm(VMConfig::default(), batch_size)
        .run(BatchedSharedInput::try_from(vec![
            shared_input;
            batch_size
        ])?)?
        .into_shared_witness()
        .unbatch();
    assert!(is_wts.into_iter().all(|is| is == should_witness));

    Ok(())
}
