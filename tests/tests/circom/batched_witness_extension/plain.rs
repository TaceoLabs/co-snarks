use std::{collections::BTreeMap, fs::File, io::BufReader};

use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm::mpc_vm::VMConfig;
use co_noir::Bn254;
use rand::{thread_rng, Rng as _};
use tests::test_utils::{self};

#[test]
fn batched_multiplier2_1() -> eyre::Result<()> {
    batched_multiplier2(1)
}

#[test]
fn batched_multiplier2_100() -> eyre::Result<()> {
    batched_multiplier2(100)
}

fn batched_multiplier2(batch_size: usize) -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let add_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/multiplier2.circom");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&add_circuit, compiler_config)?;
    let num_public_inputs = parsed.public_inputs().len();

    let mut rng = thread_rng();
    let mut batch: BTreeMap<String, Vec<ark_bn254::Fr>> = BTreeMap::default();
    let mut should_witness = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let mut plain_input = BTreeMap::new();

        let a = rng.gen::<ark_bn254::Fr>();
        let b = rng.gen::<ark_bn254::Fr>();
        batch.entry("a".to_string()).or_default().push(a);
        batch.entry("b".to_string()).or_default().push(b);

        plain_input.insert("a".to_string(), a);
        plain_input.insert("b".to_string(), b);

        let parsed = parsed.clone();
        let current_wtns = parsed
            .to_plain_vm(VMConfig::default())
            .run(plain_input, num_public_inputs)?
            .into_shared_witness();
        should_witness.push(current_wtns);
    }

    let is_wts = parsed
        .to_batched_plain_vm(VMConfig::default(), batch_size)
        .run(batch, num_public_inputs)?
        .into_shared_witness()
        .unbatch();
    assert_eq!(is_wts, should_witness);

    Ok(())
}

#[test]
fn batched_chacha20_1() -> eyre::Result<()> {
    batched_chacha20(1)
}

#[test]
fn batched_chacha20_30() -> eyre::Result<()> {
    batched_chacha20(30)
}

fn batched_chacha20(batch_size: usize) -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let chacha_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/chacha20.circom");
    let input = format!("{root}/../test_vectors/WitnessExtension/kats/chacha20/input0.json");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

    let num_public_inputs = parsed.public_inputs().len();

    let input_file = BufReader::new(File::open(input)?);
    let input: serde_json::Map<String, serde_json::Value> =
        serde_json::from_reader(input_file).unwrap();
    let mut batch: BTreeMap<String, Vec<ark_bn254::Fr>> = BTreeMap::default();

    for _ in 0..batch_size {
        for (name, value) in test_utils::split_input_plain(input.clone())? {
            batch.entry(name).or_default().push(value);
        }
    }

    let plain_input = test_utils::split_input_plain(input)?;
    let should_witness = parsed
        .clone()
        .to_plain_vm(VMConfig::default())
        .run(plain_input, num_public_inputs)?
        .into_shared_witness();

    let is_wts = parsed
        .to_batched_plain_vm(VMConfig::default(), batch_size)
        .run(batch, num_public_inputs)?
        .into_shared_witness()
        .unbatch();
    assert!(is_wts.into_iter().all(|is| is == should_witness));

    Ok(())
}
