use circom_mpc_vm::{
    mpc_vm::{BatchedRep3WitnessExtension, VMConfig},
    BatchedRep3VmType,
};
use co_circom_types::BatchedRep3SharedInput;

use ark_bn254::Bn254;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use itertools::izip;
use mpc_net::local::LocalNetwork;
use std::{fs::File, io::BufReader};
use tests::test_utils::{self};

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_line_number(false)
        .with_timer(());

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        //.with(FlamegraphLayer::file(
        //    File::create("flamegraph.data").expect("can open"),
        //))
        //        .with(FlamegraphLayer::stdio())
        .with(fmt_layer.with_filter(filter_layer))
        .init();
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let root = std::env!("CARGO_MANIFEST_DIR");
    let chacha_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/chacha20.circom");
    let input = format!("{root}/../test_vectors/WitnessExtension/kats/chacha20/input0.json");
    let batch_size = 2;

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

    let public_inputs =
        CoCircomCompiler::<Bn254>::get_public_inputs(&chacha_circuit, compiler_config).unwrap();
    let num_public_inputs = parsed.public_inputs().len();

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();

    let input_file = BufReader::new(File::open(input)?);
    let input: serde_json::Map<String, serde_json::Value> =
        serde_json::from_reader(input_file).unwrap();
    let mut batch = vec![BatchedRep3SharedInput::default(); 3];

    for _ in 0..batch_size {
        let [shares0, shares1, shares2] =
            co_circom_types::split_input(input.clone(), &public_inputs)?;
        for (name, share0, share1, share2) in izip!(
            shares0.keys(),
            shares0.values(),
            shares1.values(),
            shares2.values()
        ) {
            batch[0].entry(name.clone()).or_default().push(*share0);
            batch[1].entry(name.clone()).or_default().push(*share1);
            batch[2].entry(name.clone()).or_default().push(*share2);
        }
    }

    let plain_input = test_utils::split_input_plain(input)?;
    let should_plain_witness = parsed
        .clone()
        .to_plain_vm(VMConfig::default())
        .run(plain_input, num_public_inputs)?
        .into_shared_witness();

    let mut should_witness = vec![];
    should_witness.extend(should_plain_witness.public_inputs);
    should_witness.extend(should_plain_witness.witness);

    let compiler = [parsed.clone(), parsed.clone(), parsed];

    let mut threads = vec![];
    for (net0, net1, input, parsed) in izip!(nets0, nets1, batch, compiler) {
        threads.push(std::thread::spawn(move || {
            let witness_extension = BatchedRep3WitnessExtension::new(
                &net0,
                &net1,
                &parsed,
                VMConfig::default(),
                batch_size,
            )
            .unwrap();
            let input = input
                .into_iter()
                .map(|(name, value)| {
                    (
                        name,
                        BatchedRep3VmType::<ark_bn254::Fr>::try_from(value).unwrap(),
                    )
                })
                .collect();
            witness_extension
                .run(input, num_public_inputs)
                .unwrap()
                .into_shared_witness()
                .unbatch()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();

    assert_eq!(result3.len(), batch_size);
    assert_eq!(result2.len(), batch_size);
    assert_eq!(result1.len(), batch_size);
    for (result1, result2, result3) in izip!(result1, result2, result3) {
        let is_witness = test_utils::combine_field_elements_for_vm(result1, result2, result3);
        assert_eq!(is_witness, should_witness);
    }

    Ok(())
}
