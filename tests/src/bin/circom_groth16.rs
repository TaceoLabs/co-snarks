use circom_mpc_vm::mpc_vm::{BatchedRep3WitnessExtension, VMConfig};
use co_circom_types::{BatchedSharedInput, SharedInput};

use ark_bn254::Bn254;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use itertools::izip;
use mpc_core::protocols::rep3::{self, conversion::A2BType};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use std::{fs::File, io::BufReader};
use tests::test_utils::{self, spawn_pool};

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
    let chacha_circuit =
        "/home/fnieddu/repos/co-snarks-mpc-net/csn-dev-setup/circuits/chacha20/circuit.circom";

    let input =
        "/home/fnieddu/repos/co-snarks-mpc-net/csn-dev-setup/circuits/chacha20/input.0.json";
    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

    let public_inputs =
        CoCircomCompiler::<Bn254>::get_public_inputs(&chacha_circuit, compiler_config).unwrap();

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();

    let batch_size = 2;
    let mut rng = thread_rng();
    let input_file = BufReader::new(File::open(input)?);
    let input_json: serde_json::Map<String, serde_json::Value> =
        serde_json::from_reader(input_file).unwrap();
    let mut plain_input = SharedInput::default();
    let mut shared_input_0 = SharedInput::default();
    let mut shared_input_1 = SharedInput::default();
    let mut shared_input_2 = SharedInput::default();
    for (k, v) in input_json {
        let parsed_vals = if v.is_array() {
            test_utils::parse_array::<ark_bn254::Fr>(&v).unwrap()
        } else {
            vec![test_utils::parse_field::<ark_bn254::Fr>(&v).unwrap()]
        };
        if public_inputs.contains(&k) {
            plain_input.add_public_input(k.clone(), parsed_vals.clone());
            shared_input_0.add_public_input(k.clone(), parsed_vals.clone());
            shared_input_1.add_public_input(k.clone(), parsed_vals.clone());
            shared_input_2.add_public_input(k.clone(), parsed_vals);
        } else {
            let [share0, share1, share2] = rep3::share_field_elements(&parsed_vals, &mut rng);
            plain_input.add_shared_input(k.clone(), parsed_vals);
            shared_input_0.add_shared_input(k.clone(), share0);
            shared_input_1.add_shared_input(k.clone(), share1);
            shared_input_2.add_shared_input(k.clone(), share2);
        }
    }
    let batch = [
        vec![shared_input_0; batch_size],
        vec![shared_input_1; batch_size],
        vec![shared_input_2; batch_size],
    ];

    let should_plain_witness = parsed
        .clone()
        .to_plain_vm(VMConfig::default())
        .run(plain_input.clone())?
        .into_shared_witness();

    let mut should_witness = vec![];
    should_witness.extend(should_plain_witness.public_inputs);
    should_witness.extend(should_plain_witness.witness);

    let compiler = [parsed.clone(), parsed.clone(), parsed];

    tracing::info!("starting threads");
    let mut threads = vec![];
    for (net0, net1, input, parsed) in izip!(nets0, nets1, batch, compiler) {
        threads.push(spawn_pool(move || {
            let mut vm_config = VMConfig::new();
            vm_config.a2b_type = A2BType::Direct;
            let vm = BatchedRep3WitnessExtension::new(&net0, &net1, &parsed, vm_config, batch_size)
                .unwrap();
            vm.run(BatchedSharedInput::try_from(input).unwrap())
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
