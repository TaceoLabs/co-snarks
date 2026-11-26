//! Tests that the witness generation only opens the public inputs declared by the circuit, independent of the provided inputs.

use ark_bn254::Fr;
use co_circom::{
    Bn254, CoCircomCompiler, CoCircomCompilerParsed, CompilerConfig, Input, Rep3SharedInput,
    Rep3SharedWitness, SimplificationLevel, VMConfig,
};
use co_circom_types::Rep3InputType;
use mpc_core::protocols::rep3;
use mpc_net::local::LocalNetwork;

/// `a`, `b` and `c` are arrays of size 3, where `b` and `c` are public. The circuit has no outputs.
fn circuit() -> CoCircomCompilerParsed<Fr> {
    let path = format!(
        "{}/examples/groth16/test_vectors/sum_arrays/circuit.circom",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut config = CompilerConfig::new();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    CoCircomCompiler::<Bn254>::parse(path, config).unwrap()
}

fn input_shares(circuit: &CoCircomCompilerParsed<Fr>) -> [Rep3SharedInput<Fr>; 3] {
    let input: Input = serde_json::from_str(
        r#"{"a": ["1", "2", "3"], "b": ["4", "5", "6"], "c": ["7", "8", "9"]}"#,
    )
    .unwrap();
    co_circom::split_input(input, circuit.public_inputs()).unwrap()
}

/// The constant 1 followed by the public inputs `b` and `c`
fn expected_public_inputs() -> Vec<Fr> {
    [1u64, 4, 5, 6, 7, 8, 9].into_iter().map(Fr::from).collect()
}

fn generate_witness(
    circuit: &CoCircomCompilerParsed<Fr>,
    inputs: [Rep3SharedInput<Fr>; 3],
) -> Vec<eyre::Result<Rep3SharedWitness<Fr>>> {
    let nets = LocalNetwork::new_3_parties();
    std::thread::scope(|s| {
        let handles = nets
            .into_iter()
            .zip(inputs)
            .map(|(net, input)| {
                s.spawn(move || {
                    co_circom::generate_witness_rep3(circuit, input, VMConfig::default(), &net)
                })
            })
            .collect::<Vec<_>>();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn assert_all_fail_with(results: Vec<eyre::Result<Rep3SharedWitness<Fr>>>, message: &str) {
    for result in results {
        let err = format!("{:?}", result.expect_err("witness generation must fail"));
        assert!(err.contains(message), "unexpected error: {err}");
    }
}

#[test]
fn opens_the_public_inputs_of_the_circuit() {
    let circuit = circuit();
    assert_eq!(circuit.num_public_input_signals(), 6);
    let inputs = input_shares(&circuit);
    for result in generate_witness(&circuit, inputs) {
        let witness = result.unwrap();
        assert_eq!(witness.public_inputs, expected_public_inputs());
    }
}

#[test]
fn additional_public_inputs_are_rejected() {
    let circuit = circuit();
    let mut inputs = input_shares(&circuit);
    // Before, each additional public entry caused one more signal of the witness to be opened
    for input in inputs.iter_mut() {
        for i in 0..3 {
            input.insert(format!("junk[{i}]"), Rep3InputType::Public(Fr::from(0u64)));
        }
    }
    assert_all_fail_with(
        generate_witness(&circuit, inputs),
        "not inputs of the circuit",
    );
}

#[test]
fn private_input_provided_as_public_value_opens_nothing_else() {
    let circuit = circuit();
    let mut inputs = input_shares(&circuit);
    for input in inputs.iter_mut() {
        for i in 0..3 {
            let value = Rep3InputType::Public(Fr::from(i + 1));
            assert!(input.insert(format!("a[{i}]"), value).is_some());
        }
    }
    let num_witness = generate_witness(&circuit, input_shares(&circuit))[0]
        .as_ref()
        .unwrap()
        .witness
        .len();
    for result in generate_witness(&circuit, inputs) {
        let witness = result.unwrap();
        assert_eq!(witness.public_inputs, expected_public_inputs());
        assert_eq!(witness.witness.len(), num_witness);
    }
}

#[test]
fn public_input_provided_as_share_is_rejected() {
    let circuit = circuit();
    let mut inputs = input_shares(&circuit);
    let shares = rep3::share_field_element(Fr::from(4u64), &mut rand::thread_rng());
    for (input, share) in inputs.iter_mut().zip(shares) {
        assert!(
            input
                .insert("b[0]".to_string(), Rep3InputType::Shared(share))
                .is_some()
        );
    }
    assert_all_fail_with(
        generate_witness(&circuit, inputs),
        "is a public input of the circuit",
    );
}
