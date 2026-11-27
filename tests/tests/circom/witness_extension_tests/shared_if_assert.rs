//! Asserts inside an `if` with a secret-shared condition must only fail if their branch is taken.

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use circom_mpc_vm::{
    mpc_vm::{Rep3WitnessExtension, VMConfig},
    types::CoCircomCompilerParsed,
    Rep3VmType,
};
use itertools::izip;
use mpc_core::protocols::rep3;
use mpc_net::local::LocalNetwork;
use tests::test_utils;

const CIRCUIT: &str = "../test_vectors/WitnessExtension/tests/shared_if_assert.circom";

fn circuit() -> CoCircomCompilerParsed<Fr> {
    // The default config has debug enabled, i.e., asserts are executed
    let mut config = CompilerConfig::default();
    assert!(config.debug);
    config.simplification = SimplificationLevel::O2(usize::MAX);
    CoCircomCompiler::<Bn254>::parse(CIRCUIT.to_owned(), config).unwrap()
}

fn to_fields(input: [u64; 3]) -> Vec<Fr> {
    input.into_iter().map(Fr::from).collect()
}

fn run_plain(input: [u64; 3]) -> eyre::Result<Vec<Fr>> {
    let witness = circuit()
        .to_plain_vm(VMConfig::default())
        .run_with_flat(to_fields(input))?
        .into_shared_witness();
    Ok([witness.public_inputs, witness.witness].concat())
}

/// Runs the witness extension with all inputs secret shared
fn run_rep3(input: [u64; 3]) -> eyre::Result<Vec<Fr>> {
    let shares = rep3::share_field_elements(&to_fields(input), &mut rand::thread_rng());
    let threads = izip!(LocalNetwork::new_3_parties(), shares)
        .map(|(net, input)| {
            std::thread::spawn(move || {
                let circuit = circuit();
                let witness = Rep3WitnessExtension::new(&net, &circuit, VMConfig::default())?
                    .run_with_flat(input.into_iter().map(Rep3VmType::Arithmetic).collect())?
                    .into_shared_witness();
                eyre::Ok(witness)
            })
        })
        .collect::<Vec<_>>();
    let mut results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Result<Vec<_>, _>>()?;
    let result3 = results.pop().unwrap();
    let result2 = results.pop().unwrap();
    let result1 = results.pop().unwrap();
    Ok(test_utils::combine_field_elements_for_vm(
        result1, result2, result3,
    ))
}

// The assert of the other branch fails, but that branch is not taken
#[test]
fn assert_in_untaken_branch_is_ignored() {
    // then-branch is taken, the assert of the else-branch (in[1] != in[2]) is false
    let input = [1, 5, 5];
    assert_eq!(run_rep3(input).unwrap(), run_plain(input).unwrap());
    // else-branch is taken, the assert in the function called in the then-branch (in[1] == in[2]) is false
    let input = [0, 5, 7];
    assert_eq!(run_rep3(input).unwrap(), run_plain(input).unwrap());
}

#[test]
fn assert_in_taken_branch_fails() {
    for input in [[1, 5, 7], [0, 5, 5]] {
        assert!(run_plain(input).is_err());
        let err = run_rep3(input).expect_err("the assertion must fail");
        assert!(
            format!("{err:?}").contains("Assertion failed"),
            "unexpected error: {err:?}"
        );
    }
}
