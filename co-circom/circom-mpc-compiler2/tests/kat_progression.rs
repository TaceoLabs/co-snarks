mod common;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::program::VMConfig;
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn get_public_inputs_works() {
    let config = circom_mpc_compiler2::CompilerConfig::default();
    let inputs = circom_mpc_compiler2::CoCircomCompiler::<ark_bn254::Bn254>::get_public_inputs(
        "../../test_vectors/WitnessExtension/tests/multiplier2.circom".to_owned(),
        config,
    )
    .unwrap();
    assert!(inputs.is_empty()); // multiplier2 has no public inputs
}

/// The milestone test for the whole `circom-mpc-compiler2` plan: a circom circuit
/// compiled all the way down to the register ISA and executed to a correct witness.
///
/// `multiplier2` (the closest circuit in `test_vectors/WitnessExtension/tests/`) has no
/// KAT directory and additionally calls `log(...)`, which isn't lowered yet; every
/// KAT-backed circuit under `test_vectors/WitnessExtension/kats/` uses loops,
/// conditionals, or subcomponents (out of scope until Tasks 3+). Per the plan's
/// sanctioned fallback for this task, this instead exercises a purpose-written minimal
/// circuit (`tests/circuits/mul2.circom`, no loops/branches/functions/subcomponents)
/// with hand-chosen inputs, checked both via `get_output` and against a hand-computed
/// full witness vector. Real KAT circuits take over task by task as their required
/// features (loops, branches, subcomponents, ...) land.
#[test]
fn mul2_straight_line_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program =
        Arc::new(CoCircomCompiler::<Bn254>::parse("tests/circuits/mul2.circom", config).unwrap());

    let inputs = BTreeMap::from([
        ("a".to_string(), Fr::from(6u64)),
        ("b".to_string(), Fr::from(7u64)),
    ]);
    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();

    assert_eq!(finalized.get_output("c"), Some(vec![Fr::from(42u64)]));

    let witness = finalized.into_shared_witness();
    // signal layout (hand-computed against the circuit source): [0] = 1 (constant),
    // [1] = c (output), [2] = a, [3] = b (private inputs — mul2 declares no public
    // inputs).
    assert_eq!(witness.public_inputs, vec![Fr::from(1u64), Fr::from(42u64)]);
    assert_eq!(witness.witness, vec![Fr::from(6u64), Fr::from(7u64)]);
}
