mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::program::VMConfig;
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn run_with_named_inputs() {
    let program = Arc::new(common::multiplier_program());
    let wex = PlainWitnessExtension::new_plain(program, VMConfig::default());
    let inputs = BTreeMap::from([
        ("a".to_string(), Fr::from(6u64)),
        ("b".to_string(), Fr::from(7u64)),
    ]);
    let finalized = wex.run(inputs, 0).expect("run");
    assert_eq!(finalized.get_output("out"), Some(vec![Fr::from(42u64)]));
    let shared_witness = finalized.into_shared_witness();
    assert_eq!(
        shared_witness.public_inputs,
        vec![Fr::from(1u64), Fr::from(42u64)]
    );
    assert_eq!(shared_witness.witness, vec![Fr::from(6u64), Fr::from(7u64)]);
}

#[test]
fn run_with_flat_inputs() {
    let program = Arc::new(common::multiplier_program());
    let wex = PlainWitnessExtension::new_plain(program, VMConfig::default());
    let finalized = wex
        .run_with_flat(vec![Fr::from(6u64), Fr::from(7u64)], 0)
        .expect("run_with_flat");
    assert_eq!(finalized.get_output("out"), Some(vec![Fr::from(42u64)]));
    let shared_witness = finalized.into_shared_witness();
    assert_eq!(
        shared_witness.public_inputs,
        vec![Fr::from(1u64), Fr::from(42u64)]
    );
    assert_eq!(shared_witness.witness, vec![Fr::from(6u64), Fr::from(7u64)]);
}

#[test]
fn missing_input_name_errors() {
    let program = Arc::new(common::multiplier_program());
    let wex = PlainWitnessExtension::new_plain(program, VMConfig::default());
    let inputs = BTreeMap::from([("a".to_string(), Fr::from(6u64))]);
    let err = match wex.run(inputs, 0) {
        Ok(_) => panic!("missing \"b\" must error"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains('b'),
        "error should name the missing signal \"b\": {err}"
    );
}

#[test]
fn array_input_names() {
    let program = Arc::new(common::sum_program(3));
    let wex = PlainWitnessExtension::new_plain(program, VMConfig::default());
    let inputs = BTreeMap::from([
        ("in[0]".to_string(), Fr::from(1u64)),
        ("in[1]".to_string(), Fr::from(2u64)),
        ("in[2]".to_string(), Fr::from(3u64)),
    ]);
    let finalized = wex.run(inputs, 0).expect("run");
    assert_eq!(finalized.get_output("out"), Some(vec![Fr::from(6u64)]));
}
