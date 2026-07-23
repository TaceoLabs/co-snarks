//! Shared test helpers for the `circom-mpc-compiler2` integration tests.
//!
//! These mirror `tests/tests/circom/witness_extension_tests/plain_vm.rs` (the old
//! crate's KAT harness): compile a circuit from `test_vectors/WitnessExtension/tests/`,
//! run every `kats/<name>/{input<i>.json, witness<i>.wtns}` pair through the plain VM,
//! and assert the resulting witness matches snarkjs's ground truth exactly.
#![allow(dead_code)]

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm2::program::VMConfig;
use circom_types::Witness;
use std::{fs::File, str::FromStr};

/// Compiles `test_vectors/WitnessExtension/tests/<name>.circom` with the crate's own
/// library path and `O2` simplification (matching the old KAT harness).
pub fn compile(name: &str, config: CompilerConfig) -> circom_mpc_vm2::program::CompiledProgram<Fr> {
    let mut config = CompilerConfig {
        simplification: circom_mpc_compiler2::SimplificationLevel::O2(usize::MAX),
        ..config
    };
    config
        .link_library
        .push("../../test_vectors/WitnessExtension/tests/libs/".into());
    CoCircomCompiler::<Bn254>::parse(
        format!("../../test_vectors/WitnessExtension/tests/{name}.circom"),
        config,
    )
    .unwrap()
}

/// Parses a decimal field element, honoring a leading `-` (snarkjs's KAT JSON encodes
/// negative field elements this way instead of the field's own modular representation).
pub fn read_field_element(s: &str) -> Fr {
    if let Some(stripped) = s.strip_prefix('-') {
        -Fr::from_str(stripped).unwrap()
    } else {
        Fr::from_str(s).unwrap()
    }
}

/// Runs every KAT set for `name` and asserts witness equality with the `.wtns` ground
/// truth. Panics if not a single KAT was found (a silently-empty test is worse than no
/// test).
pub fn assert_kats(name: &str, config: CompilerConfig) {
    let program = std::sync::Arc::new(compile(name, config));
    let mut i = 0;
    loop {
        let wtns_path = format!("../../test_vectors/WitnessExtension/kats/{name}/witness{i}.wtns");
        if std::fs::metadata(&wtns_path).is_err() {
            break;
        }
        let should = Witness::<Fr>::from_reader(File::open(wtns_path).unwrap()).unwrap();
        let json: serde_json::Value = serde_json::from_reader(
            File::open(format!(
                "../../test_vectors/WitnessExtension/kats/{name}/input{i}.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let input: Vec<Fr> = json
            .get("in")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|s| read_field_element(s.as_str().unwrap()))
            .collect();
        let mut w = circom_mpc_vm2::api::PlainWitnessExtension::new_plain(
            program.clone(),
            VMConfig::default(),
        )
        .run_with_flat(input, 0)
        .unwrap()
        .into_shared_witness();
        w.public_inputs.extend(w.witness);
        assert_eq!(w.public_inputs, should.values, "{name} witness{i} mismatch");
        i += 1;
    }
    assert!(i > 0, "no KATs found for {name}");
}
