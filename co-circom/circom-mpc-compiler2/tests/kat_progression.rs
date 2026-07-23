mod common;

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
