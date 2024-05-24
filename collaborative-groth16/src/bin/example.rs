use ark_bn254::Bn254;
use collaborative_groth16::vm::compiler::CompilerBuilder;

use std::str::FromStr;
fn main() {
    let file =
        "/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/poseidon_hasher.circom";
    let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
        .link_library("/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/libs/");
    let result = builder
        .build()
        .parse()
        .unwrap()
        .run(vec![ark_bn254::Fr::from_str("5").unwrap()]);
    if result[0] == ark_bn254::Fr::from_str("0").unwrap() {
        println!("0");
    } else {
        println!("result: {}", result[0]);
    }
}
