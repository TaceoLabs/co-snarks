use ark_bn254::Bn254;
use collaborative_groth16::vm::compiler::CompilerBuilder;
use std::str::FromStr;

fn main() {
    //let file = "/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/eddsa_verify.circom";
    let file =
        "/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/poseidon_hasher.circom";
    let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
        .link_library("/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/libs/");
    let result = builder.build().parse().unwrap().run(vec![
        ark_bn254::Fr::from_str("0").unwrap(),
        ark_bn254::Fr::from_str("1").unwrap(),
        //  ark_bn254::Fr::from_str("1").unwrap(),
        //  ark_bn254::Fr::from_str("2").unwrap(),
        //  ark_bn254::Fr::from_str("3").unwrap(),
        //  ark_bn254::Fr::from_str("4").unwrap(),
        //  ark_bn254::Fr::from_str("5").unwrap(),
        //  ark_bn254::Fr::from_str("6").unwrap(),
    ]);
    println!("is    :  {}", result[0]);
    println!(
        "should:  {}",
        "19065150524771031435284970883882288895168425523179566388456001105768498065277"
    );
}
