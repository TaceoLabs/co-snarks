use ark_bn254::Bn254;
use collaborative_groth16::vm::compiler::CompilerBuilder;
use num_traits::Zero;
use std::str::FromStr;
fn main() {
    let file = "/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/eddsa_verify.circom";
    let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
        .link_library("/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/libs/");
    let result = builder.build().parse().unwrap().run(vec![
        ark_bn254::Fr::from_str("0").unwrap(),
        ark_bn254::Fr::from_str("1").unwrap(),
        ark_bn254::Fr::from_str("2").unwrap(),
        ark_bn254::Fr::from_str("3").unwrap(),
        ark_bn254::Fr::from_str("4").unwrap(),
        ark_bn254::Fr::from_str("5").unwrap(),
        ark_bn254::Fr::from_str("6").unwrap(),
    ]);

    assert_eq!(
        result,
        vec![
            ark_bn254::Fr::from_str(
                "2763488322167937039616325905516046217694264098671987087929565332380420898366"
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "2925416330664408197684231514117296356864480091858857935805219172378067397648"
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "15305195750036305661220525648961313310481046260814497672243197092298550508693"
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "7063342465777781127300100846030462898353260585544312659291125182526882563299"
            )
            .unwrap(),
        ]
    );
    println!("IT WORKED");
}
