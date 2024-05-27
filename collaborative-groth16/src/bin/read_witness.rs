use std::fs::File;

use circom_types::groth16::witness::Witness;
use num_traits::Zero;
fn main() {
    let witness = File::open("/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/delete/test_js/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
    for ele in witness.values.iter().take(10) {
        if *ele == ark_bn254::Fr::zero() {
            println!("0");
        } else {
            println!("{ele}");
        }
    }
}
