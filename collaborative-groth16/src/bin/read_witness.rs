use std::fs::File;

use circom_types::groth16::witness::Witness;

fn main() {
    let witness = File::open("/home/fnieddu/repos/collaborative-circom/test_vectors/circuits/delete/poseidon_hasher_js/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
    for ele in witness.values.iter().take(10) {
        println!("{ele}");
    }
}
