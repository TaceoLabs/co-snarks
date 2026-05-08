use poseidon::bn254::permutation;

fn main(plains: [Field; 4]) -> pub Field {
    permutation::t4(plains)[0]
}
