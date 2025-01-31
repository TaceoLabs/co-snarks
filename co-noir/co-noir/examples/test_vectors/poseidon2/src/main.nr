use dep::poseidon;

fn main(plains: [Field; 4]) -> pub Field {
    poseidon::bn254::hash_4(plains)
}
