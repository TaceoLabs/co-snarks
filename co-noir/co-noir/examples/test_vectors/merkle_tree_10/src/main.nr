// use dep::poseidon;
use std::hash::poseidon;

fn main(mut leaves: [Field; 1024]) -> pub Field {
    let mut depth = 10;

    let mut len = leaves.len();
    for _ in 0..depth {
        for k in 0..len {
            if k % 2 == 0 {
                let parent = hash(leaves[k], leaves[k + 1]);
                leaves[k / 2] = parent;
            }
        }
        len = len / 2;
    }

    leaves[0]
}

fn hash(left: Field, right: Field) -> Field {
    poseidon::bn254::hash_2([left, right])
}
