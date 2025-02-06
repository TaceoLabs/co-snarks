use dep::poseidon;
// use std::hash::poseidon;

fn main(leaf: Field, index: [bool; 3], hash_path: [Field; 3]) {
    let root = compute_merkle_root(leaf, index, hash_path);
    assert(root == 7112289017391032048158476630600402491846288115362201163571043993810608334152);
}

// Regular merkle tree means a append-only merkle tree (Explain why this is the only way to have privacy and alternatives if you don't want it)
// Currently we assume that it is a binary tree, so depth k implies a width of 2^k
// XXX: In the future we can add an arity parameter
// Returns the merkle root of the tree from the provided leaf, its hashpath, using a pedersen hash function.
pub fn compute_merkle_root<let N: u32>(
    leaf: Field,
    index_bits: [bool; N],
    hash_path: [Field; N],
) -> Field {
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i];
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = hash([hash_left, hash_right]);
    }
    current
}

fn hash(nodes: [Field; 2]) -> Field {
    poseidon::bn254::hash_2(nodes)
}
