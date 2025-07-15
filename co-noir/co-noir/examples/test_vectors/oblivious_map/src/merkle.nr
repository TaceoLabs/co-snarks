// Hashing as a compression function with t=2 and feed-forward
pub(crate) fn hash(left: Field, right: Field) -> Field {
    poseidon2::bn254::hash_2([left, right]) + left
}

pub(crate) fn compute_merkle_root<let N: u32>(
    leaf: Field,
    index_bits: [Field; N],
    hash_path: [Field; N],
) -> Field {
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i];
        let path_hash = hash_path[i];

        // Constrain the input bits to be either 0 or 1
        let path_bit_is_bit = path_bit * (path_bit - 1);
        assert(path_bit_is_bit == 0);

        // CMUX the hash pathpath
        let mul = path_bit * (path_hash - current);
        let hash_left = mul + current;
        let hash_right = path_hash - mul;

        current = hash(hash_left, hash_right);
    }
    current
}
