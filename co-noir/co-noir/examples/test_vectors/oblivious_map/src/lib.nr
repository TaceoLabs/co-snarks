pub(crate) mod merkle;

// Returns the Merkle root
pub fn read<let N: u32>(leaf: Field, index_bits: [Field; N], hash_path: [Field; N]) -> Field {
    merkle::compute_merkle_root(leaf, index_bits, hash_path)
}

// Returns the old Merkle root as well as the new Merkle root
pub fn write<let N: u32>(
    old_leaf: Field,
    new_leaf: Field,
    index_bits: [Field; N],
    hash_path: [Field; N],
) -> (Field, Field) {
    let old_root = merkle::compute_merkle_root(old_leaf, index_bits, hash_path);
    let new_root = merkle::compute_merkle_root(new_leaf, index_bits, hash_path);
    (old_root, new_root)
}

// Returns the old Merkle root as well as the new Merkle root
pub fn delete<let N: u32>(
    old_leaf: Field,
    index_bits: [Field; N],
    hash_path: [Field; N],
) -> (Field, Field) {
    let deleted_leaf = 0xDEADBEEF;
    write(old_leaf, deleted_leaf, index_bits, hash_path)
}
