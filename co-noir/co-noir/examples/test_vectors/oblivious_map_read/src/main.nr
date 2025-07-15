fn main(leaf: Field, key_bits: [Field; 40], hash_path: [Field; 40]) -> pub Field {
    oblivious_map::read(leaf, key_bits, hash_path)
}
