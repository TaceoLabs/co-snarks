fn main(leaf: Field, key_bits: [Field; 2], hash_path: [Field; 2]) -> pub Field {
    oblivious_map::read(leaf, key_bits, hash_path)
}
