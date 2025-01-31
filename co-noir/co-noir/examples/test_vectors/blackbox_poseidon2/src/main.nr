fn main(input: [Field; 4]) -> pub Field {
    std::hash::poseidon2_permutation(input, 4)[0]
}
