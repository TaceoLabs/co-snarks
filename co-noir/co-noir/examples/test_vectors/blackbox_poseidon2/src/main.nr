fn main(input: [Field; 4]) -> pub Field {
    std::hash::poseidon2_permutation::<4>(input)[0]
}
