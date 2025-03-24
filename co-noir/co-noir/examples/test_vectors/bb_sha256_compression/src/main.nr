fn main(input: [u32; 16], state: [u32; 8]) -> pub [u32; 8] {
    std::hash::sha256_compression(input, state)
}
