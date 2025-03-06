fn main(x: [u8; 4]) -> pub [u8; 32] {
    std::hash::blake2s(x)
}
