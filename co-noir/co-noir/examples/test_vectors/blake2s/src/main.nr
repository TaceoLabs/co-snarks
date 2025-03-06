fn main(x: [u8; 4]) -> pub [u8; 32] {
    // let x = [163, 117, 178, 149]; // some random bytes
    std::hash::blake2s(x)
}
