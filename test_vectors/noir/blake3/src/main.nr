fn main(x: [u8; 2048]) -> pub [u8; 32] {
    // let x = [163, 117, 178, 149]; // some random bytes
    std::hash::blake3(x)
}
