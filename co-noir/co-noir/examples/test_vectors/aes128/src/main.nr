fn main(inputs: [u8; 4], iv: [u8; 16], key: [u8; 16]) -> pub [u8; 16] {
    std::aes128::aes128_encrypt(inputs, iv, key)
}
