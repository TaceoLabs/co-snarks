use dep::sha256;

fn main(plains: [u8; 8]) -> pub [u8; 32] {
    sha256::sha256_var(plains, 8)
}
