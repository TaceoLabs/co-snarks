// Note: there is some bug in bb (or noir?) that causes a failure message in bb for more than 1024 inputs (https://github.com/AztecProtocol/barretenberg/issues/1289)

fn main(x: [u8; 4]) -> pub [u8; 32] {
    std::hash::blake3(x)
}
