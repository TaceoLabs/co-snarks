use ark_ff::PrimeField;
use mpc_core::protocols::shamir::{network::ShamirNetwork, ShamirProtocol};

pub struct ShamirGroth16Driver<F: PrimeField, N: ShamirNetwork> {
    protocol: ShamirProtocol<F, N>,
}
