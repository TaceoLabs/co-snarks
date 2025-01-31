//! Poseidon2
//!
//! This module contains implementations of the Poseidon2 permutation.

pub(crate) mod poseidon2_bn254;
pub(crate) mod poseidon2_params;
pub(crate) mod poseidon2_permutation;

pub use poseidon2_bn254::POSEIDON2_BN254_T4_PARAMS;
pub use poseidon2_params::Poseidon2Params;
pub use poseidon2_permutation::Poseidon2;
