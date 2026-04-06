//! SPDZ Gadgets — higher-level protocols built on core arithmetic.
//!
//! Currently implements:
//! - Poseidon2 permutation (mask-and-evaluate S-box technique)

pub mod aes;
pub mod bits;
pub mod blake;
pub mod ec;
pub mod parallel_prefix;
pub mod poseidon2;
pub mod yao;
pub mod yao2pc;
