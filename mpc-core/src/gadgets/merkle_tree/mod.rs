//! MerkleTree
//!
//! This module contains implementations to create Merkle trees with Poseidon2.

pub(crate) mod plain;
#[cfg(feature = "rep3")]
pub(crate) mod rep3;
#[cfg(feature = "shamir")]
pub(crate) mod shamir;
