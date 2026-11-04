//! # MPC Protocols
//!
//! Contains the implementations of the different MPC protocols. Currently, semi-honest 3-party replicated sharing (REP3) and semi-honest n-party Shamir secret sharing are implemented.

#[cfg(all(feature = "rep3", feature = "shamir"))]
pub mod bridges;
#[cfg(feature = "rep3")]
pub mod rep3;
#[cfg(feature = "rep3-ring")]
pub mod rep3_ring;
#[cfg(feature = "shamir")]
pub mod shamir;
