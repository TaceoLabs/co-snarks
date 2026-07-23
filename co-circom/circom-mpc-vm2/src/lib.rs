#![warn(missing_docs)]
//! Register-based MPC-VM for the circom witness extension (successor of `circom-mpc-vm`).
//!
//! Programs are produced by `circom-mpc-compiler2` (or hand-assembled for tests) and
//! executed by a [`WitnessExtension`](api::WitnessExtension) instantiated with a driver
//! implementing [`VmDriver`](driver::VmDriver).
pub mod isa;
pub mod program;
