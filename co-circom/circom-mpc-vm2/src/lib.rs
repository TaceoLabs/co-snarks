#![warn(missing_docs)]
//! Register-based MPC-VM for the circom witness extension (successor of `circom-mpc-vm`).
//!
//! Programs are produced by `circom-mpc-compiler2` (or hand-assembled for tests) and
//! executed by a [`WitnessExtension`](api::WitnessExtension) instantiated with a driver
//! implementing [`VmDriver`](driver::VmDriver).
pub mod api;
pub mod driver;
pub mod drivers;
#[doc(hidden)]
pub mod exec;
pub mod isa;
pub mod program;
