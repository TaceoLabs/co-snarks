#![warn(missing_docs)]
//! This crate defines the [CoBrilligVM].
//!
//! The VM computes unconstrained functions for the ACVM witness extension.

mod blackbox;
mod brillig_vm;
mod field_ops;
mod int_ops;
pub(crate) mod memory;
pub mod mpc;

pub use brillig_vm::CoBrilligResult;
pub use brillig_vm::CoBrilligVM;
