use ark_ff::PrimeField;
use mpc_core::traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol};

pub mod compiler;
pub mod mpc_vm;
mod op_codes;
pub mod plain_vm;
mod stack;
