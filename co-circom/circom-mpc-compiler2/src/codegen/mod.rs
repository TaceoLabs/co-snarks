//! Lowering from the circom-compiler [`CircomCircuit`] representation to a
//! `circom-mpc-vm2` [`CompiledProgram`].
//!
//! This module is a stub in this task; the real lowering (register allocation, expression
//! lowering, statement lowering, ...) lands in later tasks.
use crate::CompilerConfig;
use crate::frontend::OutputMapping;
use ark_ff::PrimeField;
use circom_compiler::compiler_interface::Circuit as CircomCircuit;
use circom_mpc_vm2::program::CompiledProgram;
use eyre::{Result, bail};

/// Lowers a parsed and constraint-generated [`CircomCircuit`] into a [`CompiledProgram`]
/// runnable by `circom-mpc-vm2`.
///
/// Not yet implemented; always returns an error.
pub(crate) fn compile<F: PrimeField>(
    _circuit: CircomCircuit,
    _output_mapping: OutputMapping,
    _public_inputs: Vec<String>,
    _config: &CompilerConfig,
) -> Result<CompiledProgram<F>> {
    bail!("codegen not implemented")
}
