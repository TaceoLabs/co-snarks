//! Utilities for generating, parsing and executing binary and arithmetic circuits

use thiserror::Error;
mod bristol;
pub use bristol::{BristolFashionCircuit, BristolFashionEvaluator, LeveledBristolFashionCircuit};

/// Errors that happen during parsing of circuits
#[derive(Error, Debug)]
pub enum CircuitBuilderError {
    /// An IO-Error has occurred
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    /// An Error has occurred during parsing
    #[error("Error during Parsing: {0}")]
    ParseError(String),
    /// The built/parsed circuit is invalid
    #[error("{0}")]
    InvalidCircuit(String),
}

/// Errors that happen during execution of circuits
#[derive(Error, Debug)]
pub enum CircuitExecutionError {
    /// An IO-Error has occurred
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    /// The provided input was not the correct format for the circuit
    #[error("{0}")]
    InvalidInput(String),
}
