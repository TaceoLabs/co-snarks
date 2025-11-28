//! Utilities for generating, parsing and executing binary and arithmetic circuits

use thiserror::Error;
mod bristol;
pub use bristol::{BristolFashionCircuit, BristolFashionEvaluator, LeveledBristolFashionCircuit};

/// Errors that happen during parsing of circuits
#[derive(Error, Debug)]
pub enum CircuitBuilderError {
    /// An IO-Error has occured
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    /// An Error has occured during parsing
    #[error("Error during Parsing: {0}")]
    ParseError(String),
    /// The built/parsed circuit is invalid
    #[error("{0}")]
    InvalidCircuit(String),
}

/// Errors that happen during execution of circuits
#[derive(Error, Debug)]
pub enum CircuitExecutionError {
    /// An unspecified Error has occured
    #[error("{0}")]
    GenericError(Box<dyn std::error::Error>),
    /// An IO-Error has occured
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    /// The provided input was not in the correct format for the circuit
    #[error("{0}")]
    InvalidInput(String),
}

impl From<CircuitExecutionError> for fancy_garbling::errors::FancyError {
    fn from(err: CircuitExecutionError) -> Self {
        match err {
            CircuitExecutionError::GenericError(e) => {
                fancy_garbling::errors::FancyError::InvalidArg(e.to_string())
            }
            CircuitExecutionError::IoError(e) => {
                fancy_garbling::errors::FancyError::InvalidArg(e.to_string())
            }
            CircuitExecutionError::InvalidInput(msg) => {
                fancy_garbling::errors::FancyError::InvalidArg(msg)
            }
        }
    }
}
