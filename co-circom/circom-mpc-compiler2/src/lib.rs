#![warn(missing_docs)]
//! This crate defines a [`Compiler`](CoCircomCompiler), which compiles `.circom` files into
//! bytecode for the register-based `circom-mpc-vm2` MPC-VM.
//!
//! This is the successor of [`circom-mpc-compiler`](https://docs.rs/circom-mpc-compiler),
//! targeting `circom-mpc-vm2`'s three-address instruction set
//! ([`circom_mpc_vm2::isa::Instr`]) instead of the old stack-based bytecode.
//!
//! The compiler is generic over a [`Pairing`](https://docs.rs/ark-ec/latest/ark_ec/pairing/trait.Pairing.html).
//! Currently, we support the curves `bn254` and `bls12-381`.
//!
//! The [`CoCircomCompiler`] provides two methods for interacting with circom files:
//!     * [`CoCircomCompiler::parse`] - to parse and compile a circuit
//!     * [`CoCircomCompiler::get_public_inputs`] - to obtain the name of the public inputs of the circuit
//!
//! To configure the compiler, have a look at [`CompilerConfig`].
use ark_ec::pairing::Pairing;
use circom_mpc_vm2::program::CompiledProgram;
use circom_types::traits::CircomArkworksPairingBridge;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, path::PathBuf};

mod codegen;
pub mod frontend;

/// The simplification level applied during constraint generation
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum SimplificationLevel {
    /// No simplification
    O0,
    /// Only applies signal to signal and signal to constant simplification
    /// The default value since circom 2.2.0
    #[default]
    O1,
    /// Full constraint simplification (applied for n rounds)
    O2(usize),
}

/// Controls loop unrolling during codegen (Task 2+). Not yet consumed by this task.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct UnrollConfig {
    /// Maximum number of statically-known loop iterations to unroll.
    ///
    /// `0` disables unrolling; `usize::MAX` forces unrolling wherever statically possible.
    #[serde(default = "default_unroll_threshold")]
    pub threshold: usize,
}

fn default_unroll_threshold() -> usize {
    4096
}

impl Default for UnrollConfig {
    fn default() -> Self {
        Self {
            threshold: default_unroll_threshold(),
        }
    }
}

/// The mpc-compiler configuration
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct CompilerConfig {
    /// The circom version
    #[serde(default = "default_version")]
    pub version: String,
    /// Allow leaking of secret values in loops (not used atm)
    #[serde(default)]
    pub allow_leaky_loops: bool,
    /// The path to Circom library files
    #[serde(default)]
    pub link_library: Vec<PathBuf>,
    /// The optimization flag passed to the compiler
    #[serde(default)]
    pub simplification: SimplificationLevel,
    /// Shows logs during compilation
    #[serde(default)]
    pub verbose: bool,
    /// Does an additional check over the constraints produced
    #[serde(default)]
    pub inspect: bool,
    /// Adds additional opcodes for debugging.
    #[serde(default = "default_true")]
    pub debug: bool,
    /// Loop-unrolling configuration used by codegen.
    #[serde(default)]
    pub unroll: UnrollConfig,
}

fn default_true() -> bool {
    true
}

fn default_version() -> String {
    "2.2.2".to_owned()
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            link_library: vec![],
            allow_leaky_loops: false,
            simplification: SimplificationLevel::default(),
            verbose: false,
            inspect: false,
            debug: true,
            unroll: UnrollConfig::default(),
        }
    }
}

impl CompilerConfig {
    /// Creates a new instance of the compiler config with default values. Uses `debug` optimization level.
    ///
    /// Check [`Self::release`] for a release config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new instance of the compiler config optimized for release.
    pub fn release() -> Self {
        Self {
            allow_leaky_loops: false,
            simplification: SimplificationLevel::O2(usize::MAX),
            debug: false,
            ..Default::default()
        }
    }
}

/// The compiler. Can only be instantiated internally. Have a look at these two methods for usage:
///     * [`CoCircomCompiler::parse`]
///     * [`CoCircomCompiler::get_public_inputs`]
pub struct CoCircomCompiler<P: Pairing> {
    file: PathBuf,
    config: CompilerConfig,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> CoCircomCompiler<P>
where
    P: CircomArkworksPairingBridge,
{
    // only internally to hold the state
    fn new<Pth>(file: Pth, config: CompilerConfig) -> Self
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        tracing::debug!("creating compiler for circuit {file:?} with config: {config:?}");
        Self {
            file: PathBuf::from(file),
            config,
            phantom_data: PhantomData,
        }
    }

    /// Returns a `Result<Vec<String>>`
    /// containing all public inputs from the provided .circom file.
    ///
    /// This method is useful when secret-sharing the input.
    ///
    /// # Params
    /// * **file** - a `String` denoting the path to circom file.
    /// * **config** - the [CompilerConfig]
    /// # Returns
    ///
    /// Returns a `Result` where:
    ///
    /// - `Ok(inputs)` contains a vector of public inputs as strings.
    /// - `Err(err)` indicates an error occurred during parsing or compilation.
    pub fn get_public_inputs<Pth>(file: Pth, config: CompilerConfig) -> Result<Vec<String>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        Self::new(file, config).get_public_inputs_inner()
    }

    /// Parses and compiles the circuit provided by `file`, returning a [`CompiledProgram`]
    /// ready to be run by `circom-mpc-vm2`.
    ///
    /// # Params
    /// * **file** - a `String` denoting the path to circom file.
    /// * **config** - the [CompilerConfig]
    ///
    /// # Returns
    ///
    /// Returns a `Result` where:
    ///
    /// - `Ok(program)` contains the compiled program.
    /// - `Err(err)` indicates an error occurred during parsing, compilation, or codegen.
    pub fn parse<Pth>(file: Pth, config: CompilerConfig) -> Result<CompiledProgram<P::ScalarField>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        Self::new(file, config).parse_inner()
    }

    fn get_public_inputs_inner(self) -> Result<Vec<String>> {
        let program_archive = frontend::get_program_archive::<P>(&self.file, &self.config)?;
        tracing::debug!("get public inputs: {:?}", program_archive.public_inputs);
        Ok(program_archive.public_inputs)
    }

    fn parse_inner(self) -> Result<CompiledProgram<P::ScalarField>> {
        tracing::debug!("compiler starts parsing..");
        let program_archive = frontend::get_program_archive::<P>(&self.file, &self.config)?;
        let public_inputs = program_archive.public_inputs.clone();
        let (circuit, output_mapping) = frontend::build::<P>(program_archive, &self.config)?;
        codegen::compile(circuit, output_mapping, public_inputs, &self.config)
    }
}
