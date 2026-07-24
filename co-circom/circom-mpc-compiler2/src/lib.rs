#![warn(missing_docs)]
//! This crate defines a [`Compiler`](CoCircomCompiler), which compiles `.circom` files into
//! bytecode for the register-based `circom-mpc-vm2` MPC-VM.
//!
//! This is the successor of [`circom-mpc-compiler`](https://docs.rs/circom-mpc-compiler): the
//! two crates live side by side (`circom-mpc-compiler` is untouched and still the
//! production path), and `circom-mpc-compiler2` is the target of ongoing migration work.
//! Where the old crate lowers straight to `circom-mpc-vm`'s stack-based bytecode, this
//! crate targets `circom-mpc-vm2`'s three-address instruction set
//! ([`circom_mpc_vm2::isa::Instr`]) and hands back a [`CompiledProgram`] — the type
//! `circom-mpc-vm2` executes directly (see [`CoCircomCompiler::parse`] and
//! `circom-mpc-vm2`'s own crate docs for the execution half of the pipeline). Like the
//! circom compiler it wraps, this crate is licensed `GPL-3.0`; downstream code that only
//! depends on `circom-mpc-vm2` (i.e. runs already-compiled programs) is unaffected.
//!
//! The compiler is generic over a [`Pairing`](https://docs.rs/ark-ec/latest/ark_ec/pairing/trait.Pairing.html).
//! Currently, we support the curves `bn254` and `bls12-381`.
//!
//! The [`CoCircomCompiler`] provides two methods for interacting with circom files:
//!     * [`CoCircomCompiler::parse`] - to parse and compile a circuit
//!     * [`CoCircomCompiler::get_public_inputs`] - to obtain the name of the public inputs of the circuit
//!
//! To configure the compiler, have a look at [`CompilerConfig`].
//!
//! # Pipeline
//!
//! [`CoCircomCompiler::parse`] runs two stages, split across [`frontend`] and the
//! (private) `codegen` module:
//!
//! 1. **circom front half** ([`frontend`]): parsing, type checking, and constraint
//!    generation, almost verbatim from the old `circom-mpc-compiler`'s front half —
//!    everything up to (but not including) bytecode lowering. This runs the circom
//!    compiler's own parser/type-checker/constraint-generation crates and produces a
//!    circom `Circuit` (one IR "bucket" tree per template/function) plus the output
//!    signal name -> `(offset, size)` mapping ([`frontend::OutputMapping`]).
//! 2. **codegen** (`codegen::compile`): lowers that IR into a [`CompiledProgram`], in two
//!    phases. First, every template/function is assigned a stable id and the
//!    constant/string tables are parsed, so that calls and subcomponent instantiations
//!    can resolve their targets regardless of declaration order. Second, each body is
//!    walked bucket by bucket and lowered to [`circom_mpc_vm2::isa::Instr`]s; three
//!    cooperating techniques do the actual translation work:
//!    - **Symbolic-index lowering** (`codegen::index`): every array/subcomponent address
//!      sub-tree is folded as far as possible at compile time into a constant, an affine
//!      expression in one integer register, or (only if neither applies) a runtime
//!      computation — so most array accesses cost a single addressing mode rather than
//!      an index computed on every access.
//!    - **Per-loop unroll heuristic** (`codegen::stmt`): a loop with a statically-known,
//!      constant trip count is either unrolled (each iteration's body emitted
//!      separately, letting its indices fold to constants) or compiled to a rolled form
//!      with its induction variable mirrored into an integer register for affine
//!      addressing, depending on [`UnrollConfig`] (below). Dependency-free elementwise
//!      loops may exceed the ordinary unroll budget when their entire expansion compacts
//!      to vector instructions, subject to a separate configurable trip-count cap. Loops
//!      that don't match the conservative "simple ascending counter" shape always take
//!      the rolled path.
//!    - **Register allocation** (`codegen::regalloc`): field and integer registers are
//!      handed out by a bump-pointer allocator with stack-discipline freeing (registers
//!      are freed back to a mark, never individually), which is enough because
//!      expression lowering always frees operand registers as soon as the consuming
//!      instruction is emitted. The high-water mark reached becomes the frame's
//!      register-file size in the resulting [`circom_mpc_vm2::program::TemplateCode`]/
//!      [`circom_mpc_vm2::program::FunctionCode`].
//!
//! # Example
//!
//! Compiling always reads a `.circom` file from disk, so this example is `no_run` (it is
//! still compile-checked). See `circom-mpc-vm2`'s crate docs for a runnable example that
//! hand-assembles an equivalent [`CompiledProgram`] directly.
//!
//! ```no_run
//! use ark_bn254::{Bn254, Fr};
//! use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig};
//! use circom_mpc_vm2::api::PlainWitnessExtension;
//! use circom_mpc_vm2::program::VMConfig;
//! use std::sync::Arc;
//!
//! // circuit.circom: `template Mul2() { signal input a; signal input b;
//! //                  signal output c; c <== a * b; } component main = Mul2();`
//! let program = CoCircomCompiler::<Bn254>::parse("circuit.circom", CompilerConfig::new())
//!     .expect("compilation failed");
//!
//! let wex = PlainWitnessExtension::new_plain(Arc::new(program), VMConfig::default());
//! let finalized = wex
//!     .run_with_flat(vec![Fr::from(6u64), Fr::from(7u64)], 0)
//!     .expect("run_with_flat");
//! assert_eq!(finalized.get_output("c"), Some(vec![Fr::from(42u64)]));
//! ```
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

/// Controls loop unrolling during codegen: for a conforming loop with a statically-known
/// trip count `T` (see `codegen::stmt`'s "Unrolling" module docs), unrolling is only
/// committed to if one iteration's estimated instruction count times `T` doesn't exceed
/// [`Self::threshold`]. A dependency-free elementwise loop may bypass that budget when
/// it compacts completely to vector instructions and fits
/// [`Self::max_vectorized_loop_size`]; every other oversized loop compiles to its
/// ordinary rolled/mirror-promoted form.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct UnrollConfig {
    /// The instruction-count budget (`estimated_body_instrs * trip_count`) a loop must
    /// fit under to be unrolled.
    ///
    /// `0` disables unrolling outright (every loop stays rolled, and the estimation pass
    /// itself is skipped); `usize::MAX` forces unrolling wherever the loop's trip count is
    /// statically known, however large the resulting body.
    #[serde(default = "default_unroll_threshold")]
    pub threshold: usize,
    /// Maximum trip count for a dependency-free elementwise loop that may bypass the
    /// ordinary instruction budget when its fully expanded body compacts entirely to
    /// vector instructions. This bounds the compiler's temporary expansion work and
    /// the VM register block reserved by `BinN`.
    ///
    /// `0` disables the bypass. The ordinary [`Self::threshold`] remains authoritative
    /// for every loop that cannot be completely vectorized.
    #[serde(default = "default_max_vectorized_loop_size")]
    pub max_vectorized_loop_size: usize,
}

fn default_unroll_threshold() -> usize {
    4096
}

fn default_max_vectorized_loop_size() -> usize {
    16_384
}

impl Default for UnrollConfig {
    fn default() -> Self {
        Self {
            threshold: default_unroll_threshold(),
            max_vectorized_loop_size: default_max_vectorized_loop_size(),
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
