//! MPC accelerators: fast paths for specific circom components/functions (Num2Bits,
//! AddBits, IsZero, Poseidon2, the `sqrt_0` function) that skip the general-purpose
//! bytecode body in favor of a driver-specific implementation (e.g. Rep3-native
//! Poseidon2 with precomputed randomness) or simply avoid re-deriving values the
//! interpreter would otherwise recompute the slow way.
//!
//! Registrations are matched against a [`CompiledProgram`]'s templates/functions by
//! name **once, at construction time** (`MpcAccelerator::bind`, crate-private — called
//! by [`crate::api::WitnessExtension`]) rather than by a per-instruction name lookup:
//! binding produces `Vec<Option<usize>>` side tables,
//! indexed directly by [`TemplId`]/[`FnId`], that [`crate::exec::Machine`] consults
//! before running a component body or dispatching a function call. Mirrors old
//! `circom-mpc-vm::accelerator`, with the state-size restriction that was previously a
//! hardcoded check in the VM loop (old `mpc_vm.rs:330-332`) now expressed as the
//! `Poseidon2` registration's own `can_handle` predicate.
use crate::driver::VmDriver;
use crate::isa::{FnId, TemplId};
use crate::program::CompiledProgram;
use ark_ff::PrimeField;
use eyre::{Result, bail};

/// Output of a component accelerator: the component's output-signal values plus any
/// intermediate signal values the rest of the witness extension still needs (e.g.
/// Poseidon2's round trace, or the AddBits/IsZero helper signals) — both are written
/// into signal RAM at the component's usual offsets, in place of running its body.
/// Mirrors old `circom-mpc-vm::accelerator::ComponentAcceleratorOutput`.
#[derive(Debug, Clone)]
pub struct ComponentAcceleratorOutput<T> {
    /// Values written to the component's output signals, in order.
    pub output: Vec<T>,
    /// Values written to the component's intermediate signals (immediately after its
    /// inputs), in order.
    pub intermediate: Vec<T>,
}

impl<T> ComponentAcceleratorOutput<T> {
    /// Creates a new [`ComponentAcceleratorOutput`].
    pub fn new(output: Vec<T>, intermediate: Vec<T>) -> Self {
        Self {
            output,
            intermediate,
        }
    }
}

/// Metadata about a template, presented to a component accelerator's `can_handle`
/// predicate at binding time so it can decide whether it applies to that particular
/// monomorphization (e.g. Poseidon2's state-size restriction).
#[derive(Debug, Clone, Copy)]
pub struct TemplateInfo<'a> {
    /// The component name as written in the circom source (e.g. `"Poseidon2"`).
    pub component_name: &'a str,
    /// Number of input signals.
    pub input_signals: u32,
    /// Number of output signals.
    pub output_signals: u32,
    /// Number of intermediate signal slots available to an accelerator.
    pub intermediate_signals: u32,
}

type CanHandleFn = Box<dyn Fn(&TemplateInfo) -> bool + Send>;
type ComponentFn<F, C> = Box<
    dyn Fn(
            &mut C,
            &[<C as VmDriver<F>>::VmType],
            usize,
        ) -> Result<ComponentAcceleratorOutput<<C as VmDriver<F>>::VmType>>
        + Send,
>;
type FunctionFn<F, C> = Box<
    dyn Fn(&mut C, &[<C as VmDriver<F>>::VmType]) -> Result<Vec<<C as VmDriver<F>>::VmType>> + Send,
>;

struct ComponentEntry<F: PrimeField, C: VmDriver<F>> {
    name: String,
    can_handle: CanHandleFn,
    fun: ComponentFn<F, C>,
}

struct FunctionEntry<F: PrimeField, C: VmDriver<F>> {
    name: String,
    fun: FunctionFn<F, C>,
}

/// Per-program accelerator dispatch tables produced by [`MpcAccelerator::bind`]:
/// `templ_bind`/`fn_bind` are indexed directly by [`TemplId`]/[`FnId`] and hold the
/// index into the owning [`MpcAccelerator`]'s registrations, if any matched.
pub(crate) struct AccelBindings {
    templ_bind: Vec<Option<usize>>,
    fn_bind: Vec<Option<usize>>,
}

impl AccelBindings {
    /// The bound accelerator index for template `templ`, if any.
    pub(crate) fn component_accel(&self, templ: TemplId) -> Option<usize> {
        self.templ_bind[templ.0 as usize]
    }

    /// The bound accelerator index for function `fn_id`, if any.
    pub(crate) fn function_accel(&self, fn_id: FnId) -> Option<usize> {
        self.fn_bind[fn_id.0 as usize]
    }
}

/// Registry of component/function accelerators. Construct via [`MpcAccelerator::empty`]
/// or [`MpcAccelerator::from_config`] (the predefined set), then add custom ones with
/// [`MpcAccelerator::register_component`]/[`MpcAccelerator::register_function`]. Bound
/// (crate-privately) against a specific program's templates/functions, which
/// [`crate::api::WitnessExtension`] does once, lazily, at the start of a run.
pub struct MpcAccelerator<F: PrimeField, C: VmDriver<F>> {
    components: Vec<ComponentEntry<F, C>>,
    functions: Vec<FunctionEntry<F, C>>,
}

impl<F: PrimeField, C: VmDriver<F>> Default for MpcAccelerator<F, C> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<F: PrimeField, C: VmDriver<F>> MpcAccelerator<F, C> {
    /// An empty registry (no accelerators at all).
    pub fn empty() -> Self {
        Self {
            components: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// The predefined registry (`sqrt_0`, `Num2Bits`, `AddBits`, `IsZero`, `Poseidon2`),
    /// gated per-accelerator by `config`.
    pub fn from_config(config: MpcAcceleratorConfig) -> Self {
        let mut accel = Self::empty();
        if config.sqrt {
            accel.register_sqrt();
        }
        if config.num2bits {
            accel.register_num2bits();
        }
        if config.addbits {
            accel.register_addbits();
        }
        if config.iszero {
            accel.register_iszero();
        }
        if config.poseidon2 {
            accel.register_poseidon2();
        }
        accel
    }

    /// Registers a component accelerator under `name` (replacing any existing
    /// registration of the same name): at binding time, every template whose component
    /// name equals `name` **and** for which `can_handle` returns `true` is dispatched
    /// through `fun` instead of running its body. `fun` receives the component's input
    /// signal values and its output-signal count, and returns the values to write into
    /// its output and intermediate signal slots (see [`ComponentAcceleratorOutput`]).
    pub fn register_component(
        &mut self,
        name: impl Into<String>,
        can_handle: impl Fn(&TemplateInfo) -> bool + Send + 'static,
        fun: impl Fn(&mut C, &[C::VmType], usize) -> Result<ComponentAcceleratorOutput<C::VmType>>
        + Send
        + 'static,
    ) {
        let name = name.into();
        let entry = ComponentEntry {
            name: name.clone(),
            can_handle: Box::new(can_handle),
            fun: Box::new(fun),
        };
        match self.components.iter_mut().find(|e| e.name == name) {
            Some(slot) => *slot = entry,
            None => self.components.push(entry),
        }
    }

    /// Registers a function accelerator under `name` (replacing any existing
    /// registration of the same name): at binding time, every function whose symbol
    /// equals `name` is dispatched through `fun` instead of running its body. `fun`
    /// receives the call's argument values and returns the values to hand back to the
    /// caller (padded/truncated to the callsite's arity like any other function
    /// return).
    pub fn register_function(
        &mut self,
        name: impl Into<String>,
        fun: impl Fn(&mut C, &[C::VmType]) -> Result<Vec<C::VmType>> + Send + 'static,
    ) {
        let name = name.into();
        let entry = FunctionEntry {
            name: name.clone(),
            fun: Box::new(fun),
        };
        match self.functions.iter_mut().find(|e| e.name == name) {
            Some(slot) => *slot = entry,
            None => self.functions.push(entry),
        }
    }

    fn register_sqrt(&mut self) {
        self.register_function("sqrt_0", |driver, args| {
            tracing::debug!("calling pre-defined sqrt accelerator");
            if args.len() != 1 {
                bail!("Calling SQRT accelerator with more than one argument!");
            }
            Ok(vec![driver.sqrt(&args[0])?])
        });
    }

    fn register_num2bits(&mut self) {
        self.register_component(
            "Num2Bits",
            |_info| true,
            |driver, args, amount_outputs| {
                tracing::debug!("calling pre-defined Num2Bits accelerator");
                if args.len() != 1 {
                    bail!("Calling Num2Bits accelerator with more than one argument!");
                }
                let output = driver.num2bits(&args[0], amount_outputs)?;
                Ok(ComponentAcceleratorOutput {
                    output,
                    intermediate: Vec::new(),
                })
            },
        );
    }

    fn register_addbits(&mut self) {
        self.register_component(
            "AddBits",
            |_info| true,
            |driver, args, _amount_outputs| {
                tracing::debug!("calling pre-defined AddBits accelerator");
                if args.len() % 2 != 0 {
                    bail!("Calling AddBits accelerator with odd number of arguments!");
                }
                let (a, b) = args.split_at(args.len() / 2);
                let (output, carry) = driver.addbits(a, b)?;
                Ok(ComponentAcceleratorOutput {
                    output,
                    intermediate: vec![carry],
                })
            },
        );
    }

    fn register_iszero(&mut self) {
        self.register_component(
            "IsZero",
            |_info| true,
            |driver, args, _amount_outputs| {
                tracing::debug!("calling pre-defined IsZero accelerator");
                if args.len() != 1 {
                    bail!("Calling IsZero accelerator with more than one argument!");
                }
                let zero = driver.public_zero();
                let is_zero = driver.eq(&args[0], &zero)?;
                let inv_input = driver.add(&args[0], &is_zero)?;
                let one = driver.public_one();
                let maybe_masked_inv = driver.div(&one, &inv_input)?;
                let helper = driver.sub(&maybe_masked_inv, &is_zero)?;
                Ok(ComponentAcceleratorOutput {
                    output: vec![is_zero],
                    intermediate: vec![helper],
                })
            },
        );
    }

    fn register_poseidon2(&mut self) {
        self.register_component(
            "Poseidon2",
            // Mirrors old mpc_vm.rs:330-332 exactly: only state sizes 2, 3, 4, 16 are
            // supported; this used to be a hardcoded VM-loop guard, now it's the
            // registration's own can_handle predicate.
            |info| {
                !(info.input_signals == 8 || info.input_signals == 12 || info.input_signals > 16)
            },
            |driver, args, _amount_outputs| {
                tracing::debug!("calling pre-defined Poseidon2 accelerator");
                let args_len = args.len();
                let (state, traces) = match args_len {
                    2 => driver.poseidon2_accelerator::<2>(args)?,
                    3 => driver.poseidon2_accelerator::<3>(args)?,
                    4 => driver.poseidon2_accelerator::<4>(args)?,
                    16 => driver.poseidon2_accelerator::<16>(args)?,
                    _ => bail!(
                        "Poseidon2 accelerator currently only supports input lengths 2, 3, 4 or 16, got {args_len}"
                    ),
                };
                Ok(ComponentAcceleratorOutput {
                    output: state,
                    intermediate: traces,
                })
            },
        );
    }

    /// Binds this registry against `program`'s templates/functions, producing the
    /// index-keyed dispatch tables the VM consults on every component run/function
    /// call. A template matches the first registered component whose name equals its
    /// component name ([`TemplateCode::name_id`](crate::program::TemplateCode)) and
    /// whose `can_handle` returns `true` for it; a function matches the first
    /// registered function whose name equals its symbol
    /// ([`FunctionCode::name_id`](crate::program::FunctionCode)).
    pub(crate) fn bind(&self, program: &CompiledProgram<F>) -> AccelBindings {
        let templ_bind = program
            .templates
            .iter()
            .map(|code| {
                let component_name = program.debug.names[code.name_id as usize].as_str();
                let info = TemplateInfo {
                    component_name,
                    input_signals: code.input_signals,
                    output_signals: code.output_signals,
                    intermediate_signals: code.intermediate_signals,
                };
                self.components
                    .iter()
                    .position(|e| e.name == component_name && (e.can_handle)(&info))
            })
            .collect();
        let fn_bind = program
            .functions
            .iter()
            .map(|code| {
                let symbol = program.debug.names[code.name_id as usize].as_str();
                self.functions.iter().position(|e| e.name == symbol)
            })
            .collect();
        AccelBindings {
            templ_bind,
            fn_bind,
        }
    }

    /// Runs the component accelerator bound at `accel_idx` (see [`Self::bind`]).
    pub(crate) fn run_component(
        &self,
        accel_idx: usize,
        driver: &mut C,
        args: &[C::VmType],
        amount_outputs: usize,
    ) -> Result<ComponentAcceleratorOutput<C::VmType>> {
        (self.components[accel_idx].fun)(driver, args, amount_outputs)
    }

    /// Runs the function accelerator bound at `accel_idx` (see [`Self::bind`]).
    pub(crate) fn run_function(
        &self,
        accel_idx: usize,
        driver: &mut C,
        args: &[C::VmType],
    ) -> Result<Vec<C::VmType>> {
        (self.functions[accel_idx].fun)(driver, args)
    }
}

/// Which predefined accelerators [`MpcAccelerator::from_config`] should register.
/// Every field defaults to `true` (both [`Default`] and [`MpcAcceleratorConfig::from_env`]'s
/// fallback for an unset/unrecognized variable). Mirrors old
/// `circom-mpc-vm::accelerator::MpcAcceleratorConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpcAcceleratorConfig {
    /// Whether to register the predefined `sqrt_0` function accelerator.
    pub sqrt: bool,
    /// Whether to register the predefined `Num2Bits` component accelerator.
    pub num2bits: bool,
    /// Whether to register the predefined `AddBits` component accelerator.
    pub addbits: bool,
    /// Whether to register the predefined `IsZero` component accelerator.
    pub iszero: bool,
    /// Whether to register the predefined `Poseidon2` component accelerator.
    pub poseidon2: bool,
}

impl Default for MpcAcceleratorConfig {
    fn default() -> Self {
        Self {
            sqrt: true,
            num2bits: true,
            addbits: true,
            iszero: true,
            poseidon2: true,
        }
    }
}

/// Parses a `CIRCOM_MPC_ACCELERATOR_*` environment variable's value; unrecognized
/// values default to `true` (with a warning), matching old
/// `circom-mpc-vm::accelerator::map_env_string_to_bool` verbatim.
fn map_env_string_to_bool(value: &str) -> bool {
    match value.to_ascii_lowercase().as_str() {
        "1" => true,
        "true" => true,
        "on" => true,
        "0" => false,
        "false" => false,
        "off" => false,
        _ => {
            tracing::warn!("Invalid value for boolean ENV var, defaulting to true");
            true
        }
    }
}

impl MpcAcceleratorConfig {
    /// Constructs an [`MpcAcceleratorConfig`] from the environment.
    ///
    /// If a variable is not set, it defaults to `true`. The variables are of the form
    /// `CIRCOM_MPC_ACCELERATOR_<NAME>` where `<NAME>` is one of `SQRT`, `NUM2BITS`,
    /// `ADDBITS`, `ISZERO`, `POSEIDON2`. Possible values for the boolean variables are
    /// `"1"`, `"true"`, `"on"`, `"0"`, `"false"`, `"off"` (case-insensitive).
    pub fn from_env() -> Self {
        Self {
            sqrt: std::env::var("CIRCOM_MPC_ACCELERATOR_SQRT")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            num2bits: std::env::var("CIRCOM_MPC_ACCELERATOR_NUM2BITS")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            addbits: std::env::var("CIRCOM_MPC_ACCELERATOR_ADDBITS")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            iszero: std::env::var("CIRCOM_MPC_ACCELERATOR_ISZERO")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            poseidon2: std::env::var("CIRCOM_MPC_ACCELERATOR_POSEIDON2")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_bool_parsing_table() {
        for (raw, expected) in [
            ("1", true),
            ("true", true),
            ("TRUE", true),
            ("on", true),
            ("ON", true),
            ("0", false),
            ("false", false),
            ("FALSE", false),
            ("off", false),
            ("OFF", false),
            ("garbage", true), // unrecognized defaults to true (with a warning)
        ] {
            assert_eq!(map_env_string_to_bool(raw), expected, "input {raw:?}");
        }
    }

    #[test]
    fn default_config_all_true() {
        let cfg = MpcAcceleratorConfig::default();
        assert!(cfg.sqrt);
        assert!(cfg.num2bits);
        assert!(cfg.addbits);
        assert!(cfg.iszero);
        assert!(cfg.poseidon2);
    }

    // SAFETY (both `unsafe` blocks below): test-only mutation of process-global env
    // vars, scoped to the `CIRCOM_MPC_ACCELERATOR_*` names this module owns — no other
    // test in this crate reads or writes them, so concurrent test execution cannot
    // race on these particular keys.
    #[test]
    fn from_env_reads_configured_vars_and_defaults_unset_ones_to_true() {
        unsafe {
            std::env::set_var("CIRCOM_MPC_ACCELERATOR_SQRT", "0");
            std::env::set_var("CIRCOM_MPC_ACCELERATOR_NUM2BITS", "false");
            std::env::set_var("CIRCOM_MPC_ACCELERATOR_ADDBITS", "on");
            std::env::remove_var("CIRCOM_MPC_ACCELERATOR_ISZERO");
            std::env::remove_var("CIRCOM_MPC_ACCELERATOR_POSEIDON2");
        }
        let cfg = MpcAcceleratorConfig::from_env();
        unsafe {
            std::env::remove_var("CIRCOM_MPC_ACCELERATOR_SQRT");
            std::env::remove_var("CIRCOM_MPC_ACCELERATOR_NUM2BITS");
            std::env::remove_var("CIRCOM_MPC_ACCELERATOR_ADDBITS");
        }
        assert!(!cfg.sqrt);
        assert!(!cfg.num2bits);
        assert!(cfg.addbits);
        assert!(cfg.iszero, "unset variable must default to true");
        assert!(cfg.poseidon2, "unset variable must default to true");
    }
}
