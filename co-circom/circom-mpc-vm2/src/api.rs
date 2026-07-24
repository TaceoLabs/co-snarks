//! The supported public API of the crate: [`WitnessExtension`], driven to completion via
//! [`WitnessExtension::run`]/[`WitnessExtension::run_with_flat`] into a
//! [`FinalizedWitnessExtension`].
use crate::accel::{ComponentAcceleratorOutput, MpcAccelerator, TemplateInfo};
use crate::driver::VmDriver;
use crate::drivers::plain::PlainDriver;
use crate::drivers::rep3::Rep3Driver;
use crate::exec::Machine;
use crate::program::{CompiledProgram, InputInfo, VMConfig};
use ark_ff::PrimeField;
use co_circom_types::SharedWitness;
use eyre::{Result, bail};
use mpc_net::Network;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Drives one witness extension of a [`CompiledProgram`] with a given [`VmDriver`].
///
/// Construct with [`WitnessExtension::new`] (or [`PlainWitnessExtension::new_plain`] for
/// local plain execution), then consume it with [`WitnessExtension::run`] or
/// [`WitnessExtension::run_with_flat`].
pub struct WitnessExtension<F: PrimeField, C: VmDriver<F>> {
    program: Arc<CompiledProgram<F>>,
    driver: C,
    config: VMConfig,
    accelerator: MpcAccelerator<F, C>,
}

/// Convenience alias for local (non-MPC) plain execution.
pub type PlainWitnessExtension<F> = WitnessExtension<F, PlainDriver<F>>;

impl<F: PrimeField, C: VmDriver<F>> WitnessExtension<F, C> {
    /// Creates a new witness extension for `program`, driven by `driver`.
    ///
    /// The accelerator registry uses [`VMConfig::accelerator`]'s predefined set
    /// (`sqrt_0`/`Num2Bits`/`AddBits`/`IsZero`/`Poseidon2`). [`VMConfig::default`]
    /// initializes that field from the `CIRCOM_MPC_ACCELERATOR_*` environment variables,
    /// while callers can override it directly without mutating process-global state. Use
    /// [`WitnessExtension::register_accelerator_component`]/
    /// [`WitnessExtension::register_accelerator_function`] to add to it. Registrations
    /// are matched against `program`'s templates/functions lazily, once, at the start
    /// of [`WitnessExtension::run`]/[`WitnessExtension::run_with_flat`] — so register
    /// everything you need before calling either.
    pub fn new(program: Arc<CompiledProgram<F>>, driver: C, config: VMConfig) -> Self {
        let accelerator = MpcAccelerator::from_config(config.accelerator);
        Self {
            program,
            driver,
            config,
            accelerator,
        }
    }

    /// Registers a component accelerator (see
    /// [`MpcAccelerator::register_component`]) on this witness extension's registry.
    /// Must be called before [`WitnessExtension::run`]/[`WitnessExtension::run_with_flat`]
    /// (binding happens lazily at the start of either).
    pub fn register_accelerator_component(
        &mut self,
        name: impl Into<String>,
        can_handle: impl Fn(&TemplateInfo) -> bool + Send + 'static,
        fun: impl Fn(&mut C, &[C::VmType], usize) -> Result<ComponentAcceleratorOutput<C::VmType>>
        + Send
        + 'static,
    ) {
        self.accelerator.register_component(name, can_handle, fun);
    }

    /// Registers a function accelerator (see [`MpcAccelerator::register_function`]) on
    /// this witness extension's registry. Must be called before
    /// [`WitnessExtension::run`]/[`WitnessExtension::run_with_flat`] (binding happens
    /// lazily at the start of either).
    pub fn register_accelerator_function(
        &mut self,
        name: impl Into<String>,
        fun: impl Fn(&mut C, &[C::VmType]) -> Result<Vec<C::VmType>> + Send + 'static,
    ) {
        self.accelerator.register_function(name, fun);
    }

    /// Starts the witness extension with the provided named inputs and consumes `self`.
    ///
    /// `inputs` maps circom input-signal names to values; a multi-element input `name`
    /// of size `n` must be provided as the keys `name[0]..name[n-1]` (matching circom's
    /// own naming convention), not as a single `name` key.
    ///
    /// Cross-checks `config` across parties via [`VmDriver::compare_vm_config`] before
    /// running.
    pub fn run(
        mut self,
        inputs: BTreeMap<String, C::VmType>,
        amount_public_inputs: usize,
    ) -> Result<FinalizedWitnessExtension<F, C>> {
        self.driver.compare_vm_config(&self.config)?;
        let signals = {
            let mut machine = Machine::new_with_accelerator(
                &self.program,
                &mut self.driver,
                self.config.clone(),
                &self.accelerator,
            )?;
            set_input_signals(&self.program.main_input_list, &mut machine.signals, inputs)?;
            machine.run_main()?;
            machine.signals
        };
        post_processing(
            &mut self.driver,
            &self.program,
            signals,
            amount_public_inputs,
        )
    }

    /// Starts the witness extension with the provided flat inputs and consumes `self`.
    ///
    /// # Warning
    /// The input signals are copied, element by element, straight into signal RAM
    /// following the main component's input layout — there is no name-based mapping.
    /// Use this only when you are certain which value corresponds to which input
    /// position; prefer [`WitnessExtension::run`] otherwise.
    ///
    /// Unlike [`WitnessExtension::run`], this does **not** call
    /// [`VmDriver::compare_vm_config`] first.
    pub fn run_with_flat(
        mut self,
        inputs: Vec<C::VmType>,
        amount_public_inputs: usize,
    ) -> Result<FinalizedWitnessExtension<F, C>> {
        let signals = {
            let mut machine = Machine::new_with_accelerator(
                &self.program,
                &mut self.driver,
                self.config.clone(),
                &self.accelerator,
            )?;
            set_flat_input_signals(
                self.program.main_inputs,
                self.program.main_outputs,
                &mut machine.signals,
                inputs,
            )?;
            machine.run_main()?;
            machine.signals
        };
        post_processing(
            &mut self.driver,
            &self.program,
            signals,
            amount_public_inputs,
        )
    }
}

impl<F: PrimeField> PlainWitnessExtension<F> {
    /// Convenience constructor for local plain execution.
    pub fn new_plain(program: Arc<CompiledProgram<F>>, config: VMConfig) -> Self {
        Self::new(program, PlainDriver::default(), config)
    }
}

/// Convenience alias for Rep3 (3-party replicated secret sharing) execution.
pub type Rep3WitnessExtension<'a, F, N> = WitnessExtension<F, Rep3Driver<'a, F, N>>;

impl<'a, F: PrimeField, N: Network> Rep3WitnessExtension<'a, F, N> {
    /// Convenience constructor for Rep3 execution: builds the [`Rep3Driver`] (running
    /// the Rep3 setup handshake over `net0`/`net1`) and wraps it in a
    /// [`WitnessExtension`].
    pub fn new_rep3(
        net0: &'a N,
        net1: &'a N,
        program: Arc<CompiledProgram<F>>,
        config: VMConfig,
    ) -> Result<Self> {
        let driver = Rep3Driver::new(net0, net1, config.a2b_type)?;
        Ok(Self::new(program, driver, config))
    }
}

/// Writes `inputs` into `signals` following `main_input_list`, removing each consumed
/// key. A multi-element input `name` (`size > 1`) is looked up element-wise as
/// `name[0]..name[size-1]`, matching circom's own naming convention. Mirrors old
/// `WitnessExtension::set_input_signals` (`circom-mpc-vm/src/mpc_vm.rs:956-977`).
fn set_input_signals<T>(
    main_input_list: &[InputInfo],
    signals: &mut [T],
    mut inputs: BTreeMap<String, T>,
) -> Result<()> {
    for info in main_input_list {
        if info.size == 1 {
            let v = inputs.remove(&info.name).ok_or_else(|| {
                eyre::eyre!("Cannot find signal \"{}\" in provided input", info.name)
            })?;
            signals[info.offset] = v;
        } else {
            for i in 0..info.size {
                let key = format!("{}[{i}]", info.name);
                let v = inputs.remove(&key).ok_or_else(|| {
                    eyre::eyre!("Cannot find signal \"{}\" in provided input", info.name)
                })?;
                signals[info.offset + i] = v;
            }
        }
    }
    Ok(())
}

/// Writes `inputs` straight into `signals[1 + main_outputs .. 1 + main_outputs +
/// main_inputs]`, in order. Mirrors old `WitnessExtension::set_flat_input_signals`
/// (`circom-mpc-vm/src/mpc_vm.rs:978-986`).
fn set_flat_input_signals<T>(
    main_inputs: usize,
    main_outputs: usize,
    signals: &mut [T],
    inputs: Vec<T>,
) -> Result<()> {
    if inputs.len() != main_inputs {
        bail!(
            "expected {main_inputs} flat input signal(s), got {}",
            inputs.len()
        );
    }
    let dst = &mut signals[1 + main_outputs..1 + main_outputs + main_inputs];
    for (slot, v) in dst.iter_mut().zip(inputs) {
        *slot = v;
    }
    Ok(())
}

/// Splits the finished `signals` RAM into the public part (opened) and the secret
/// witness part (converted to a share), following `program.signal_to_witness`. The
/// public part is the first `main_outputs + amount_public_inputs + 1` witness entries
/// (the `+ 1` is the constant 1 at signal 0). Mirrors old
/// `WitnessExtension::post_processing` (`circom-mpc-vm/src/mpc_vm.rs:911-934`).
fn post_processing<F: PrimeField, C: VmDriver<F>>(
    driver: &mut C,
    program: &CompiledProgram<F>,
    signals: Vec<C::VmType>,
    amount_public_inputs: usize,
) -> Result<FinalizedWitnessExtension<F, C>> {
    let total_public_amount = program.main_outputs + amount_public_inputs + 1;
    let mut public_inputs = Vec::with_capacity(total_public_amount);
    let mut witness = Vec::with_capacity(
        program
            .signal_to_witness
            .len()
            .saturating_sub(total_public_amount),
    );
    for (count, idx) in program.signal_to_witness.iter().enumerate() {
        if count < total_public_amount {
            public_inputs.push(driver.open(&signals[*idx])?);
        } else {
            witness.push(driver.to_share(&signals[*idx])?);
        }
    }
    Ok(FinalizedWitnessExtension {
        shared_witness: SharedWitness {
            public_inputs,
            witness,
        },
        output_mapping: program.output_mapping.clone(),
    })
}

/// The result of a finished witness extension: the secret-shared witness plus the
/// output-name mapping needed to look up individual outputs (see
/// [`FinalizedWitnessExtension::get_output`]).
pub struct FinalizedWitnessExtension<F: PrimeField, C: VmDriver<F>> {
    shared_witness: SharedWitness<C::Public, C::ArithmeticShare>,
    output_mapping: std::collections::HashMap<String, (usize, usize)>,
}

impl<F: PrimeField, C: VmDriver<F>> FinalizedWitnessExtension<F, C> {
    /// Consumes `self` and returns the [`SharedWitness`].
    pub fn into_shared_witness(self) -> SharedWitness<C::Public, C::ArithmeticShare> {
        self.shared_witness
    }

    /// Returns the (opened) public values of the main component's output signal
    /// `name`, or `None` if `name` is not a known output. Mirrors old
    /// `FinalizedWitnessExtension::get_output` (`circom-mpc-vm/src/mpc_vm.rs:1141-1145`).
    pub fn get_output(&self, name: &str) -> Option<Vec<C::Public>> {
        self.output_mapping.get(name).map(|(offset, size)| {
            self.shared_witness.public_inputs[*offset..*offset + *size].to_vec()
        })
    }
}
