//! The compiled program artifact produced by circom-mpc-compiler2.
use crate::accel::MpcAcceleratorConfig;
use crate::fingerprint::FingerprintWriter;
use crate::isa::{Instr, TemplId};
use ark_ff::{BigInteger, PrimeField};
use eyre::Result;
use mpc_core::protocols::rep3::conversion::A2BType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Code and metadata for one monomorphized template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateCode {
    /// The instructions of the template body (ends with [`Instr::Return`]).
    pub instrs: Vec<Instr>,
    /// Field-register frame size.
    pub num_field_regs: u16,
    /// Integer-register frame size.
    pub num_int_regs: u8,
    /// Number of var slots.
    pub num_vars: u32,
    /// Number of input signals.
    pub input_signals: u32,
    /// Number of output signals.
    pub output_signals: u32,
    /// Number of intermediate (neither input nor output) signals owned by the template.
    pub intermediate_signals: u32,
    /// Number of subcomponents (capacity hint).
    pub sub_components: u32,
    /// io-map offsets for mapped subcomponent access (old `TemplateDecl::mappings`).
    pub mappings: Vec<u32>,
    /// Index into [`DebugInfo::names`]: the component name (e.g. `"Poseidon2"`), used
    /// for accelerator binding and error messages.
    pub name_id: u32,
    /// Index into [`DebugInfo::names`]: the template symbol (e.g. `"Poseidon2_5"`).
    pub symbol_id: u32,
}

/// Code and metadata for one unconstrained function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCode {
    /// The instructions of the function body.
    pub instrs: Vec<Instr>,
    /// Field-register frame size.
    pub num_field_regs: u16,
    /// Integer-register frame size.
    pub num_int_regs: u8,
    /// Number of var slots (params occupy `0..num_params`).
    pub num_vars: u32,
    /// Total number of parameter values.
    pub num_params: u32,
    /// Index into [`DebugInfo::names`]: the function symbol.
    pub name_id: u32,
}

/// Names and source mapping for errors, logs, and accelerator binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugInfo {
    /// Interned name table referenced by `name_id`/`symbol_id`.
    pub names: Vec<String>,
}

/// One main-component input: (name, signal offset, size).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    /// Signal name as written in the circom source.
    pub name: String,
    /// Offset in signal RAM.
    pub offset: usize,
    /// Number of field elements.
    pub size: usize,
}

/// The serializable compiled artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledProgram<F: PrimeField> {
    /// Template table, indexed by [`TemplId`].
    pub templates: Vec<TemplateCode>,
    /// Function table, indexed by [`FnId`](crate::isa::FnId).
    pub functions: Vec<FunctionCode>,
    /// Field-constant table.
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub constants: Vec<F>,
    /// Log string table.
    pub strings: Vec<String>,
    /// The main template.
    pub main: TemplId,
    /// Total size of signal RAM (index 0 is the constant 1).
    pub total_signals: usize,
    /// Number of main-component inputs.
    pub main_inputs: usize,
    /// Number of main-component outputs.
    pub main_outputs: usize,
    /// Main-component input layout.
    pub main_input_list: Vec<InputInfo>,
    /// Output name → (offset, size) within the public part of the witness.
    pub output_mapping: HashMap<String, (usize, usize)>,
    /// Witness index → signal index.
    pub signal_to_witness: Vec<usize>,
    /// Names of public inputs.
    pub public_inputs: Vec<String>,
    /// Debug side table.
    pub debug: DebugInfo,
}

impl<F: PrimeField> CompiledProgram<F> {
    /// Computes the deterministic digest used to ensure every MPC party will execute
    /// identical bytecode and witness layout. The hash is streamed rather than first
    /// materializing a second program-sized byte buffer. `output_mapping` is sorted
    /// explicitly because its in-memory `HashMap` iteration order is randomized.
    pub(crate) fn execution_digest(&self) -> Result<[u8; 32]> {
        let mut writer = FingerprintWriter::new(b"circom-mpc-vm2/program/v1\0");
        writer.serialize(&1u32)?;
        writer.serialize(&F::MODULUS.to_bytes_le())?;
        writer.serialize(&self.templates)?;
        writer.serialize(&self.functions)?;
        writer.serialize(&self.constants.len())?;
        writer.serialize_canonical(&self.constants)?;
        writer.serialize(&self.strings)?;
        writer.serialize(&self.main)?;
        writer.serialize(&self.total_signals)?;
        writer.serialize(&self.main_inputs)?;
        writer.serialize(&self.main_outputs)?;
        writer.serialize(&self.main_input_list)?;

        let mut output_mapping: Vec<_> = self
            .output_mapping
            .iter()
            .map(|(name, &(offset, size))| (name.as_str(), offset, size))
            .collect();
        output_mapping.sort_unstable_by(|a, b| a.0.cmp(b.0));
        writer.serialize(&output_mapping)?;

        writer.serialize(&self.signal_to_witness)?;
        writer.serialize(&self.public_inputs)?;
        writer.serialize(&self.debug)?;
        Ok(writer.finish())
    }

    /// Returns the main component's input names and sizes (old
    /// `CoCircomCompilerParsed::inputs`, `circom-mpc-vm/src/types.rs:199-205`), derived
    /// from [`Self::main_input_list`].
    pub fn inputs(&self) -> Vec<(String, usize)> {
        self.main_input_list
            .iter()
            .map(|input| (input.name.clone(), input.size))
            .collect()
    }

    /// Returns the main component's public input names (old
    /// `CoCircomCompilerParsed::public_inputs`, `circom-mpc-vm/src/types.rs:207-210`).
    pub fn public_inputs(&self) -> &[String] {
        &self.public_inputs
    }
}

/// Combines every execution-affecting input checked between MPC parties into one compact
/// fingerprint. `program_digest` and `accelerator_digest` are separately domain-separated;
/// this outer hash binds both to the selected VM configuration and schema version.
pub(crate) fn execution_fingerprint(
    config: &VMConfig,
    program_digest: [u8; 32],
    accelerator_digest: [u8; 32],
) -> Result<[u8; 32]> {
    let mut writer = FingerprintWriter::new(b"circom-mpc-vm2/execution/v1\0");
    writer.serialize(&1u32)?;
    writer.serialize(config)?;
    writer.serialize(&program_digest)?;
    writer.serialize(&accelerator_digest)?;
    Ok(writer.finish())
}

/// The VM configuration (parity with the old crate's `VMConfig`).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct VMConfig {
    /// Allow leaking of secret values in logs.
    #[serde(default)]
    pub allow_leaky_logs: bool,
    /// Implementation choice for arithmetic/binary conversions (Rep3).
    #[serde(default)]
    pub a2b_type: A2BType,
    /// Predefined witness-extension accelerators to enable.
    #[serde(default)]
    pub accelerator: MpcAcceleratorConfig,
}

impl Default for VMConfig {
    fn default() -> Self {
        Self {
            allow_leaky_logs: false,
            a2b_type: A2BType::default(),
            accelerator: MpcAcceleratorConfig::from_env(),
        }
    }
}

impl VMConfig {
    /// Creates a new default config.
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::*;

    fn digest_test_program() -> CompiledProgram<ark_bn254::Fr> {
        CompiledProgram {
            templates: vec![TemplateCode {
                instrs: vec![Instr::Return],
                num_field_regs: 0,
                num_int_regs: 0,
                num_vars: 0,
                input_signals: 0,
                output_signals: 0,
                intermediate_signals: 0,
                sub_components: 0,
                mappings: vec![],
                name_id: 0,
                symbol_id: 0,
            }],
            functions: vec![],
            constants: vec![ark_bn254::Fr::from(42u64)],
            strings: vec![],
            main: TemplId(0),
            total_signals: 1,
            main_inputs: 0,
            main_outputs: 0,
            main_input_list: vec![],
            output_mapping: HashMap::new(),
            signal_to_witness: vec![0],
            public_inputs: vec![],
            debug: DebugInfo {
                names: vec!["Main".into()],
            },
        }
    }

    #[test]
    fn execution_digest_is_independent_of_hash_map_insertion_order() {
        let mut a = digest_test_program();
        a.output_mapping.insert("z".into(), (3, 4));
        a.output_mapping.insert("a".into(), (1, 2));

        let mut b = digest_test_program();
        b.output_mapping.insert("a".into(), (1, 2));
        b.output_mapping.insert("z".into(), (3, 4));

        assert_eq!(a.execution_digest().unwrap(), b.execution_digest().unwrap());
    }

    #[test]
    fn execution_digest_covers_program_and_context_changes() {
        let program = digest_test_program();
        let digest = program.execution_digest().unwrap();

        let mut changed = program.clone();
        changed.templates[0].instrs.insert(0, Instr::SharedEnd);
        assert_ne!(digest, changed.execution_digest().unwrap());

        let accelerator_digest = [7u8; 32];
        let config = VMConfig::default();
        let fingerprint = execution_fingerprint(&config, digest, accelerator_digest).unwrap();
        let mut changed_config = config;
        changed_config.allow_leaky_logs = !changed_config.allow_leaky_logs;
        assert_ne!(
            fingerprint,
            execution_fingerprint(&changed_config, digest, accelerator_digest).unwrap()
        );
        assert_ne!(
            fingerprint,
            execution_fingerprint(&VMConfig::default(), digest, [8u8; 32]).unwrap()
        );
    }

    #[test]
    fn program_bincode_roundtrip() {
        let program = CompiledProgram::<ark_bn254::Fr> {
            templates: vec![TemplateCode {
                instrs: vec![
                    Instr::Bin {
                        op: BinOp::Mul,
                        dst: 0,
                        a: Src::Signal(Addr::Const(1)),
                        b: Src::Signal(Addr::Const(2)),
                    },
                    Instr::Mov {
                        dst: Dst::Signal(Addr::Const(0)),
                        src: Src::Reg(0),
                    },
                    Instr::Return,
                ],
                num_field_regs: 1,
                num_int_regs: 0,
                num_vars: 0,
                input_signals: 2,
                output_signals: 1,
                intermediate_signals: 0,
                sub_components: 0,
                mappings: vec![],
                name_id: 0,
                symbol_id: 0,
            }],
            functions: vec![],
            constants: vec![ark_bn254::Fr::from(42u64)],
            strings: vec![],
            main: TemplId(0),
            total_signals: 4,
            main_inputs: 2,
            main_outputs: 1,
            main_input_list: vec![InputInfo {
                name: "a".into(),
                offset: 2,
                size: 1,
            }],
            output_mapping: Default::default(),
            signal_to_witness: vec![0, 1, 2, 3],
            public_inputs: vec![],
            debug: DebugInfo {
                names: vec!["Mul".into()],
            },
        };
        let bytes = bincode::serialize(&program).unwrap();
        let de: CompiledProgram<ark_bn254::Fr> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(de.templates[0].instrs, program.templates[0].instrs);
        assert_eq!(de.constants, program.constants);
        assert_eq!(de.total_signals, 4);
    }

    #[test]
    fn inputs_and_public_inputs_accessors() {
        let program = CompiledProgram::<ark_bn254::Fr> {
            templates: vec![],
            functions: vec![],
            constants: vec![],
            strings: vec![],
            main: TemplId(0),
            total_signals: 0,
            main_inputs: 2,
            main_outputs: 0,
            main_input_list: vec![
                InputInfo {
                    name: "a".into(),
                    offset: 1,
                    size: 1,
                },
                InputInfo {
                    name: "b".into(),
                    offset: 2,
                    size: 3,
                },
            ],
            output_mapping: Default::default(),
            signal_to_witness: vec![],
            public_inputs: vec!["a".into()],
            debug: DebugInfo::default(),
        };

        assert_eq!(
            program.inputs(),
            vec![("a".to_string(), 1), ("b".to_string(), 3)]
        );
        assert_eq!(program.public_inputs(), &["a".to_string()]);
    }
}
