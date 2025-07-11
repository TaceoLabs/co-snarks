use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{
    mpc::{
        batched_plain::BatchedCircomPlainVmWitnessExtension, plain::CircomPlainVmWitnessExtension,
    },
    mpc_vm::{BatchedPlainWitnessExtension, PlainWitnessExtension, VMConfig, WitnessExtension},
    op_codes::CodeBlock,
};

/// A template declaration.
///
/// Stores all necessary information to create a component, including the [`CodeBlock`],
/// the number of input signals, sub-components, and vars.
///
/// > **Warning**: Users should usually not interact directly with this struct. It is only public because the
/// > compiler requires these declarations, and the compiler is a separate crate due to licensing constraints.
#[derive(Clone, Serialize, Deserialize)]
pub struct TemplateDecl {
    pub(crate) symbol: String,
    pub(crate) component_name: String,
    pub(crate) input_signals: usize,
    pub(crate) output_signals: usize,
    pub(crate) sub_components: usize,
    pub(crate) vars: usize,
    pub(crate) mappings: Vec<usize>,
    pub(crate) body: Arc<CodeBlock>,
}

impl TemplateDecl {
    #[expect(clippy::too_many_arguments)]
    /// Creates a new template declaration. Only the MPC-compiler should use this method!
    pub fn new(
        symbol: String,
        component_name: String,
        input_signals: usize,
        output_signals: usize,
        sub_components: usize,
        vars: usize,
        mappings: Vec<usize>,
        body: CodeBlock,
    ) -> Self {
        Self {
            symbol,
            component_name,
            input_signals,
            output_signals,
            sub_components,
            vars,
            mappings,
            body: Arc::new(body),
        }
    }
}

/// An unconstrained function declaration.
///
/// Stores all necessary information to call the function, including the [`CodeBlock`],
/// the number of params, and vars.
///
/// > **Warning**: Users should usually not interact directly with this struct. It is only public because the
/// > compiler requires these declarations, and the compiler is a separate crate due to licensing constraints.
#[derive(Clone, Serialize, Deserialize)]
pub struct FunDecl {
    pub(crate) num_params: usize,
    pub(crate) vars: usize,
    pub(crate) body: Arc<CodeBlock>,
}

impl FunDecl {
    /// Creates a new function declaration. Only the MPC-compiler should use this method!
    pub fn new(num_params: usize, vars: usize, body: CodeBlock) -> Self {
        Self {
            num_params,
            vars,
            body: Arc::new(body),
        }
    }
}

/// A type that stores the name of an output signal and maps it to
/// the respective offset in the witness.
///
/// String -> (offset, size)
pub type OutputMapping = HashMap<String, (usize, usize)>;

/// A list of inputs (Name, offset, size).
pub(crate) type InputList = Vec<(String, usize, usize)>;

/// The state of the compiler after it parsed the circom file.
///
/// The struct provides certain methods to consume it and create an
/// [MPC-VM](WitnessExtension).
#[derive(Clone, Serialize, Deserialize)]
pub struct CoCircomCompilerParsed<F: PrimeField> {
    pub(crate) main: String,
    pub(crate) amount_signals: usize,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub(crate) constant_table: Vec<F>,
    pub(crate) string_table: Vec<String>,
    pub(crate) fun_decls: HashMap<String, FunDecl>,
    pub(crate) templ_decls: HashMap<String, TemplateDecl>,
    pub(crate) signal_to_witness: Vec<usize>,
    pub(crate) main_inputs: usize,
    pub(crate) main_outputs: usize,
    pub(crate) main_input_list: InputList,
    pub(crate) output_mapping: OutputMapping,
    pub(crate) public_inputs: Vec<String>,
}

impl<F: PrimeField> CoCircomCompilerParsed<F> {
    /// > **Warning**: DO NOT CALL THIS DIRECTLY! This struct is intended for internal use by the compiler crate
    /// > and should not be instantiated directly. It is publicly visible due to requirements imposed by licensing constraints.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        main: String,
        amount_signals: usize,
        constant_table: Vec<F>,
        string_table: Vec<String>,
        fun_decls: HashMap<String, FunDecl>,
        templ_decls: HashMap<String, TemplateDecl>,
        signal_to_witness: Vec<usize>,
        main_inputs: usize,
        main_outputs: usize,
        main_input_list: InputList,
        output_mapping: OutputMapping,
        public_inputs: Vec<String>,
    ) -> Self {
        Self {
            main,
            amount_signals,
            constant_table,
            string_table,
            fun_decls,
            templ_decls,
            signal_to_witness,
            main_inputs,
            main_outputs,
            main_input_list,
            output_mapping,
            public_inputs,
        }
    }
}

//TODO: Add another builder step here?
//ParserCompiler -> into Rep3/Shamir -> build
impl<F: PrimeField> CoCircomCompilerParsed<F> {
    /// Consumes `self` and constructs an instance of [`PlainWitnessExtension`].
    ///
    /// The plain witness extension allows local execution of the witness extension without
    /// using MPC. Be cautious when using this method, as the resulting
    /// witness and input will not be protected. Do not share sensitive data when using this feature.
    ///
    /// This method is primarily intended for testing purposes.
    pub fn to_plain_vm(
        self,
        vm_config: VMConfig,
    ) -> WitnessExtension<F, CircomPlainVmWitnessExtension<F>> {
        PlainWitnessExtension::new(&self, vm_config)
    }

    /// Consumes `self` and constructs an instance of [`BatchedPlainWitnessExtension`].
    ///
    /// The plain witness extension allows local execution of the witness extension without
    /// using MPC. Be cautious when using this method, as the resulting
    /// witness and input will not be protected. Do not share sensitive data when using this feature.
    ///
    /// The difference to [`Self::to_plain_vm`] is that this version executes the same circuit
    /// simultaneously with different inputs. This does NOT use folding or any other similar
    /// techniques. It reduces multiplicative depth in contrast to running $n$ witness
    /// extensions consecutively.
    ///
    /// This method is primarily intended for testing purposes.
    pub fn to_batched_plain_vm(
        self,
        vm_config: VMConfig,
        batch_size: usize,
    ) -> WitnessExtension<F, BatchedCircomPlainVmWitnessExtension<F>> {
        BatchedPlainWitnessExtension::new(&self, vm_config, batch_size)
    }

    /// Get public input names.
    pub fn public_inputs(&self) -> &[String] {
        &self.public_inputs
    }
}
