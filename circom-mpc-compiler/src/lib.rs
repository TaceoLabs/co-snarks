#![warn(missing_docs)]
//! This crate defines a [`Compiler`](CollaborativeCircomCompiler), which compiles `.circom` files into proprietary bytecode for the [`circom MPC-VM`](circom_mpc_vm).
//!
//! The MPC-VM then executes the bytecode and performs the [witness extension](https://docs.circom.io/getting-started/computing-the-witness/) in MPC (Multiparty Computation). This crate provides a [`CompilerBuilder`] for convenient construction of the [`CollaborativeCircomCompiler`].
//!
//! The compiler and the VM are generic over a [`Pairing`](https://docs.rs/ark-ec/latest/ark_ec/pairing/trait.Pairing.html). Currently, we support the curves `bn254` and `bls12-381`.
//!
//! # Examples
//!
//! To instantiate the [`CollaborativeCircomCompiler`], first create a [`CompilerBuilder`]. In this example, we use the curve `bn254` and link external libraries such as those
//!  from [`circomlib`](https://github.com/iden3/circomlib/).
//!
//! Finally, we build the compiler and parse the circuit:
//!
//! ```
//! # use circom_mpc_compiler::CompilerBuilder;
//! # use ark_bn254::Bn254;
//! # let circuit_file = "".to_owned();
//!
//! let link_library = vec!["link/to/lib/"];
//! // Instantiate the compiler with the circuit file
//! let mut builder = CompilerBuilder::<Bn254>::new(circuit_file);
//!
//! // Link external circom libraries
//! for lib in link_library {
//!     builder = builder.link_library(lib);
//! }
//!
//! // Build the compiler and parse
//! let parsed_circom_circuit = builder
//!     .build()
//!     .parse();
//! ```
//!
//! The [`parse()`](CollaborativeCircomCompiler::parse) method consumes the compiler and returns an instance of [`CollaborativeCircomCompilerParsed`].
//! Refer to its documentation to learn how to create an MPC-VM for the witness extension.
use ark_ec::pairing::Pairing;
use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags},
    intermediate_representation::{
        ir_interface::{
            AddressType, AssertBucket, BranchBucket, CallBucket, ComputeBucket, CreateCmpBucket,
            Instruction, LoadBucket, LocationRule, LogBucket, LogBucketArg, LoopBucket,
            OperatorType, ReturnBucket, ReturnType, StoreBucket, ValueBucket, ValueType,
        },
        InstructionList,
    },
};
use circom_constraint_generation::BuildConfig;
use circom_mpc_vm::{
    op_codes::{CodeBlock, MpcOpCode},
    types::{CollaborativeCircomCompilerParsed, FunDecl, TemplateDecl},
};
use circom_program_structure::{error_definition::Report, program_archive::ProgramArchive};
use circom_type_analysis::check_types;
use eyre::eyre;
use eyre::{bail, Result};
use itertools::Itertools;
use std::{collections::HashMap, marker::PhantomData, path::PathBuf};

const DEFAULT_VERSION: &str = "2.0.0";

/// A builder to create a [`CollaborativeCircomCompiler`].
///
/// This builder allows configuring the compiler with options such as linking external libraries.
/// For future releases, additional flags defined by [circom](https://docs.circom.io/getting-started/compilation-options/)
/// will be supported.
///
/// # Examples
///
/// ```
/// # use circom_mpc_compiler::CompilerBuilder;
/// # use ark_bn254::Bn254;
/// # let circuit_file = "".to_owned();
///
/// let link_library = vec!["link/to/lib/"];
/// // Create a new compiler builder for the Bn254 curve
/// let mut builder = CompilerBuilder::<Bn254>::new(circuit_file);
///
/// // Link external circom libraries
/// for lib in link_library {
///     builder = builder.link_library(lib);
/// }
///
/// // Build the compiler
/// let compiler = builder.build();
/// ```

pub struct CompilerBuilder<P: Pairing> {
    file: String,
    version: String,
    link_libraries: Vec<PathBuf>,
    phantom_data: PhantomData<P>,
}

/// The constructed compiler.
///
/// See [`CompilerBuilder`] on how to create the compiler.
pub struct CollaborativeCircomCompiler<P: Pairing> {
    file: String,
    version: String,
    link_libraries: Vec<PathBuf>,
    phantom_data: PhantomData<P>,
    pub(crate) fun_decls: HashMap<String, FunDecl>,
    pub(crate) templ_decls: HashMap<String, TemplateDecl>,
    pub(crate) current_code_block: CodeBlock,
}

impl<P: Pairing> CompilerBuilder<P> {
    /// Creates a new instance of the [`CompilerBuilder`].
    ///
    /// Initializes the builder with no linked libraries and defaults to using circom version "2.0.0".
    ///
    /// # Arguments
    ///
    /// * `file` - The path to the circom file.
    pub fn new(file: String) -> Self {
        Self {
            file,
            version: DEFAULT_VERSION.to_owned(),
            link_libraries: vec![],
            phantom_data: PhantomData,
        }
    }

    /// Adds a folder to link during compilation. Call this method multiple times to add multiple folders.
    ///
    /// # Arguments
    ///
    /// * `link_library` - Something that implements `From<PathBuf>`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::path::PathBuf;
    /// # use circom_mpc_compiler::CompilerBuilder;
    /// # use ark_bn254::Bn254;
    ///
    /// let mut builder = CompilerBuilder::<Bn254>::new("/path/to/your/circom/file.circom".to_owned());
    ///
    /// // Add multiple libraries to link during compilation
    /// builder = builder.link_library(PathBuf::from("/path/to/library1"));
    /// builder = builder.link_library(PathBuf::from("/path/to/library2"));
    ///
    /// // Continue building the compiler...
    /// ```
    pub fn link_library<S>(mut self, link_library: S) -> Self
    where
        PathBuf: From<S>,
    {
        self.link_libraries.push(PathBuf::from(link_library));
        self
    }

    /// Consumes the builder and creates a new [CollaborativeCircomCompiler].
    pub fn build(self) -> CollaborativeCircomCompiler<P> {
        CollaborativeCircomCompiler {
            file: self.file,
            version: self.version,
            link_libraries: self.link_libraries,
            current_code_block: vec![],
            fun_decls: HashMap::new(),
            templ_decls: HashMap::new(),
            phantom_data: PhantomData,
        }
    }
}

impl<P: Pairing> CollaborativeCircomCompiler<P> {
    fn get_program_archive(&self) -> Result<ProgramArchive> {
        match circom_parser::run_parser(
            self.file.clone(),
            &self.version,
            self.link_libraries.clone(),
        ) {
            Ok((mut program_archive, warnings)) => {
                Report::print_reports(&warnings, &program_archive.file_library);
                match check_types::check_types(&mut program_archive) {
                    Ok(warnings) => {
                        Report::print_reports(&warnings, &program_archive.file_library);
                        Ok(program_archive)
                    }
                    Err(errors) => {
                        Report::print_reports(&errors, &program_archive.file_library);
                        bail!("Error during type checking");
                    }
                }
            }
            Err((file_lib, errors)) => {
                Report::print_reports(&errors, &file_lib);
                bail!("Error during compilation");
            }
        }
    }

    fn build_circuit(&self, program_archive: ProgramArchive) -> Result<CircomCircuit> {
        let build_config = BuildConfig {
            no_rounds: usize::MAX, //simplification_style. Use default from their lib
            flag_json_sub: false,
            json_substitutions: String::new(),
            flag_s: false,
            flag_f: false,
            flag_p: false,
            flag_verbose: false,
            flag_old_heuristics: false,
            inspect_constraints: false,
            prime: "bn128".to_owned(),
        };
        let (_, vcp) = circom_constraint_generation::build_circuit(program_archive, build_config)
            .map_err(|_| eyre!("cannot build vcp"))?;
        let flags = CompilationFlags {
            main_inputs_log: false,
            wat_flag: false,
        };
        Ok(CircomCircuit::build(vcp, flags, &self.version))
    }

    fn emit_store_opcodes(
        &mut self,
        location_rule: &LocationRule,
        dest_addr: &AddressType,
        context_size: usize,
    ) {
        let (mapped, signal_code) = match location_rule {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                self.handle_instruction(location);
                (false, 0)
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => {
                debug_assert!(*signal_code > 0);
                indexes
                    .iter()
                    .for_each(|inst| self.handle_instruction(inst));
                (true, *signal_code)
            }
        };
        match dest_addr {
            AddressType::Variable => self
                .current_code_block
                .push(MpcOpCode::StoreVars(context_size)),
            AddressType::Signal => self
                .current_code_block
                .push(MpcOpCode::StoreSignals(context_size)),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value: _,
                is_output,
                input_information: _,
            } => {
                debug_assert!(!is_output);
                self.handle_instruction(cmp_address);
                self.emit_opcode(MpcOpCode::InputSubComp(mapped, signal_code, context_size));
            }
        }
    }

    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) {
        self.handle_instruction(&store_bucket.src);
        self.emit_store_opcodes(
            &store_bucket.dest,
            &store_bucket.dest_address_type,
            store_bucket.context.size,
        );
    }

    #[inline(always)]
    fn emit_opcode(&mut self, op_code: MpcOpCode) {
        self.current_code_block.push(op_code);
    }

    #[inline(always)]
    fn add_code_block(&mut self, code_block: CodeBlock) {
        self.current_code_block.extend(code_block);
    }

    #[inline(always)]
    fn handle_inner_body(&mut self, instr_list: &InstructionList) -> CodeBlock {
        let mut inner_block = CodeBlock::default();
        std::mem::swap(&mut inner_block, &mut self.current_code_block);
        instr_list
            .iter()
            .for_each(|inst| self.handle_instruction(inst));
        std::mem::swap(&mut inner_block, &mut self.current_code_block);
        inner_block
    }

    fn handle_compute_bucket(&mut self, compute_bucket: &ComputeBucket) {
        //load stack
        compute_bucket.stack.iter().for_each(|inst| {
            self.handle_instruction(inst);
        });

        match compute_bucket.op {
            OperatorType::Add => self.emit_opcode(MpcOpCode::Add),
            OperatorType::Sub => self.emit_opcode(MpcOpCode::Sub),
            OperatorType::Mul => self.emit_opcode(MpcOpCode::Mul),
            OperatorType::Div => self.emit_opcode(MpcOpCode::Div),
            OperatorType::Pow => self.emit_opcode(MpcOpCode::Pow),
            OperatorType::IntDiv => self.emit_opcode(MpcOpCode::IntDiv),
            OperatorType::Mod => self.emit_opcode(MpcOpCode::Mod),
            OperatorType::ShiftL => self.emit_opcode(MpcOpCode::ShiftL),
            OperatorType::ShiftR => self.emit_opcode(MpcOpCode::ShiftR),
            OperatorType::LesserEq => self.emit_opcode(MpcOpCode::Le),
            OperatorType::GreaterEq => self.emit_opcode(MpcOpCode::Ge),
            OperatorType::Lesser => self.emit_opcode(MpcOpCode::Lt),
            OperatorType::Greater => self.emit_opcode(MpcOpCode::Gt),
            OperatorType::Eq(size) => {
                assert_ne!(size, 0);
                self.emit_opcode(MpcOpCode::Eq);
            }
            OperatorType::NotEq => self.emit_opcode(MpcOpCode::Neq),
            OperatorType::BoolOr => self.emit_opcode(MpcOpCode::BoolOr),
            OperatorType::BoolAnd => self.emit_opcode(MpcOpCode::BoolAnd),
            OperatorType::BitOr => self.emit_opcode(MpcOpCode::BitOr),
            OperatorType::BitAnd => self.emit_opcode(MpcOpCode::BitAnd),
            OperatorType::BitXor => self.emit_opcode(MpcOpCode::BitXOr),
            OperatorType::PrefixSub => self.emit_opcode(MpcOpCode::Neg),
            OperatorType::BoolNot => todo!(),
            OperatorType::Complement => todo!(),
            OperatorType::ToAddress => {
                self.emit_opcode(MpcOpCode::ToIndex);
            }
            OperatorType::MulAddress => {
                self.emit_opcode(MpcOpCode::MulIndex);
            }
            OperatorType::AddAddress => {
                self.emit_opcode(MpcOpCode::AddIndex);
            }
        }
    }

    #[allow(dead_code)]
    fn debug_code_block(&self) {
        for (idx, op) in self.current_code_block.iter().enumerate() {
            println!("{idx:0>3}|    {op}");
        }
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket) {
        //TODO ContextSize > 1
        let context_size = load_bucket.context.size;
        //first eject for src
        let (mapped, signal_code) = match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                self.handle_instruction(location);
                (false, 0)
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => {
                if indexes.is_empty() {
                    // Just push 0 to signal that it is the first signal of the component
                    // I am not sure if this is correct for all cases, so maybe investigate
                    // this further
                    self.emit_opcode(MpcOpCode::PushIndex(0));
                } else {
                    indexes
                        .iter()
                        .for_each(|inst| self.handle_instruction(inst));
                }
                (true, *signal_code)
            }
        };
        match &load_bucket.address_type {
            AddressType::Variable => self
                .current_code_block
                .push(MpcOpCode::LoadVars(context_size)),
            AddressType::Signal => self
                .current_code_block
                .push(MpcOpCode::LoadSignals(context_size)),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value: _,
                is_output: _,
                input_information: _,
            } => {
                self.handle_instruction(cmp_address);
                self.emit_opcode(MpcOpCode::OutputSubComp(mapped, signal_code, context_size));
            }
        }
    }

    fn handle_create_cmp_bucket(&mut self, create_cmp_bucket: &CreateCmpBucket) {
        self.emit_opcode(MpcOpCode::PushIndex(create_cmp_bucket.signal_offset));
        self.emit_opcode(MpcOpCode::PushIndex(create_cmp_bucket.signal_offset_jump));
        self.emit_opcode(MpcOpCode::CreateCmp(
            create_cmp_bucket.symbol.clone(),
            create_cmp_bucket.number_of_cmp,
        ));
    }

    fn handle_loop_bucket(&mut self, loop_bucket: &LoopBucket) {
        let start_condition = self.current_code_block.len();
        self.handle_instruction(&loop_bucket.continue_condition);
        let predicate_len = self.current_code_block.len() - start_condition;
        let mut body_code_block = self.handle_inner_body(&loop_bucket.body);
        let body_len = body_code_block.len();
        body_code_block.push(MpcOpCode::JumpBack(body_len + predicate_len + 1));
        self.emit_opcode(MpcOpCode::JumpIfFalse(body_len + 2));
        self.current_code_block.append(&mut body_code_block);
    }

    fn handle_branch_bucket(&mut self, branch_bucket: &BranchBucket) {
        let has_else_branch = !branch_bucket.else_branch.is_empty();
        self.handle_instruction(&branch_bucket.cond);
        let truthy_block = self.handle_inner_body(&branch_bucket.if_branch);
        self.emit_opcode(MpcOpCode::If(truthy_block.len() + 2));
        self.add_code_block(truthy_block);
        if has_else_branch {
            let falsy_block = self.handle_inner_body(&branch_bucket.else_branch);
            let falsy_end = falsy_block.len() + 2;
            self.emit_opcode(MpcOpCode::EndTruthyBranch(falsy_end));
            self.add_code_block(falsy_block);
            self.emit_opcode(MpcOpCode::EndFalsyBranch);
        } else {
            self.emit_opcode(MpcOpCode::EndTruthyBranch(0));
        }
    }

    fn handle_assert_bucket(&mut self, assert_bucket: &AssertBucket) {
        //evaluate the assertion
        self.handle_instruction(&assert_bucket.evaluate);
        self.emit_opcode(MpcOpCode::Assert(assert_bucket.line));
    }

    fn handle_return_bucket(&mut self, return_bucket: &ReturnBucket) {
        if return_bucket.with_size == 1 {
            self.handle_instruction(&return_bucket.value);
            self.emit_opcode(MpcOpCode::ReturnFun);
        } else {
            //unwrap the return value instruction and get the index
            if let Instruction::Load(load_bucket) = &*return_bucket.value {
                if let LocationRule::Indexed {
                    location,
                    template_header: _,
                } = &load_bucket.src
                {
                    let inner: &Instruction = location;
                    if let Instruction::Value(value_bucket) = inner {
                        debug_assert!(matches!(value_bucket.parse_as, ValueType::U32));
                        self.emit_opcode(MpcOpCode::PushIndex(value_bucket.value));
                        self.emit_opcode(MpcOpCode::ReturnFun);
                    } else {
                        panic!("Another way for multiple return vals???");
                    }
                } else {
                    panic!("Another way for multiple return vals???");
                }
            } else {
                panic!("Another way for multiple return vals???");
            }
        }
    }

    fn handle_call_bucket(&mut self, call_bucket: &CallBucket) {
        call_bucket
            .arguments
            .iter()
            .enumerate()
            .for_each(|(idx, inst)| {
                let arg_size = call_bucket.argument_types[idx].size;
                self.handle_instruction(inst);
                if arg_size > 1 {
                    //replace Load{Var/Signal} with with respective MultiOpCode
                    let last_instruction = self.current_code_block.pop().expect("is not empty");
                    //self.emit_opcode(MpcOpCode::PushIndex(arg_size));
                    //TODO CLEAN UP
                    match last_instruction {
                        MpcOpCode::LoadVars(amount) => {
                            debug_assert_eq!(arg_size, amount);
                            self.emit_opcode(MpcOpCode::LoadVars(amount))
                        }
                        MpcOpCode::LoadSignals(amount) => {
                            debug_assert_eq!(arg_size, amount);
                            self.emit_opcode(MpcOpCode::LoadSignals(amount))
                        }
                        MpcOpCode::PushConstant(idx) => {
                            for i in 0..arg_size {
                                self.emit_opcode(MpcOpCode::PushConstant(idx + i));
                            }
                        }
                        x => unreachable!("last instruction for loading multi params is {x}?"),
                    }
                }
            });
        match &call_bucket.return_info {
            ReturnType::Intermediate { op_aux_no: _ } => todo!(),
            ReturnType::Final(final_data) => {
                if final_data.context.size == 1 {
                    self.emit_opcode(MpcOpCode::Call(call_bucket.symbol.clone(), 1));
                    self.emit_store_opcodes(&final_data.dest, &final_data.dest_address_type, 1);
                } else {
                    match &final_data.dest {
                        LocationRule::Indexed {
                            location,
                            template_header: _,
                        } => {
                            let inner: &Instruction = location;
                            if let Instruction::Value(value_bucket) = inner {
                                self.emit_opcode(MpcOpCode::Call(
                                    call_bucket.symbol.clone(),
                                    final_data.context.size,
                                ));
                                debug_assert!(matches!(value_bucket.parse_as, ValueType::U32));
                                self.emit_opcode(MpcOpCode::PushIndex(value_bucket.value));
                            } else {
                                panic!("Another way for multiple return vals???");
                            }
                        }
                        LocationRule::Mapped {
                            signal_code: _,
                            indexes: _,
                        } => {
                            todo!();
                        }
                    };
                    match &final_data.dest_address_type {
                        AddressType::Variable => {
                            self.emit_opcode(MpcOpCode::StoreVars(final_data.context.size))
                        }
                        AddressType::Signal => {
                            self.emit_opcode(MpcOpCode::StoreSignals(final_data.context.size))
                        }
                        AddressType::SubcmpSignal {
                            cmp_address: _,
                            uniform_parallel_value: _,
                            is_output: _,
                            input_information: _,
                        } => {
                            todo!()
                        }
                    }
                }
            }
        }
    }

    fn handle_log_bucket(&mut self, log_bucket: &LogBucket) {
        for to_log in log_bucket.argsprint.iter() {
            match &to_log {
                LogBucketArg::LogExp(log_expr) => {
                    self.handle_instruction(log_expr);
                    self.emit_opcode(MpcOpCode::Log);
                }
                LogBucketArg::LogStr(idx) => {
                    self.emit_opcode(MpcOpCode::LogString(*idx));
                }
            }
        }
        self.emit_opcode(MpcOpCode::LogFlush(log_bucket.line));
    }

    fn handle_value_bucket(&mut self, value_bucket: &ValueBucket) {
        let index = value_bucket.value;
        match value_bucket.parse_as {
            ValueType::BigInt => self.emit_opcode(MpcOpCode::PushConstant(index)),
            ValueType::U32 => self.emit_opcode(MpcOpCode::PushIndex(index)),
        }
    }

    fn handle_instruction(&mut self, inst: &Instruction) {
        match inst {
            Instruction::Value(value_bucket) => self.handle_value_bucket(value_bucket),
            Instruction::Load(load_bucket) => self.handle_load_bucket(load_bucket),
            Instruction::Store(store_bucket) => self.handle_store_bucket(store_bucket),
            Instruction::Compute(compute_bucket) => self.handle_compute_bucket(compute_bucket),
            Instruction::Call(call_bucket) => self.handle_call_bucket(call_bucket),
            Instruction::Branch(branch_bucket) => self.handle_branch_bucket(branch_bucket),
            Instruction::Return(return_bucket) => self.handle_return_bucket(return_bucket),
            Instruction::Assert(assert_bucket) => self.handle_assert_bucket(assert_bucket),
            Instruction::Log(log_bucket) => self.handle_log_bucket(log_bucket),
            Instruction::Loop(loop_bucket) => self.handle_loop_bucket(loop_bucket),
            Instruction::CreateCmp(create_cmp_bucket) => {
                self.handle_create_cmp_bucket(create_cmp_bucket)
            }
        }
    }

    /// Consumes the [`CollaborativeCircomCompiler`] and returns a `Result<Vec<String>>`
    /// containing all public inputs from the provided .circom file.
    ///
    /// This method is useful when secret-sharing the input.
    ///
    /// # Returns
    ///
    /// Returns a `Result` where:
    ///
    /// - `Ok(inputs)` contains a vector of public inputs as strings.
    /// - `Err(err)` indicates an error occurred during parsing or compilation.
    pub fn get_public_inputs(self) -> Result<Vec<String>> {
        let program_archive = self.get_program_archive()?;
        Ok(program_archive.public_inputs)
    }

    /// Consumes the [`CollaborativeCircomCompiler`] and returns a `Result` of [`CollaborativeCircomCompilerParsed`].
    ///
    /// # Returns
    ///
    /// Returns a `Result` where:
    ///
    /// - `Ok(parsed)` contains the parsed compiler, which can be used to construct the MPC-VM.
    ///   Refer to its [documentation](CollaborativeCircomCompilerParsed) for usage details.
    /// - `Err(err)` indicates an error occurred during parsing or compilation.
    pub fn parse(mut self) -> Result<CollaborativeCircomCompilerParsed<P>> {
        let program_archive = self.get_program_archive()?;
        let circuit = self.build_circuit(program_archive)?;
        let constant_table = circuit
            .c_producer
            .get_field_constant_list()
            .iter()
            .map(|s| s.parse::<P::ScalarField>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| eyre!("cannot parse string in constant list"))?;
        let string_table = circuit.c_producer.get_string_table().to_owned();
        //build functions
        for fun in circuit.functions.iter() {
            fun.body.iter().for_each(|inst| {
                self.handle_instruction(inst);
            });
            //this opcode will only execute if we have a function
            //with an shared if condition and no other return vals
            self.emit_opcode(MpcOpCode::ReturnSharedIfFun);
            let mut new_code_block = CodeBlock::default();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);

            let params_length = fun
                .params
                .iter()
                .map(|p| p.length.iter().product::<usize>())
                .sum::<usize>();
            self.fun_decls.insert(
                fun.header.clone(),
                FunDecl::new(params_length, fun.max_number_of_vars, new_code_block),
            );
        }
        for templ in circuit.templates.iter() {
            templ.body.iter().for_each(|inst| {
                self.handle_instruction(inst);
            });
            let mut new_code_block = CodeBlock::default();
            // self.debug_code_block();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);
            new_code_block.push(MpcOpCode::Return);
            //check if we need mapping for store bucket
            let mappings = if let Some(mappings) = circuit.c_producer.io_map.get(&templ.id) {
                mappings.iter().map(|m| m.offset).collect_vec()
            } else {
                vec![]
            };
            self.templ_decls.insert(
                templ.header.clone(),
                TemplateDecl::new(
                    templ.header.clone(),
                    templ.number_of_inputs,
                    templ.number_of_components,
                    templ.var_stack_depth,
                    mappings,
                    new_code_block,
                ),
            );
        }

        Ok(CollaborativeCircomCompilerParsed::new(
            circuit.c_producer.main_header,
            circuit.c_producer.total_number_of_signals,
            constant_table,
            string_table,
            self.fun_decls,
            self.templ_decls,
            circuit.c_producer.witness_to_signal_list,
            circuit.c_producer.number_of_main_inputs,
            circuit.c_producer.number_of_main_outputs,
            circuit.c_producer.main_input_list.clone(),
        ))
    }
}
