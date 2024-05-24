use ark_ec::pairing::Pairing;
use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags},
    hir::very_concrete_program::Param,
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
use circom_program_structure::{error_definition::Report, program_archive::ProgramArchive};
use circom_type_analysis::check_types;
use color_eyre::{
    eyre::{bail, eyre},
    Result,
};
use std::{collections::HashMap, marker::PhantomData, path::PathBuf, rc::Rc};

use super::WitnessExtension;

const DEFAULT_VERSION: &str = "2.0.0";

pub type CodeBlock = Vec<MpcOpCode>;
#[derive(Clone)]
pub enum MpcOpCode {
    PushConstant(usize),
    PushIndex(usize),
    LoadSignal,
    StoreSignal,
    LoadVar,
    LoadVars,
    StoreVars,
    StoreVar,
    OutputSubComp,
    InputSubComp(bool),
    CreateCmp(String, usize), //what else do we need?
    Call(String),
    Return,
    Assert,
    Add,
    Sub,
    Mul,
    Div,
    Neg,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    Neq,
    BoolOr,
    BoolAnd,
    BitOr,
    BitAnd,
    BitXOr,
    ShiftR,
    ShiftL,
    MulIndex,
    AddIndex,
    ToIndex,
    Jump(usize),
    JumpBack(usize),
    JumpIfFalse(usize),
    Panic(String),
    Log(usize, usize),
}

impl std::fmt::Display for MpcOpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            MpcOpCode::PushConstant(constant_index) => {
                format!("PUSH_CONSTANT_OP {}", constant_index)
            }
            MpcOpCode::PushIndex(index) => format!("PUSH_INDEX_OP {}", index),
            MpcOpCode::LoadSignal => "LOAD_SIGNAL_OP".to_owned(),
            MpcOpCode::StoreSignal => "STORE_SIGNAL_OP".to_owned(),
            MpcOpCode::LoadVar => "LOAD_VAR_OP".to_owned(),
            MpcOpCode::LoadVars => "LOAD_VARS_OP".to_owned(),
            MpcOpCode::StoreVar => "STORE_VAR_OP".to_owned(),
            MpcOpCode::StoreVars => "STORE_VARS_OP".to_owned(),
            MpcOpCode::Call(symbol) => format!("CALL_OP {symbol}"),
            MpcOpCode::CreateCmp(header, amount) => format!("CREATE_CMP_OP {} [{amount}]", header),
            MpcOpCode::Assert => "ASSERT_OP".to_owned(),
            MpcOpCode::Add => "ADD_OP".to_owned(),
            MpcOpCode::Sub => "SUB_OP".to_owned(),
            MpcOpCode::Mul => "MUL_OP".to_owned(),
            MpcOpCode::Div => "DIV_OP".to_owned(),
            MpcOpCode::Neg => "NEG_OP".to_owned(),
            MpcOpCode::Lt => "LESS_THAN_OP".to_owned(),
            MpcOpCode::Le => "LESS_EQ_OP".to_owned(),
            MpcOpCode::Gt => "GREATER_THAN_OP".to_owned(),
            MpcOpCode::Ge => "GREATER_EQ_OP".to_owned(),
            MpcOpCode::Eq => "IS_EQUAL_OP".to_owned(),
            MpcOpCode::Ne => "NOT_EQUAL_OP".to_owned(),
            MpcOpCode::Neq => "NOT_EQUAL_OP".to_owned(),
            MpcOpCode::BoolOr => "BOOL_OR_OP".to_owned(),
            MpcOpCode::BoolAnd => "BOOL_AND_OP".to_owned(),
            MpcOpCode::BitOr => "BIT_OR_OP".to_owned(),
            MpcOpCode::BitAnd => "BIT_AND_OP".to_owned(),
            MpcOpCode::BitXOr => "BIT_XOR_OP".to_owned(),
            MpcOpCode::ShiftR => "RIGHT_SHIFT_OP".to_owned(),
            MpcOpCode::ShiftL => "LEFT_SHIFT_OP".to_owned(),
            MpcOpCode::AddIndex => "ADD_INDEX_OP".to_owned(),
            MpcOpCode::MulIndex => "MUL_INDEX_OP".to_owned(),
            MpcOpCode::ToIndex => "TO_INDEX_OP".to_owned(),
            MpcOpCode::Jump(line) => format!("JUMP_OP {line}"),
            MpcOpCode::JumpBack(line) => format!("JUMP_BACK_OP {line}"),
            MpcOpCode::JumpIfFalse(line) => format!("JUMP_IF_FALSE_OP {line}"),
            MpcOpCode::Return => "RETURN_OP".to_owned(),
            MpcOpCode::Panic(message) => format!("PANIC_OP {message}"),
            MpcOpCode::OutputSubComp => "OUTPUT_SUB_COMP_OP".to_owned(),
            MpcOpCode::InputSubComp(true) => "INPUT_SUB_COMP_MAPPED_OP".to_owned(),
            MpcOpCode::InputSubComp(false) => "INPUT_SUB_COMP_OP".to_owned(),
            MpcOpCode::Log(line, amount) => format!("LOG {line} {amount}"),
        };
        f.write_str(&string)
    }
}

pub struct CompilerBuilder<P: Pairing> {
    file: String,
    version: String,
    link_libraries: Vec<PathBuf>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> CompilerBuilder<P> {
    pub fn new(file: String) -> Self {
        Self {
            file,
            version: DEFAULT_VERSION.to_owned(),
            link_libraries: vec![],
            phantom_data: PhantomData,
        }
    }

    pub fn link_libraries(mut self, link_libraries: Vec<PathBuf>) -> Self {
        self.link_libraries = link_libraries;
        self
    }

    pub fn link_library<S>(mut self, link_library: S) -> Self
    where
        PathBuf: From<S>,
    {
        self.link_libraries.push(PathBuf::from(link_library));
        self
    }

    pub fn build(self) -> CollaborativeCircomCompiler<P> {
        CollaborativeCircomCompiler {
            file: self.file,
            version: self.version,
            link_libraries: self.link_libraries,
            constant_table: vec![],
            current_code_block: vec![],
            fun_decls: HashMap::new(),
            templ_decls: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct TemplateDecl {
    pub(crate) input_signals: usize,
    pub(crate) output_signals: usize,
    pub(crate) intermediate_signals: usize,
    pub(crate) sub_components: usize,
    pub(crate) vars: usize,
    pub(crate) body: Rc<CodeBlock>,
}

pub(crate) struct FunDecl {
    pub(crate) params: Vec<Param>,
    pub(crate) vars: usize,
    pub(crate) body: Rc<CodeBlock>,
}

impl FunDecl {
    fn new(params: Vec<Param>, vars: usize, body: CodeBlock) -> Self {
        Self {
            params,
            vars,
            body: Rc::new(body),
        }
    }
}

impl TemplateDecl {
    fn new(
        input_signals: usize,
        output_signals: usize,
        intermediate_signals: usize,
        sub_components: usize,
        vars: usize,
        body: CodeBlock,
    ) -> Self {
        Self {
            input_signals,
            output_signals,
            intermediate_signals,
            sub_components,
            vars,
            body: Rc::new(body),
        }
    }
}

pub struct CollaborativeCircomCompiler<P: Pairing> {
    file: String,
    version: String,
    link_libraries: Vec<PathBuf>,
    pub(crate) constant_table: Vec<P::ScalarField>,
    pub(crate) fun_decls: HashMap<String, FunDecl>,
    pub(crate) templ_decls: HashMap<String, TemplateDecl>,
    pub(crate) current_code_block: CodeBlock,
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

    fn emit_store_opcodes(&mut self, location_rule: &LocationRule, dest_addr: &AddressType) {
        let mapped = match location_rule {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                self.handle_instruction(location);
                false
                //What do we do with the template header??
            }
            LocationRule::Mapped {
                signal_code: _,
                indexes,
            } => {
                indexes
                    .iter()
                    .for_each(|inst| self.handle_instruction(inst));
                true
            }
        };
        match dest_addr {
            AddressType::Variable => self.current_code_block.push(MpcOpCode::StoreVar),
            AddressType::Signal => self.current_code_block.push(MpcOpCode::StoreSignal),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value: _,
                is_output,
                input_information: _,
            } => {
                debug_assert!(!is_output);
                self.handle_instruction(cmp_address);
                self.emit_opcode(MpcOpCode::InputSubComp(mapped));
                //There are a lot of additional information for this arm
                //For the time being it works but maybe we need some information
                //for more complex problems
            }
        }
    }

    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) {
        self.handle_instruction(&store_bucket.src);
        self.emit_store_opcodes(&store_bucket.dest, &store_bucket.dest_address_type);
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
            OperatorType::Pow => todo!(),
            OperatorType::IntDiv => todo!(),
            OperatorType::Mod => todo!(),
            OperatorType::ShiftL => self.emit_opcode(MpcOpCode::ShiftL),
            OperatorType::ShiftR => self.emit_opcode(MpcOpCode::ShiftR),
            OperatorType::LesserEq => todo!(),
            OperatorType::GreaterEq => todo!(),
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
    fn debug_code_block(code_block: &CodeBlock) {
        for (idx, op) in code_block.iter().enumerate() {
            println!("{idx}|    {op}");
        }
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket) {
        //first eject for src
        match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                self.handle_instruction(location);
            }
            LocationRule::Mapped {
                signal_code: _,
                indexes,
            } => {
                indexes
                    .iter()
                    .for_each(|inst| self.handle_instruction(inst));
            }
        }
        match &load_bucket.address_type {
            AddressType::Variable => self.current_code_block.push(MpcOpCode::LoadVar),
            AddressType::Signal => self.current_code_block.push(MpcOpCode::LoadSignal),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value: _,
                is_output: _,
                input_information: _,
            } => {
                self.handle_instruction(cmp_address);
                self.emit_opcode(MpcOpCode::OutputSubComp);
            }
        }
    }

    fn handle_create_cmp_bucket(&mut self, create_cmp_bucket: &CreateCmpBucket) {
        //get the id:
        self.handle_instruction(&create_cmp_bucket.sub_cmp_id);
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
        let falsy_offset = if has_else_branch {
            truthy_block.len() + 2
        } else {
            truthy_block.len() + 1
        };
        self.emit_opcode(MpcOpCode::JumpIfFalse(falsy_offset));
        self.add_code_block(truthy_block);
        if has_else_branch {
            let falsy_block = self.handle_inner_body(&branch_bucket.else_branch);
            let falsy_end = falsy_block.len() + 1;
            self.emit_opcode(MpcOpCode::Jump(falsy_end));
            self.add_code_block(falsy_block);
        }
    }

    fn handle_assert_bucket(&mut self, assert_bucket: &AssertBucket) {
        //evaluate the assertion
        self.handle_instruction(&assert_bucket.evaluate);
        self.emit_opcode(MpcOpCode::Assert);
    }

    fn handle_return_bucket(&mut self, return_bucket: &ReturnBucket) {
        if return_bucket.with_size == 1 {
            self.handle_instruction(&return_bucket.value);
            self.emit_opcode(MpcOpCode::Return);
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
                        self.emit_opcode(MpcOpCode::PushIndex(
                            value_bucket.value + return_bucket.with_size,
                        ));
                        self.emit_opcode(MpcOpCode::PushIndex(value_bucket.value));
                        self.emit_opcode(MpcOpCode::LoadVars);
                        self.emit_opcode(MpcOpCode::Return);
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
        //todo check what argument types mean
        call_bucket
            .arguments
            .iter()
            .for_each(|inst| self.handle_instruction(inst));
        self.emit_opcode(MpcOpCode::Call(call_bucket.symbol.clone()));
        match &call_bucket.return_info {
            ReturnType::Intermediate { op_aux_no: _ } => todo!(),
            ReturnType::Final(final_data) => {
                if final_data.context.size == 1 {
                    self.emit_store_opcodes(&final_data.dest, &final_data.dest_address_type);
                } else {
                    match &final_data.dest {
                        LocationRule::Indexed {
                            location,
                            template_header: _,
                        } => {
                            let inner: &Instruction = location;
                            if let Instruction::Value(value_bucket) = inner {
                                debug_assert!(matches!(value_bucket.parse_as, ValueType::U32));
                                self.emit_opcode(MpcOpCode::PushIndex(final_data.context.size));
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
                        AddressType::Variable => self.emit_opcode(MpcOpCode::StoreVars),
                        AddressType::Signal => todo!(),
                        AddressType::SubcmpSignal {
                            cmp_address: _,
                            uniform_parallel_value: _,
                            is_output: _,
                            input_information: _,
                        } => {
                            todo!()
                            //debug_assert!(!is_output);
                            //self.handle_instruction(cmp_address);
                            //self.emit_opcode(MpcOpCode::InputSubComp(mapped));
                            //There are a lot of additional information for this arm
                            //For the time being it works but maybe we need some information
                            //for more complex problems
                        }
                    }
                }
            }
        }
    }

    fn handle_log_bucket(&mut self, log_bucket: &LogBucket) {
        //todo
        for to_log in log_bucket.argsprint.iter() {
            match &to_log {
                LogBucketArg::LogExp(log_expr) => self.handle_instruction(log_expr),
                LogBucketArg::LogStr(_) => {
                    todo!()
                }
            }
        }
        self.emit_opcode(MpcOpCode::Log(log_bucket.line, log_bucket.argsprint.len()))
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

    pub fn parse(mut self) -> Result<WitnessExtension<P>> {
        let program_archive = self.get_program_archive()?;
        let circuit = self.build_circuit(program_archive)?;
        self.constant_table = circuit
            .c_producer
            .get_field_constant_list()
            .iter()
            .map(|s| s.parse::<P::ScalarField>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| eyre!("cannot parse string in constant list"))?;

        //build functions
        for fun in circuit.functions.iter() {
            fun.body.iter().for_each(|inst| {
                self.handle_instruction(inst);
            });
            let mut new_code_block = CodeBlock::default();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);
            self.fun_decls.insert(
                fun.header.clone(),
                FunDecl::new(fun.params.clone(), fun.max_number_of_vars, new_code_block),
            );
        }
        for templ in circuit.templates.iter() {
            templ.body.iter().for_each(|inst| {
                self.handle_instruction(inst);
            });
            let mut new_code_block = CodeBlock::default();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);
            new_code_block.push(MpcOpCode::Return);
            self.templ_decls.insert(
                templ.header.clone(),
                TemplateDecl::new(
                    templ.number_of_inputs,
                    templ.number_of_outputs,
                    templ.number_of_intermediates,
                    templ.number_of_components,
                    templ.var_stack_depth,
                    new_code_block,
                ),
            );
        }
        Ok(WitnessExtension::new(self, circuit.c_producer.main_header))
    }
}
