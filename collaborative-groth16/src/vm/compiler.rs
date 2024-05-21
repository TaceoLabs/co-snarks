use ark_ec::pairing::Pairing;
use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags},
    intermediate_representation::{
        self,
        ir_interface::{
            AddressType, AssertBucket, BranchBucket, ComputeBucket, CreateCmpBucket, Instruction,
            LoadBucket, LocationRule, LoopBucket, OperatorType, StoreBucket, ValueBucket,
            ValueType,
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
    LoadSignal(usize),
    StoreSignal(usize),
    LoadVar(usize),
    StoreVar(usize),
    OutputSubComp,
    InputSubComp,
    CreateCmp(String, Vec<usize>), //what else do we need?
    Return,
    Assert,
    Add,
    Sub,
    Mul,
    Div,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    MulIndex,
    AddIndex,
    ToIndex,
    Jump(usize),
    JumpIfFalse(usize),
    Panic(String),
}

impl std::fmt::Display for MpcOpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            MpcOpCode::PushConstant(constant_index) => {
                format!("PUSH_CONSTANT_OP {}", constant_index)
            }
            MpcOpCode::PushIndex(index) => format!("PUSH_INDEX_OP {}", index),
            MpcOpCode::LoadSignal(template_id) => format!("LOAD_SIGNAL_OP {}", template_id),
            MpcOpCode::StoreSignal(template_id) => format!("STORE_SIGNAL_OP {}", template_id),
            MpcOpCode::LoadVar(template_id) => format!("LOAD_VAR_OP {}", template_id),
            MpcOpCode::StoreVar(template_id) => format!("STORE_VAR_OP {}", template_id),
            MpcOpCode::CreateCmp(header, dims) => format!("CREATE_CMP_OP {} {:?}", header, dims),
            MpcOpCode::Assert => "ASSERT_OP".to_owned(),
            MpcOpCode::Add => "ADD_OP".to_owned(),
            MpcOpCode::Sub => "SUB_OP".to_owned(),
            MpcOpCode::Mul => "MUL_OP".to_owned(),
            MpcOpCode::Div => "DIV_OP".to_owned(),
            MpcOpCode::Lt => "LESS_THAN_OP".to_owned(),
            MpcOpCode::Le => "LESS_EQ_OP".to_owned(),
            MpcOpCode::Gt => "GREATER_THAN_OP".to_owned(),
            MpcOpCode::Ge => "GREATER_EQ_OP".to_owned(),
            MpcOpCode::Eq => "IS_EQUAL_OP".to_owned(),
            MpcOpCode::Ne => "NOT_EQUAL_OP".to_owned(),
            MpcOpCode::AddIndex => "ADD_INDEX_OP".to_owned(),
            MpcOpCode::MulIndex => "MUL_INDEX_OP".to_owned(),
            MpcOpCode::ToIndex => "TO_INDEX_OP".to_owned(),
            MpcOpCode::Jump(line) => format!("JUMP_OP {line}"),
            MpcOpCode::JumpIfFalse(line) => format!("JUMP_IF_FALSE_OP {line}"),
            MpcOpCode::Return => "RETURN_OP".to_owned(),
            MpcOpCode::Panic(message) => format!("PANIC_OP {message}"),
            MpcOpCode::OutputSubComp => "OUTPUT_SUB_COMP_OP".to_owned(),
            MpcOpCode::InputSubComp => "INPUT_SUB_COMP_OP".to_owned(),
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
            current_line_offset: 0,
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
    pub(crate) vars: usize,
    pub(crate) sub_comps: usize,
    pub(crate) body: Rc<CodeBlock>,
}

impl TemplateDecl {
    fn new(
        input_signals: usize,
        output_signals: usize,
        intermediate_signals: usize,
        vars: usize,
        sub_comps: usize,
        body: CodeBlock,
    ) -> Self {
        Self {
            input_signals,
            output_signals,
            intermediate_signals,
            vars,
            sub_comps,
            body: Rc::new(body),
        }
    }
}

pub struct CollaborativeCircomCompiler<P: Pairing> {
    file: String,
    version: String,
    link_libraries: Vec<PathBuf>,
    pub(crate) constant_table: Vec<P::ScalarField>,
    pub(crate) fun_decls: HashMap<String, CodeBlock>,
    pub(crate) templ_decls: HashMap<String, TemplateDecl>,
    pub(crate) current_code_block: CodeBlock,
    pub(crate) current_line_offset: usize,
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

    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) {
        self.handle_instruction(&store_bucket.src);
        match &store_bucket.dest {
            LocationRule::Indexed {
                location,
                template_header,
            } => {
                self.handle_instruction(location);
                if template_header.is_some() {
                    //TODO what do we do with the template header
                }
                //assert!(
                //    template_header.is_none(),
                //    "TODO template header is not none in load"
                //);
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => todo!(),
        }
        match &store_bucket.dest_address_type {
            AddressType::Variable => self
                .current_code_block
                .push(MpcOpCode::StoreVar(store_bucket.message_id)),
            AddressType::Signal => self
                .current_code_block
                .push(MpcOpCode::StoreSignal(store_bucket.message_id)),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value,
                is_output,
                input_information,
            } => {
                self.handle_instruction(cmp_address);
                self.emit_opcode(MpcOpCode::InputSubComp);

                //               println!("{}", store_bucket.to_string());
                //               println!();
                //               println!();
                //               println!("{}", cmp_address.to_string());
                //               println!("{:?}", uniform_parallel_value);
                //               println!("{}", is_output);
                //               match input_information {
                //                   InputInformation::NoInput => println!("no input"),
                //                   InputInformation::Input { status } => match status {
                //                       StatusInput::Last => println!("input last"),
                //                       StatusInput::NoLast => println!("input no last"),
                //                       StatusInput::Unknown => println!("unknown"),
                //                   },
                //               }
                //               println!();
                //               println!();
                //               println!("==================");
            }
        }
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
        let offset = self.current_code_block.len();
        self.current_line_offset += offset;
        std::mem::swap(&mut inner_block, &mut self.current_code_block);
        instr_list
            .iter()
            .for_each(|inst| self.handle_instruction(inst));
        self.current_line_offset -= offset;
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
            OperatorType::ShiftL => todo!(),
            OperatorType::ShiftR => todo!(),
            OperatorType::LesserEq => todo!(),
            OperatorType::GreaterEq => todo!(),
            OperatorType::Lesser => self.emit_opcode(MpcOpCode::Lt),
            OperatorType::Greater => todo!(),
            OperatorType::Eq(size) => {
                assert_ne!(size, 0);
                self.emit_opcode(MpcOpCode::Eq);
            }
            OperatorType::NotEq => todo!(),
            OperatorType::BoolOr => todo!(),
            OperatorType::BoolAnd => todo!(),
            OperatorType::BitOr => todo!(),
            OperatorType::BitAnd => todo!(),
            OperatorType::BitXor => todo!(),
            OperatorType::PrefixSub => todo!(),
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
                template_header,
            } => {
                self.handle_instruction(location);
                // assert!(
                //     template_header.is_none(),
                //     "TODO template header is not none in load"
                // );
            }
            LocationRule::Mapped {
                signal_code: _,
                indexes: _,
            } => todo!(),
        }
        match &load_bucket.address_type {
            AddressType::Variable => self
                .current_code_block
                .push(MpcOpCode::LoadVar(load_bucket.message_id)),
            AddressType::Signal => self
                .current_code_block
                .push(MpcOpCode::LoadSignal(load_bucket.message_id)),
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
            create_cmp_bucket.dimensions.clone(),
        ));
        //println!("{}", create_cmp_bucket.message_id);
        //println!("{}", create_cmp_bucket.template_id);
        //println!("{}", create_cmp_bucket.cmp_unique_id);
        //println!("{}", create_cmp_bucket.symbol);
        //println!("{}", create_cmp_bucket.sub_cmp_id.to_string());
        //println!("{}", create_cmp_bucket.name_subcomponent);
        //println!("{:?}", create_cmp_bucket.defined_positions);
        //println!("{:?}", create_cmp_bucket.dimensions);
        //println!("{:?}", create_cmp_bucket.signal_offset);
        //println!("{:?}", create_cmp_bucket.signal_offset_jump);
        //println!("{:?}", create_cmp_bucket.number_of_cmp);
        //println!("{:?}", create_cmp_bucket.has_inputs);
    }

    fn handle_loop_bucket(&mut self, loop_bucket: &LoopBucket) {
        let start_condition = self.current_line_offset + self.current_code_block.len();
        self.handle_instruction(&loop_bucket.continue_condition);

        //we need one extra offset because we will add a jump if false later
        //we don't know at this point where to jump though
        self.current_line_offset += 1;
        let mut body_code_block = self.handle_inner_body(&loop_bucket.body);
        body_code_block.push(MpcOpCode::Jump(start_condition));
        self.current_line_offset -= 1;

        self.emit_opcode(MpcOpCode::JumpIfFalse(
            self.current_line_offset + body_code_block.len() + self.current_code_block.len() + 1,
        ));
        self.current_code_block.append(&mut body_code_block);
    }

    fn handle_branch_bucket(&mut self, branch_bucket: &BranchBucket) {
        self.handle_instruction(&branch_bucket.cond);
        let truthy_block = self.handle_inner_body(&branch_bucket.if_branch);
        println!("current line offset is: {}", self.current_line_offset);
        let falsy_offset =
            self.current_line_offset + self.current_code_block.len() + truthy_block.len() + 2;
        self.emit_opcode(MpcOpCode::JumpIfFalse(falsy_offset));
        self.add_code_block(truthy_block);
        let falsy_block = self.handle_inner_body(&branch_bucket.else_branch);
        let falsy_end =
            self.current_line_offset + self.current_code_block.len() + falsy_block.len() + 1;
        self.emit_opcode(MpcOpCode::Jump(falsy_end));
        self.add_code_block(falsy_block);
        Self::debug_code_block(&self.current_code_block);
        println!();
        println!();
        println!();
    }

    fn handle_assert_bucket(&mut self, assert_bucket: &AssertBucket) {
        //evaluate the assertion
        self.handle_instruction(&assert_bucket.evaluate);
        self.emit_opcode(MpcOpCode::Assert);
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
            Instruction::Call(_call_bucket) => todo!(),
            Instruction::Branch(branch_bucket) => self.handle_branch_bucket(branch_bucket),
            Instruction::Return(_) => todo!(),
            Instruction::Assert(assert_bucket) => self.handle_assert_bucket(assert_bucket),
            Instruction::Log(log_bucket) => todo!(),
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
            self.fun_decls.insert(fun.header.clone(), new_code_block);
        }
        for templ in circuit.templates.iter() {
            println!("==============");
            println!("id      : {}", templ.id);
            println!("name    : {}", templ.name);
            println!("header  : {}", templ.header);
            println!("#ins    : {}", templ.number_of_inputs);
            println!("#outs   : {}", templ.number_of_outputs);
            println!("#inters : {}", templ.number_of_intermediates);
            println!("#cmps   : {}", templ.number_of_components);
            println!("#var    : {}", templ.var_stack_depth);
            println!("#expr   : {}", templ.expression_stack_depth);
            println!("#signal : {}", templ.signal_stack_depth);
            templ.body.iter().for_each(|inst| {
                self.handle_instruction(inst);
            });
            let mut new_code_block = CodeBlock::default();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);
            new_code_block.push(MpcOpCode::Return);
            Self::debug_code_block(&new_code_block);
            self.templ_decls.insert(
                templ.header.clone(),
                TemplateDecl::new(
                    templ.number_of_inputs,
                    templ.number_of_outputs,
                    templ.number_of_intermediates,
                    templ.var_stack_depth,
                    templ.number_of_components,
                    new_code_block,
                ),
            );
        }
        Ok(WitnessExtension::new(self, circuit.c_producer.main_header))
    }
}
