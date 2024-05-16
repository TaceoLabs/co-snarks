use ark_ec::pairing::Pairing;
use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags},
    intermediate_representation::ir_interface::{
        AddressType, ComputeBucket, CreateCmpBucket, InputInformation, Instruction, LoadBucket,
        LocationRule, LoopBucket, OperatorType, StatusInput, StoreBucket, ValueBucket, ValueType,
    },
};
use circom_constraint_generation::BuildConfig;
use circom_program_structure::{
    error_definition::{Report, ReportCollection},
    file_definition::FileLibrary,
    program_archive::{self, ProgramArchive},
};
use circom_type_analysis::check_types;
use mpc_core::traits::PrimeFieldMpcProtocol;
use serde::de::value;
use std::{collections::HashMap, fmt::format, marker::PhantomData, path::PathBuf};

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
    CreateCmp(String, Vec<usize>), //what else do we need?
    PushStackFrame,
    PopStackFrame,
    Return,
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
    Jump(usize),
    JumpIfFalse(usize),
    Panic(String),
}

impl ToString for MpcOpCode {
    fn to_string(&self) -> String {
        match self {
            MpcOpCode::PushConstant(constant_index) => {
                format!("PUSH_CONSTANT_OP {}", constant_index)
            }
            MpcOpCode::PushIndex(index) => format!("PUSH_INDEX_OP {}", index),
            MpcOpCode::LoadSignal(template_id) => format!("LOAD_SIGNAL_OP {}", template_id),
            MpcOpCode::StoreSignal(template_id) => format!("STORE_SIGNAL_OP {}", template_id),
            MpcOpCode::LoadVar(template_id) => format!("LOAD_VAR_OP {}", template_id),
            MpcOpCode::StoreVar(template_id) => format!("STORE_VAR_OP {}", template_id),
            MpcOpCode::CreateCmp(header, dims) => format!("CREATE_CMP_OP {} {:?}", header, dims),
            MpcOpCode::PushStackFrame => "PUSH_STACK_FRAME_OP".to_owned(),
            MpcOpCode::PopStackFrame => "POP_STACK_FRAME_OP".to_owned(),
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
            MpcOpCode::Jump(line) => format!("JUMP_OP {line}"),
            MpcOpCode::JumpIfFalse(line) => format!("JUMP_IF_FALSE_OP {line}"),
            MpcOpCode::Return => "RETURN_OP".to_owned(),
            MpcOpCode::Panic(message) => format!("PANIC_OP {message}"),
        }
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

    pub fn build(self) -> CollaborativeCircomCompiler<P> {
        CollaborativeCircomCompiler {
            file: self.file,
            version: self.version,
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
    pub(crate) vars: usize,
    pub(crate) sub_comps: usize,
    pub(crate) body: CodeBlock,
}

impl TemplateDecl {
    fn new(
        input_signals: usize,
        output_signals: usize,
        vars: usize,
        sub_comps: usize,
        body: CodeBlock,
    ) -> Self {
        Self {
            input_signals,
            output_signals,
            vars,
            sub_comps,
            body,
        }
    }
}

pub struct CollaborativeCircomCompiler<P: Pairing> {
    file: String,
    version: String,
    pub(crate) constant_table: Vec<P::ScalarField>,
    pub(crate) fun_decls: HashMap<String, CodeBlock>,
    pub(crate) templ_decls: HashMap<String, TemplateDecl>,
    pub(crate) current_code_block: CodeBlock,
}

impl<P: Pairing> CollaborativeCircomCompiler<P> {
    fn get_program_archive(&self) -> Result<ProgramArchive, ()> {
        match circom_parser::run_parser(self.file.clone(), &self.version, vec![]) {
            Ok((mut program_archive, warnings)) => {
                Report::print_reports(&warnings, &program_archive.file_library);
                match check_types::check_types(&mut program_archive) {
                    Ok(warnings) => {
                        Report::print_reports(&warnings, &program_archive.file_library);
                        Ok(program_archive)
                    }
                    Err(errors) => {
                        Report::print_reports(&errors, &program_archive.file_library);
                        Err(())
                    }
                }
            }
            Err((file_lib, errors)) => {
                Report::print_reports(&errors, &file_lib);
                Err(())
            }
        }
    }

    fn build_circuit(&self, program_archive: ProgramArchive) -> Result<CircomCircuit, ()> {
        let build_config = BuildConfig {
            no_rounds: usize::MAX, //simplification_style. Use default
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
        let (_, vcp) = circom_constraint_generation::build_circuit(program_archive, build_config)?;
        let flags = CompilationFlags {
            main_inputs_log: false,
            wat_flag: false,
        };
        Ok(CircomCircuit::build(vcp, flags, &self.version))
    }

    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) {
        self.eject_mpc_opcode(&store_bucket.src);
        match &store_bucket.dest {
            LocationRule::Indexed {
                location,
                template_header,
            } => {
                self.eject_mpc_opcode(location);
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
                self.current_code_block
                    .push(MpcOpCode::Panic("TODO".to_owned()));
                println!("{}", store_bucket.to_string());
                println!("{}", cmp_address.to_string());
                println!("{:?}", uniform_parallel_value);
                println!("{}", is_output);
                match input_information {
                    InputInformation::NoInput => println!("no input"),
                    InputInformation::Input { status } => match status {
                        StatusInput::Last => println!("input last"),
                        StatusInput::NoLast => println!("input no last"),
                        StatusInput::Unknown => println!("unknown"),
                    },
                }
                println!();
                println!();
            }
        }
    }

    fn handle_compute_bucket(&mut self, compute_bucket: &ComputeBucket) {
        //load stack
        compute_bucket.stack.iter().for_each(|inst| {
            self.eject_mpc_opcode(inst);
        });
        match compute_bucket.op {
            OperatorType::Add => self.current_code_block.push(MpcOpCode::Add),
            OperatorType::Sub => todo!(),
            OperatorType::Mul => self.current_code_block.push(MpcOpCode::Mul),
            OperatorType::Div => todo!(),
            OperatorType::Pow => todo!(),
            OperatorType::IntDiv => todo!(),
            OperatorType::Mod => todo!(),
            OperatorType::ShiftL => todo!(),
            OperatorType::ShiftR => todo!(),
            OperatorType::LesserEq => todo!(),
            OperatorType::GreaterEq => todo!(),
            OperatorType::Lesser => self.current_code_block.push(MpcOpCode::Lt),
            OperatorType::Greater => todo!(),
            OperatorType::Eq(_) => todo!(),
            OperatorType::NotEq => todo!(),
            OperatorType::BoolOr => todo!(),
            OperatorType::BoolAnd => todo!(),
            OperatorType::BitOr => todo!(),
            OperatorType::BitAnd => todo!(),
            OperatorType::BitXor => todo!(),
            OperatorType::PrefixSub => todo!(),
            OperatorType::BoolNot => todo!(),
            OperatorType::Complement => todo!(),
            OperatorType::ToAddress => self
                .current_code_block
                .push(MpcOpCode::Panic("TODO".to_owned())),
            OperatorType::MulAddress => self
                .current_code_block
                .push(MpcOpCode::Panic("TODO".to_owned())),
            OperatorType::AddAddress => self
                .current_code_block
                .push(MpcOpCode::Panic("TODO".to_owned())),
        }
    }

    fn debug_code_block(code_block: &CodeBlock) {
        for (idx, op) in code_block.iter().enumerate() {
            println!("{idx}|    {}", op.to_string());
        }
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket) {
        //first eject for src
        match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header,
            } => {
                self.eject_mpc_opcode(location);
                // assert!(
                //     template_header.is_none(),
                //     "TODO template header is not none in load"
                // );
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
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
                uniform_parallel_value,
                is_output,
                input_information,
            } => self
                .current_code_block
                .push(MpcOpCode::Panic("TODO".to_owned())),
        }
    }

    fn handle_create_cmp_bucket(&mut self, create_cmp_bucket: &CreateCmpBucket) {
        //get the id:
        self.eject_mpc_opcode(&create_cmp_bucket.sub_cmp_id);
        self.current_code_block.push(MpcOpCode::CreateCmp(
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
        self.current_code_block.push(MpcOpCode::PushStackFrame);
        let start_condition = self.current_code_block.len();
        let mut body_code_block = CodeBlock::default();
        std::mem::swap(&mut body_code_block, &mut self.current_code_block);
        loop_bucket.body.iter().for_each(|inst| {
            self.eject_mpc_opcode(inst);
        });
        self.current_code_block
            .push(MpcOpCode::Jump(start_condition));
        std::mem::swap(&mut body_code_block, &mut self.current_code_block);
        self.eject_mpc_opcode(&loop_bucket.continue_condition);
        self.current_code_block.push(MpcOpCode::JumpIfFalse(
            body_code_block.len() + self.current_code_block.len() + 1,
        ));
        self.current_code_block.append(&mut body_code_block);
        self.current_code_block.push(MpcOpCode::PopStackFrame);
    }

    fn handle_value_bucket(&mut self, value_bucket: &ValueBucket) {
        let index = value_bucket.value;
        match value_bucket.parse_as {
            ValueType::BigInt => self.current_code_block.push(MpcOpCode::PushConstant(index)),
            ValueType::U32 => self.current_code_block.push(MpcOpCode::PushIndex(index)),
        }
    }

    fn eject_mpc_opcode(&mut self, inst: &Instruction) {
        match inst {
            Instruction::Value(value_bucket) => self.handle_value_bucket(value_bucket),
            Instruction::Load(load_bucket) => self.handle_load_bucket(load_bucket),
            Instruction::Store(store_bucket) => self.handle_store_bucket(store_bucket),
            Instruction::Compute(compute_bucket) => self.handle_compute_bucket(compute_bucket),
            Instruction::Call(call_bucket) => todo!(),
            Instruction::Branch(_) => todo!(),
            Instruction::Return(_) => todo!(),
            Instruction::Assert(_) => todo!(),
            Instruction::Log(_) => todo!(),
            Instruction::Loop(loop_bucket) => self.handle_loop_bucket(loop_bucket),
            Instruction::CreateCmp(create_cmp_bucket) => {
                self.handle_create_cmp_bucket(create_cmp_bucket)
            }
        }
    }

    pub fn parse(mut self) -> Result<WitnessExtension<P>, ()> {
        let program_archive = self.get_program_archive()?;
        let circuit = self.build_circuit(program_archive)?;
        self.constant_table = circuit
            .c_producer
            .get_field_constant_list()
            .iter()
            .map(|s| s.parse::<P::ScalarField>().map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        println!("=====Constants=====");
        for fr in self.constant_table.iter() {
            println!("{fr}");
        }
        //build functions
        assert!(circuit.functions.is_empty(), "must be empty for now");
        for fun in circuit.functions.iter() {
            fun.body.iter().for_each(|inst| {
                self.eject_mpc_opcode(inst);
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
                self.eject_mpc_opcode(inst);
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
                    templ.var_stack_depth,
                    templ.number_of_components,
                    new_code_block,
                ),
            );
        }

        //let main_template = circuit
        //    .templates
        //    .iter()
        //    .find(|temp| temp.header == circuit.c_producer.main_header)
        //    .unwrap();
        //for inst in main_template.body.iter() {
        //    println!("==============");
        //    println!("{}", inst.to_string());
        //    println!();
        //    println!();
        //    //self.eject_mpc_opcode(inst, &circuit);
        //}
        Ok(WitnessExtension::new(self, circuit.c_producer.main_header))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;

    use super::*;
    use std::str::FromStr;
    #[test]
    fn test() {
        let file = "/home/fnieddu/research/circom/circuits/multiplier2.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        builder.parse().unwrap().run(vec![
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
        ]);
    }
}
