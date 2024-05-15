use ark_ec::pairing::Pairing;
use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags},
    intermediate_representation::ir_interface::{
        AddressType, ComputeBucket, Instruction, LoadBucket, LocationRule, OperatorType,
        StoreBucket, ValueBucket, ValueType,
    },
};
use circom_constraint_generation::BuildConfig;
use circom_program_structure::{
    error_definition::{Report, ReportCollection},
    file_definition::FileLibrary,
    program_archive::{self, ProgramArchive},
};
use circom_type_analysis::check_types;
use std::{collections::HashMap, fmt::format, marker::PhantomData, path::PathBuf};

const DEFAULT_VERSION: &str = "2.0.0";

type CodeBlock = Vec<MpcOpCode>;
enum MpcOpCode {
    PushConstant(usize),
    PushIndex(usize),
    LoadSignal(usize),
    StoreSignal(usize),
    Add,
    Mul,
}

impl ToString for MpcOpCode {
    fn to_string(&self) -> String {
        match self {
            MpcOpCode::PushConstant(index) => format!("PUSH_CONSTANT_OP {}", index),
            MpcOpCode::PushIndex(index) => format!("PUSH_INDEX_OP {}", index),
            MpcOpCode::LoadSignal(template_id) => format!("LOAD_SIGNAL_OP {}", template_id),
            MpcOpCode::StoreSignal(template_id) => format!("STORE_SIGNAL_OP {}", template_id),
            MpcOpCode::Add => "ADD".to_owned(),
            MpcOpCode::Mul => "MUL".to_owned(),
        }
    }
}

struct CompilerBuilder<P: Pairing> {
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

    pub fn build(self) -> Builder<P> {
        Builder {
            file: self.file,
            version: self.version,
            constant_table: vec![],
            current_code_block: vec![],
            phantom_data: PhantomData,
        }
    }
}
struct Builder<P: Pairing> {
    file: String,
    version: String,
    constant_table: Vec<P::ScalarField>,
    current_code_block: CodeBlock,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Builder<P> {
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

    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket, circuit: &CircomCircuit) {
        self.eject_mpc_opcode(&store_bucket.src, circuit);
        match &store_bucket.dest {
            LocationRule::Indexed {
                location,
                template_header,
            } => {
                self.eject_mpc_opcode(location, circuit);
                assert!(
                    template_header.is_none(),
                    "TODO template header is not none in load"
                );
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => todo!(),
        }
        match &store_bucket.dest_address_type {
            AddressType::Variable => todo!(),
            AddressType::Signal => self
                .current_code_block
                .push(MpcOpCode::StoreSignal(store_bucket.message_id)),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value,
                is_output,
                input_information,
            } => todo!(),
        }
        println!("{}", store_bucket.to_string());
        println!();
        Self::debug_code_block(&self.current_code_block);
    }

    fn handle_compute_bucket(&mut self, compute_bucket: &ComputeBucket, circuit: &CircomCircuit) {
        //load stack
        compute_bucket.stack.iter().for_each(|inst| {
            self.eject_mpc_opcode(inst, circuit);
        });
        match compute_bucket.op {
            OperatorType::Mul => self.current_code_block.push(MpcOpCode::Mul),
            OperatorType::Div => todo!(),
            OperatorType::Add => self.current_code_block.push(MpcOpCode::Add),
            OperatorType::Sub => todo!(),
            OperatorType::Pow => todo!(),
            OperatorType::IntDiv => todo!(),
            OperatorType::Mod => todo!(),
            OperatorType::ShiftL => todo!(),
            OperatorType::ShiftR => todo!(),
            OperatorType::LesserEq => todo!(),
            OperatorType::GreaterEq => todo!(),
            OperatorType::Lesser => todo!(),
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
            OperatorType::ToAddress => todo!(),
            OperatorType::MulAddress => todo!(),
            OperatorType::AddAddress => todo!(),
        }
    }

    fn debug_code_block(code_block: &CodeBlock) {
        for op in code_block {
            println!("{}", op.to_string());
        }
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket, circuit: &CircomCircuit) {
        //first eject for src
        match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header,
            } => {
                self.eject_mpc_opcode(location, circuit);
                assert!(
                    template_header.is_none(),
                    "TODO template header is not none in load"
                );
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => todo!(),
        }
        match &load_bucket.address_type {
            AddressType::Variable => todo!(),
            AddressType::Signal => self
                .current_code_block
                .push(MpcOpCode::LoadSignal(load_bucket.message_id)),
            AddressType::SubcmpSignal {
                cmp_address,
                uniform_parallel_value,
                is_output,
                input_information,
            } => todo!(),
        }
    }

    fn handle_value_bucket(&mut self, value_bucket: &ValueBucket, circuit: &CircomCircuit) {
        let index = value_bucket.value;
        match value_bucket.parse_as {
            ValueType::BigInt => self.current_code_block.push(MpcOpCode::PushConstant(index)),
            ValueType::U32 => self.current_code_block.push(MpcOpCode::PushIndex(index)),
        }
    }

    fn eject_mpc_opcode(&mut self, inst: &Instruction, circuit: &CircomCircuit) {
        match inst {
            Instruction::Value(value_bucket) => self.handle_value_bucket(value_bucket, circuit),
            Instruction::Load(load_bucket) => self.handle_load_bucket(load_bucket, circuit),
            Instruction::Store(store_bucket) => self.handle_store_bucket(store_bucket, circuit),
            Instruction::Compute(compute_bucket) => {
                self.handle_compute_bucket(compute_bucket, circuit)
            }
            Instruction::Call(_) => todo!(),
            Instruction::Branch(_) => todo!(),
            Instruction::Return(_) => todo!(),
            Instruction::Assert(_) => todo!(),
            Instruction::Log(_) => todo!(),
            Instruction::Loop(_) => todo!(),
            Instruction::CreateCmp(create_cmp_bucket) => todo!(),
        }
    }

    pub fn parse(mut self) -> Result<(), ()> {
        let program_archive = self.get_program_archive()?;
        let circuit = self.build_circuit(program_archive)?;
        self.constant_table = circuit
            .c_producer
            .get_field_constant_list()
            .iter()
            .map(|s| s.parse::<P::ScalarField>().map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        //build functions
        let mut fun_decls = HashMap::new();
        assert!(circuit.functions.is_empty(), "must be empty for now");
        for fun in circuit.functions.iter() {
            fun.body.iter().for_each(|inst| {
                self.eject_mpc_opcode(inst, &circuit);
            });
            let mut new_code_block = CodeBlock::default();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);
            fun_decls.insert(fun.header.clone(), new_code_block);
        }
        let mut templ_decls = HashMap::new();
        for templ in circuit.templates.iter() {
            println!("==============");
            println!("id      : {}", templ.id);
            println!("name    : {}", templ.name);
            println!("header  : {}", templ.header);
            println!("#ins    : {}", templ.number_of_inputs);
            println!("#outs   : {}", templ.number_of_outputs);
            println!("#inters : {}", templ.number_of_intermediates);
            println!("#cmps   : {}", templ.number_of_components);
            templ.body.iter().for_each(|inst| {
                self.eject_mpc_opcode(inst, &circuit);
            });
            let mut new_code_block = CodeBlock::default();
            std::mem::swap(&mut new_code_block, &mut self.current_code_block);
            templ_decls.insert(templ.header.clone(), new_code_block);
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;

    use super::*;
    #[test]
    fn test() {
        let file = "/home/fnieddu/research/circom/circuits/multiplier2.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        builder.parse().unwrap();
    }
}
