//! Shared helpers for hand-assembled single-template test programs.
#![allow(dead_code)]

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::*;
use std::collections::HashMap;

/// Builds a single-template `CompiledProgram` around a hand-assembled instruction
/// sequence, filling every other field with an empty/default value.
pub fn single_template_program(
    instrs: Vec<Instr>,
    num_field_regs: u16,
    num_int_regs: u8,
    num_vars: u32,
    input_signals: u32,
    output_signals: u32,
    total_signals: usize,
) -> CompiledProgram<Fr> {
    CompiledProgram {
        templates: vec![TemplateCode {
            instrs,
            num_field_regs,
            num_int_regs,
            num_vars,
            input_signals,
            output_signals,
            sub_components: 0,
            mappings: vec![],
            name_id: 0,
            symbol_id: 0,
        }],
        functions: vec![],
        constants: vec![],
        strings: vec![],
        main: TemplId(0),
        total_signals,
        main_inputs: input_signals as usize,
        main_outputs: output_signals as usize,
        main_input_list: vec![InputInfo {
            name: "in".to_string(),
            offset: 1 + output_signals as usize,
            size: input_signals as usize,
        }],
        output_mapping: HashMap::new(),
        signal_to_witness: (0..total_signals).collect(),
        public_inputs: vec![],
        debug: DebugInfo {
            names: vec!["Test".to_string()],
        },
    }
}

/// Runs main with the given flat inputs (constants table = `[0]`), returns the full
/// signal RAM.
pub fn run_plain(program: &CompiledProgram<Fr>, inputs: Vec<Fr>) -> Vec<Fr> {
    run_plain_with_consts(program, vec![Fr::from(0u64)], inputs)
}

/// Runs main with the given constants table and flat inputs, returns the full signal
/// RAM.
pub fn run_plain_with_consts(
    program: &CompiledProgram<Fr>,
    consts: Vec<Fr>,
    inputs: Vec<Fr>,
) -> Vec<Fr> {
    let mut program = program.clone();
    program.constants = consts;
    let mut driver = PlainDriver::default();
    let config = VMConfig::default();
    let mut machine = Machine::new(&program, &mut driver, config).expect("Machine::new");
    if let Some(info) = program.main_input_list.first() {
        for (i, v) in inputs.into_iter().enumerate() {
            machine.signals[info.offset + i] = v;
        }
    }
    machine.run_main().expect("run_main");
    machine.signals
}
