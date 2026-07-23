//! Shared helpers for hand-assembled single-template test programs.
#![allow(dead_code)]

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::drivers::taint::{Taint, TaintDriver};
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

/// Like [`single_template_program`], but also installs a function table and appends
/// each function's name to the debug names table (indices `1..`, right after the
/// template's own name at index `0` — set `FunctionCode::name_id` accordingly).
#[allow(clippy::too_many_arguments)]
pub fn program_with_functions(
    template_instrs: Vec<Instr>,
    num_field_regs: u16,
    num_int_regs: u8,
    num_vars: u32,
    input_signals: u32,
    output_signals: u32,
    total_signals: usize,
    functions: Vec<FunctionCode>,
    function_names: Vec<&str>,
) -> CompiledProgram<Fr> {
    let mut program = single_template_program(
        template_instrs,
        num_field_regs,
        num_int_regs,
        num_vars,
        input_signals,
        output_signals,
        total_signals,
    );
    program.functions = functions;
    program
        .debug
        .names
        .extend(function_names.into_iter().map(str::to_string));
    program
}

/// A two-named-input multiplier program (`out <== a * b`), with `output_mapping =
/// {"out": (1, 1)}` — the program used by the `api` integration tests.
///
/// Signal layout: `[0]=1, [1]=out, [2]=a, [3]=b`.
pub fn multiplier_program() -> CompiledProgram<Fr> {
    let mut program = CompiledProgram {
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
            sub_components: 0,
            mappings: vec![],
            name_id: 0,
            symbol_id: 0,
        }],
        functions: vec![],
        constants: vec![],
        strings: vec![],
        main: TemplId(0),
        total_signals: 4,
        main_inputs: 2,
        main_outputs: 1,
        main_input_list: vec![
            InputInfo {
                name: "a".to_string(),
                offset: 2,
                size: 1,
            },
            InputInfo {
                name: "b".to_string(),
                offset: 3,
                size: 1,
            },
        ],
        output_mapping: HashMap::new(),
        signal_to_witness: vec![0, 1, 2, 3],
        public_inputs: vec![],
        debug: DebugInfo {
            names: vec!["Test".to_string()],
        },
    };
    program.output_mapping.insert("out".to_string(), (1, 1));
    program
}

/// A single-array-input program computing `out = in[0] + in[1] + ... + in[n-1]`, with
/// `output_mapping = {"out": (1, 1)}` and constants already installed — ready to run
/// through the `api` module directly (no `run_plain_with_consts` needed). The array
/// input is named `"in"` (old naming convention: consumed as `in[0]..in[n-1]`).
pub fn sum_program(n: u64) -> CompiledProgram<Fr> {
    // regs: r0 = acc, r1 = i (field copy), r2 = cond scratch
    // iregs: i0 = i (address copy)
    // signals: [0]=1, [1]=out, [2..2+n]=in[i]
    let instrs = vec![
        /* 0 */
        Instr::Mov {
            dst: Dst::Reg(0),
            src: Src::Const(0),
        }, // acc = 0
        /* 1 */
        Instr::Mov {
            dst: Dst::Reg(1),
            src: Src::Const(0),
        }, // i_f = 0
        /* 2 */ Instr::ISet { dst: 0, val: 0 }, // i = 0
        /* 3 */
        Instr::Bin {
            op: BinOp::Lt,
            dst: 2,
            a: Src::Reg(1),
            b: Src::Const(1),
        }, // i_f < n
        /* 4 */
        Instr::JmpIfZero {
            cond: Src::Reg(2),
            target: 9,
        },
        /* 5 */
        Instr::Bin {
            op: BinOp::Add,
            dst: 0,
            a: Src::Reg(0),
            b: Src::Signal(Addr::Affine {
                ireg: 0,
                stride: 1,
                offset: 1,
            }),
        },
        /* 6 */
        Instr::IAdd {
            dst: 0,
            a: ISrc::Reg(0),
            b: ISrc::Const(1),
        },
        /* 7 */
        Instr::Bin {
            op: BinOp::Add,
            dst: 1,
            a: Src::Reg(1),
            b: Src::Const(2),
        }, // i_f += 1
        /* 8 */ Instr::Jmp { target: 3 },
        /* 9 */
        Instr::Mov {
            dst: Dst::Signal(Addr::Const(0)),
            src: Src::Reg(0),
        },
        /*10 */ Instr::Return,
    ];
    let mut program = single_template_program(instrs, 3, 1, 0, n as u32, 1, (n + 2) as usize);
    program.constants = vec![Fr::from(0u64), Fr::from(n), Fr::from(1u64)];
    program.output_mapping.insert("out".to_string(), (1, 1));
    program
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

/// Runs main with a [`TaintDriver`], the given constants table, and the given
/// (value, shared) input pairs; returns the full signal RAM as [`Taint`] values.
pub fn run_taint_with_consts(
    program: &CompiledProgram<Fr>,
    consts: Vec<Fr>,
    inputs: Vec<Taint<Fr>>,
) -> Vec<Taint<Fr>> {
    let mut program = program.clone();
    program.constants = consts;
    let mut driver = TaintDriver::<Fr>::default();
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

/// Convenience constructor for a shared (secret) taint value.
pub fn shared(v: u64) -> Taint<Fr> {
    Taint {
        val: Fr::from(v),
        shared: true,
    }
}

/// Convenience constructor for a public taint value.
pub fn public(v: u64) -> Taint<Fr> {
    Taint {
        val: Fr::from(v),
        shared: false,
    }
}
