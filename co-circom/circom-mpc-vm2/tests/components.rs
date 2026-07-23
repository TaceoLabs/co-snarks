mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::taint::TaintDriver;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::*;
use std::collections::HashMap;

/// Build a multi-template `CompiledProgram` with `main` = template index 0.
fn multi_template_program(
    templates: Vec<TemplateCode>,
    total_signals: usize,
    main_inputs: usize,
    main_outputs: usize,
    names: Vec<&str>,
) -> CompiledProgram<Fr> {
    CompiledProgram {
        templates,
        functions: vec![],
        constants: vec![],
        strings: vec![],
        main: TemplId(0),
        total_signals,
        main_inputs,
        main_outputs,
        main_input_list: vec![InputInfo {
            name: "in".to_string(),
            offset: 1 + main_outputs,
            size: main_inputs,
        }],
        output_mapping: HashMap::new(),
        signal_to_witness: (0..total_signals).collect(),
        public_inputs: vec![],
        debug: DebugInfo {
            names: names.into_iter().map(str::to_string).collect(),
        },
    }
}

// Square: out = in * in.  addr0 = out, addr1 = in.
fn square_template(name_id: u32) -> TemplateCode {
    TemplateCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Signal(Addr::Const(1)),
                b: Src::Signal(Addr::Const(1)),
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
        input_signals: 1,
        output_signals: 1,
        sub_components: 0,
        mappings: vec![],
        name_id,
        symbol_id: name_id,
    }
}

// main creates a single `Square` subcomponent (1 in -> 1 out), feeds it `in0`, reads
// back the square, and stores it to `out`. Two templates: Main (0), Square (1).
//
// main signal layout (component-relative): addr0=out, addr1=in0, addr2..4=Square's
// block (addr2=Square.out, addr3=Square.in).
#[test]
fn two_level_tree() {
    let square = square_template(1);
    let main = TemplateCode {
        instrs: vec![
            Instr::CreateCmp {
                templ: TemplId(1),
                count: 1,
                base: 2,
                jump: 0,
            },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(1)),
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(1),
                mapped: None,
                src: 0,
                n: 1,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 1,
                n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(1),
            },
            Instr::Return,
        ],
        num_field_regs: 2,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 1,
        output_signals: 1,
        sub_components: 1,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let program = multi_template_program(vec![main, square], 5, 1, 1, vec!["Main", "Square"]);
    let signals = common::run_plain_with_consts(&program, vec![], vec![Fr::from(7u64)]);
    assert_eq!(signals[1], Fr::from(49u64));
}

// `CreateCmp { count: 3, base: 4, jump: 2 }`: three `Square` subcomponents at distinct
// per-instance offsets `base + i*jump`; main feeds each with a different input and sums
// the outputs. Verifies the raw signal offsets directly, not just the final sum.
#[test]
fn array_of_components() {
    let square = square_template(1);
    let main = TemplateCode {
        instrs: vec![
            Instr::CreateCmp {
                templ: TemplId(1),
                count: 3,
                base: 4,
                jump: 2,
            },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(1)),
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Signal(Addr::Const(2)),
            },
            Instr::Mov {
                dst: Dst::Reg(2),
                src: Src::Signal(Addr::Const(3)),
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(1),
                mapped: None,
                src: 0,
                n: 1,
            },
            Instr::InputSub {
                cmp: ISrc::Const(1),
                addr: Addr::Const(1),
                mapped: None,
                src: 1,
                n: 1,
            },
            Instr::InputSub {
                cmp: ISrc::Const(2),
                addr: Addr::Const(1),
                mapped: None,
                src: 2,
                n: 1,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 3,
                n: 1,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(1),
                addr: Addr::Const(0),
                mapped: None,
                dst: 4,
                n: 1,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(2),
                addr: Addr::Const(0),
                mapped: None,
                dst: 5,
                n: 1,
            },
            Instr::Bin {
                op: BinOp::Add,
                dst: 6,
                a: Src::Reg(3),
                b: Src::Reg(4),
            },
            Instr::Bin {
                op: BinOp::Add,
                dst: 6,
                a: Src::Reg(6),
                b: Src::Reg(5),
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(6),
            },
            Instr::Return,
        ],
        num_field_regs: 7,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 3,
        output_signals: 1,
        sub_components: 3,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let program = multi_template_program(vec![main, square], 11, 3, 1, vec!["Main", "Square"]);
    let signals = common::run_plain_with_consts(
        &program,
        vec![],
        vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)],
    );
    // main offset is 1; instance i sits at 1 + base + i*jump = 1 + 4 + i*2 = 5, 7, 9.
    assert_eq!(signals[5], Fr::from(4u64)); // Square(2).out
    assert_eq!(signals[7], Fr::from(9u64)); // Square(3).out
    assert_eq!(signals[9], Fr::from(16u64)); // Square(4).out
    assert_eq!(signals[1], Fr::from(29u64)); // 4 + 9 + 16
}

// A 0-input subcomponent writes a constant to its output at `CreateCmp` time; main
// reads it back immediately afterwards with no `InputSub` in between.
#[test]
fn zero_input_component_runs_at_create() {
    let const42 = TemplateCode {
        instrs: vec![
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::Return,
        ],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 0,
        output_signals: 1,
        sub_components: 0,
        mappings: vec![],
        name_id: 1,
        symbol_id: 1,
    };
    let main = TemplateCode {
        instrs: vec![
            Instr::CreateCmp {
                templ: TemplId(1),
                count: 1,
                base: 1,
                jump: 0,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 0,
                n: 1,
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
        input_signals: 0,
        output_signals: 1,
        sub_components: 1,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let program = multi_template_program(vec![main, const42], 3, 0, 1, vec!["Main", "Const42"]);
    let signals = common::run_plain_with_consts(&program, vec![Fr::from(42u64)], vec![]);
    assert_eq!(signals[1], Fr::from(42u64));
}

// A 2-input `Adder` subcomponent: the sum is only computed once the second `InputSub`
// arrives. Deferral itself is structurally guaranteed by the `provided_inputs ==
// input_signals` gate; this test asserts final correctness (per the brief's
// simplification note).
#[test]
fn partial_inputs_defer_run() {
    let adder = TemplateCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Add,
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
        name_id: 1,
        symbol_id: 1,
    };
    let main = TemplateCode {
        instrs: vec![
            Instr::CreateCmp {
                templ: TemplId(1),
                count: 1,
                base: 3,
                jump: 0,
            },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(1)),
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Signal(Addr::Const(2)),
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(1),
                mapped: None,
                src: 0,
                n: 1,
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(2),
                mapped: None,
                src: 1,
                n: 1,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 2,
                n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(2),
            },
            Instr::Return,
        ],
        num_field_regs: 3,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 2,
        output_signals: 1,
        sub_components: 1,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let program = multi_template_program(vec![main, adder], 7, 2, 1, vec!["Main", "Adder"]);
    let signals =
        common::run_plain_with_consts(&program, vec![], vec![Fr::from(5u64), Fr::from(9u64)]);
    assert_eq!(signals[1], Fr::from(14u64));
}

// `InputSub` executed while a shared `if` is active must error (old `assert!`, now a
// `bail!`). Uses the `TaintDriver` so a signal can actually be tainted shared.
#[test]
fn input_sub_in_shared_if_errors() {
    let square = square_template(1);
    let main = TemplateCode {
        instrs: vec![
            Instr::CreateCmp {
                templ: TemplId(1),
                count: 1,
                base: 1,
                jump: 0,
            },
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(0)),
                else_target: 4,
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(1),
                mapped: None,
                src: 0,
                n: 1,
            },
            Instr::SharedElse { end_target: 5 },
            Instr::SharedEnd,
            Instr::Return,
        ],
        num_field_regs: 1,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 1,
        output_signals: 0,
        sub_components: 1,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let program = multi_template_program(vec![main, square], 4, 1, 0, vec!["Main", "Square"]);
    let mut driver = TaintDriver::<Fr>::default();
    let config = VMConfig::default();
    let mut machine = Machine::new(&program, &mut driver, config).expect("Machine::new");
    // main's only input sits at offset 1 (main offset 1, 0 outputs preceding it).
    machine.signals[1] = common::shared(1);
    let err = machine
        .run_main()
        .expect_err("InputSub under a shared if must error");
    assert!(
        err.to_string().contains("shared"),
        "unexpected error message: {err}"
    );
}

// A subcomponent template with a non-empty `mappings` table; `InputSub { mapped:
// Some(1), addr: Const(1), .. }` must resolve to `addr + mappings[1]` and land on the
// subcomponent's third input signal (verified via the raw signal, not just the sum).
#[test]
fn mapped_addressing() {
    let mapped_tpl = TemplateCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Signal(Addr::Const(1)),
                b: Src::Signal(Addr::Const(2)),
            },
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Reg(0),
                b: Src::Signal(Addr::Const(3)),
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
        input_signals: 3,
        output_signals: 1,
        sub_components: 0,
        // mappings[1] = 2, so `addr: Const(1), mapped: Some(1)` resolves to slot 1+2=3
        // (the third input, `in2`).
        mappings: vec![0, 2],
        name_id: 1,
        symbol_id: 1,
    };
    let main = TemplateCode {
        instrs: vec![
            Instr::CreateCmp {
                templ: TemplId(1),
                count: 1,
                base: 4,
                jump: 0,
            },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(1)),
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Signal(Addr::Const(2)),
            },
            Instr::Mov {
                dst: Dst::Reg(2),
                src: Src::Signal(Addr::Const(3)),
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(1),
                mapped: None,
                src: 0,
                n: 1,
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(2),
                mapped: None,
                src: 1,
                n: 1,
            },
            Instr::InputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(1),
                mapped: Some(1),
                src: 2,
                n: 1,
            },
            Instr::OutputSub {
                cmp: ISrc::Const(0),
                addr: Addr::Const(0),
                mapped: None,
                dst: 3,
                n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(3),
            },
            Instr::Return,
        ],
        num_field_regs: 4,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 3,
        output_signals: 1,
        sub_components: 1,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let program = multi_template_program(vec![main, mapped_tpl], 9, 3, 1, vec!["Main", "Mapped"]);
    let signals = common::run_plain_with_consts(
        &program,
        vec![],
        vec![Fr::from(2u64), Fr::from(3u64), Fr::from(5u64)],
    );
    assert_eq!(signals[1], Fr::from(10u64)); // 2 + 3 + 5
    // sub offset = main offset(1) + base(4) = 5; in2 sits at sub_offset + 3 = 8.
    assert_eq!(signals[8], Fr::from(5u64));
}
