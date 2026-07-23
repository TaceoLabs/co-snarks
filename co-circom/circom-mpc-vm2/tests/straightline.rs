mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::VMConfig;

// signal layout: [0]=1, [1]=out, [2]=a, [3]=b   (outputs first, then inputs — as circom)
#[test]
fn multiply_two_signals() {
    let program = common::single_template_program(
        vec![
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
        1,
        0,
        0,
        2,
        1,
        4,
    );
    let signals = common::run_plain(&program, vec![Fr::from(6u64), Fr::from(7u64)]);
    assert_eq!(signals[1], Fr::from(42u64));
}

#[test]
fn rolled_loop_sums_inputs() {
    let n = 5u64;
    // regs: r0 = acc, r1 = i (field copy), r2 = cond scratch
    // iregs: i0 = i (address copy)
    // signals: [0]=1, [1]=out, [2..2+n]=in[i]
    let program = common::single_template_program(
        vec![
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
        ],
        3,
        1,
        0,
        n as u32,
        1,
        (n + 2) as usize,
    );
    // constants table for this program: c0 = 0, c1 = n, c2 = 1
    let signals = common::run_plain_with_consts(
        &program,
        vec![Fr::from(0u64), Fr::from(n), Fr::from(1u64)],
        (1..=n).map(Fr::from).collect(),
    );
    assert_eq!(signals[1], Fr::from(n * (n + 1) / 2));
}

// signal layout: [0]=1, [1]=out, [2..5]=a[3], [5..8]=b[3]
// (component-relative addressing: comp_offset=1 is added by the engine, so relative
// addr 0 = signal 1 = out, relative addr 1 = signal 2 = a[0], relative addr 4 = signal
// 5 = b[0])
#[test]
fn eqn_reports_equal_arrays() {
    let program = common::single_template_program(
        vec![
            Instr::EqN {
                dst: 0,
                a: Src::Signal(Addr::Const(1)),
                b: Src::Signal(Addr::Const(4)),
                n: 3,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(0),
            },
            Instr::Return,
        ],
        1,
        0,
        0,
        6,
        1,
        8,
    );
    let signals = common::run_plain(
        &program,
        vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ],
    );
    assert_eq!(signals[1], Fr::from(1u64));
}

#[test]
fn eqn_reports_unequal_arrays() {
    let program = common::single_template_program(
        vec![
            Instr::EqN {
                dst: 0,
                a: Src::Signal(Addr::Const(1)),
                b: Src::Signal(Addr::Const(4)),
                n: 3,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(0),
            },
            Instr::Return,
        ],
        1,
        0,
        0,
        6,
        1,
        8,
    );
    let signals = common::run_plain(
        &program,
        vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(4u64),
        ],
    );
    assert_eq!(signals[1], Fr::from(0u64));
}

// signal layout: [0]=1, [1..4]=out[3], [4..7]=in[3]
// (component-relative: out base = 0, in base = 3)
#[test]
fn loadn_storen_round_trip() {
    let program = common::single_template_program(
        vec![
            Instr::LoadN {
                dst: 0,
                src: Src::Signal(Addr::Const(3)),
                n: 3,
            },
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(0)),
                src: 0,
                n: 3,
            },
            Instr::Return,
        ],
        3,
        0,
        0,
        3,
        3,
        7,
    );
    let signals = common::run_plain(
        &program,
        vec![Fr::from(11u64), Fr::from(22u64), Fr::from(33u64)],
    );
    assert_eq!(signals[1], Fr::from(11u64));
    assert_eq!(signals[2], Fr::from(22u64));
    assert_eq!(signals[3], Fr::from(33u64));
}

// signal layout: [0]=1, [1..5]=out[4], [5..9]=a[4], [9..13]=b[4]
// (component-relative: out base = 0, a base = 4, b base = 8)
#[test]
fn binn_elementwise_mul() {
    let program = common::single_template_program(
        vec![
            Instr::BinN {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Signal(Addr::Const(4)),
                b: Src::Signal(Addr::Const(8)),
                n: 4,
            },
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(0)),
                src: 0,
                n: 4,
            },
            Instr::Return,
        ],
        4,
        0,
        0,
        8,
        4,
        13,
    );
    let signals = common::run_plain(
        &program,
        vec![
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(10u64),
            Fr::from(10u64),
            Fr::from(10u64),
            Fr::from(10u64),
        ],
    );
    assert_eq!(signals[1], Fr::from(20u64));
    assert_eq!(signals[2], Fr::from(30u64));
    assert_eq!(signals[3], Fr::from(40u64));
    assert_eq!(signals[4], Fr::from(50u64));
}

// signal layout: [0]=1, [1]=out, [2..6]=in[4]; loads in[in[0]] via ToIndex + Dynamic
// double indirection.
#[test]
fn to_index_and_dynamic_double_indirection() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::ToIndex {
                dst: 0,
                src: Src::Signal(Addr::Const(1)),
            }, // ireg0 = to_index(in[0])
            /* 1 */
            Instr::IAdd {
                dst: 1,
                a: ISrc::Reg(0),
                b: ISrc::Const(1),
            }, // ireg1 = ireg0 + 1 (array base, component-relative)
            /* 2 */
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Dynamic(1)),
            },
            /* 3 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(0),
            },
            /* 4 */ Instr::Return,
        ],
        1,
        2,
        0,
        4,
        1,
        6,
    );
    let signals = common::run_plain(
        &program,
        vec![
            Fr::from(2u64),
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
        ],
    );
    assert_eq!(signals[1], Fr::from(20u64));
}

#[test]
fn assert_failure_reports_symbol_and_line() {
    let program = common::single_template_program(
        vec![
            Instr::Assert {
                cond: Src::Const(0),
                line: 42,
            },
            Instr::Return,
        ],
        0,
        0,
        0,
        0,
        0,
        1,
    );
    let mut program = program;
    program.constants = vec![Fr::from(0u64)];
    let mut driver = PlainDriver::default();
    let mut machine = Machine::new(&program, &mut driver, VMConfig::default()).unwrap();
    let err = machine.run_main().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("Test"), "error message was: {msg}");
    assert!(msg.contains("42"), "error message was: {msg}");
}

#[test]
fn log_smoke_test_does_not_crash() {
    let mut program = common::single_template_program(
        vec![
            Instr::Log { src: Src::Const(0) },
            Instr::LogStr { id: 0 },
            Instr::LogFlush { line: 7 },
            Instr::Return,
        ],
        0,
        0,
        0,
        0,
        0,
        1,
    );
    program.strings = vec!["hello".to_string()];
    let signals = common::run_plain_with_consts(&program, vec![Fr::from(5u64)], vec![]);
    assert_eq!(signals[0], Fr::from(1u64));
}
