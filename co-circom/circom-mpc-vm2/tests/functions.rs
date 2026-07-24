mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::{FunctionCode, VMConfig};

// f(a, b) = a * b + 1 (regs only, no vars).
// f instrs:  0: r0 = vars[0] * vars[1]     (a * b)
//            1: r1 = r0 + consts[0]        (+ 1)
//            2: Ret Reg(1), n=1
//
// signal layout: [0]=1, [1]=out, [2]=in0, [3]=in1.
// template: reg0=in0, reg1=in1, reg2=CallFn(f, args=[reg0,reg1]) -> reg2, out=reg2.
#[test]
fn simple_call() {
    let f = FunctionCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Var(Addr::Const(0)),
                b: Src::Var(Addr::Const(1)),
            },
            Instr::Bin {
                op: BinOp::Add,
                dst: 1,
                a: Src::Reg(0),
                b: Src::Const(0),
            },
            Instr::Ret {
                src: RetSrc::Reg(1),
                n: 1,
            },
        ],
        num_field_regs: 2,
        num_int_regs: 0,
        num_vars: 2,
        num_params: 2,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(1)),
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Signal(Addr::Const(2)),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 2,
                ret: 2,
                ret_n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(2),
            },
            Instr::Return,
        ],
        3,
        0,
        0,
        2,
        1,
        4,
        vec![f],
        vec!["f"],
    );
    let signals = common::run_plain_with_consts(
        &program,
        vec![Fr::from(1u64)],
        vec![Fr::from(3u64), Fr::from(4u64)],
    );
    assert_eq!(signals[1], Fr::from(13u64)); // 3*4 + 1
}

// f() returns three values from var slots (RetSrc::Var), no arguments.
// f instrs: vars[0..3] = consts[0..3]; Ret Var(0), n=3.
// template: CallFn(f) -> regs[0..3], StoreN into 3 output signals.
#[test]
fn multi_value_return() {
    let f = FunctionCode {
        instrs: vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(1)),
                src: Src::Const(1),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(2)),
                src: Src::Const(2),
            },
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(0)),
                n: 3,
            },
        ],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 3,
        num_params: 0,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 0,
                ret: 0,
                ret_n: 3,
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
        0,
        3,
        4,
        vec![f],
        vec!["f"],
    );
    let signals = common::run_plain_with_consts(
        &program,
        vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)],
        vec![],
    );
    assert_eq!(signals[1], Fr::from(10u64));
    assert_eq!(signals[2], Fr::from(20u64));
    assert_eq!(signals[3], Fr::from(30u64));
}

// Callsite-arity parity (old mpc_vm.rs:788-838): the CALLSITE, not the callee,
// determines how many values a call produces. f() returns 2 values but the callsite
// asks for 3 (`ret_n: 3`) — the third slot must be zero-padded.
//
// f instrs: vars[0..2] = consts[0..2]; Ret Var(0), n=2.
// template: CallFn(f, ret_n=3) -> regs[0..3], StoreN into 3 output signals.
#[test]
fn callee_returns_fewer_than_callsite_pads_with_zero() {
    let f = FunctionCode {
        instrs: vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(1)),
                src: Src::Const(1),
            },
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(0)),
                n: 2,
            },
        ],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 2,
        num_params: 0,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 0,
                ret: 0,
                ret_n: 3,
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
        0,
        3,
        4,
        vec![f],
        vec!["f"],
    );
    let signals =
        common::run_plain_with_consts(&program, vec![Fr::from(10u64), Fr::from(20u64)], vec![]);
    assert_eq!(signals[1], Fr::from(10u64));
    assert_eq!(signals[2], Fr::from(20u64));
    assert_eq!(signals[3], Fr::from(0u64)); // padded with public_zero()
}

// Callsite-arity parity, the other direction: f() returns 3 values but the callsite
// only wants 2 (`ret_n: 2`) — old behavior copies exactly the callsite's arity, so the
// third value is dropped.
//
// f instrs: vars[0..3] = consts[0..3]; Ret Var(0), n=3.
// template: CallFn(f, ret_n=2) -> regs[0..2], StoreN into 2 output signals.
#[test]
fn callee_returns_more_than_callsite_truncates() {
    let f = FunctionCode {
        instrs: vec![
            Instr::Mov {
                dst: Dst::Var(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(1)),
                src: Src::Const(1),
            },
            Instr::Mov {
                dst: Dst::Var(Addr::Const(2)),
                src: Src::Const(2),
            },
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(0)),
                n: 3,
            },
        ],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 3,
        num_params: 0,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 0,
                ret: 0,
                ret_n: 2,
            },
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(0)),
                src: 0,
                n: 2,
            },
            Instr::Return,
        ],
        3,
        0,
        0,
        0,
        2,
        3,
        vec![f],
        vec!["f"],
    );
    let signals = common::run_plain_with_consts(
        &program,
        vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)],
        vec![],
    );
    assert_eq!(signals[1], Fr::from(10u64));
    assert_eq!(signals[2], Fr::from(20u64)); // the third (30) is dropped
}

// fact(n): if n == 0 { return 1 } else { return n * fact(n - 1) } — a public-condition
// early return, recursing via plain Rust recursion of `run_function`.
//
// fact instrs:
//   0: r0 = (vars[0] == consts[0]=0)
//   1: JmpIfZero r0, 4          (n != 0 -> recursive case)
//   2: r1 = consts[1]=1
//   3: Ret Reg(1), n=1          (base case)
//   4: r2 = vars[0] - consts[1]=1
//   5: CallFn(fact, args=[r2]) -> r3
//   6: r4 = vars[0] * r3
//   7: Ret Reg(4), n=1
#[test]
fn recursion() {
    let fact = FunctionCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Eq,
                dst: 0,
                a: Src::Var(Addr::Const(0)),
                b: Src::Const(0),
            },
            Instr::JmpIfZero {
                cond: Src::Reg(0),
                target: 4,
            },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Const(1),
            },
            Instr::Ret {
                src: RetSrc::Reg(1),
                n: 1,
            },
            Instr::Bin {
                op: BinOp::Sub,
                dst: 2,
                a: Src::Var(Addr::Const(0)),
                b: Src::Const(1),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 2,
                args_n: 1,
                ret: 3,
                ret_n: 1,
            },
            Instr::Bin {
                op: BinOp::Mul,
                dst: 4,
                a: Src::Var(Addr::Const(0)),
                b: Src::Reg(3),
            },
            Instr::Ret {
                src: RetSrc::Reg(4),
                n: 1,
            },
        ],
        num_field_regs: 5,
        num_int_regs: 0,
        num_vars: 1,
        num_params: 1,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(1)),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 1,
                ret: 1,
                ret_n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(1),
            },
            Instr::Return,
        ],
        2,
        0,
        0,
        1,
        1,
        3,
        vec![fact],
        vec!["fact"],
    );
    let signals = common::run_plain_with_consts(
        &program,
        vec![Fr::from(0u64), Fr::from(1u64)],
        vec![Fr::from(10u64)],
    );
    assert_eq!(signals[1], Fr::from(3628800u64)); // 10!
}

// f(cond, x, y) = if (shared cond) { return x } return y — the canonical shared
// early-return shape (old mpc_vm.rs semantics test). Result must equal
// cond*x + (1-cond)*y and be tainted shared, for both cond values.
//
// f instrs:
//   0: SharedIf vars[0]=cond, else_target=2
//   1: Ret Var(1)=x, n=1        (accumulates: is_shared() is true here)
//   2: SharedElse end_target=3  (empty else)
//   3: SharedEnd
//   4: Ret Var(2)=y, n=1        (unconditional: merges the accumulator and returns)
#[test]
fn shared_early_return_single() {
    let f = FunctionCode {
        instrs: vec![
            Instr::SharedIf {
                cond: Src::Var(Addr::Const(0)),
                else_target: 2,
            },
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(1)),
                n: 1,
            },
            Instr::SharedElse { end_target: 3 },
            Instr::SharedEnd,
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(2)),
                n: 1,
            },
        ],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 3,
        num_params: 3,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
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
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 3,
                ret: 3,
                ret_n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(3),
            },
            Instr::Return,
        ],
        4,
        0,
        0,
        3,
        1,
        5,
        vec![f],
        vec!["f"],
    );

    // cond = shared(1): result = x = 5, tainted shared.
    let signals = common::run_taint_with_consts(
        &program,
        vec![],
        vec![common::shared(1), common::public(5), common::public(7)],
    );
    assert_eq!(signals[1].val, Fr::from(5u64));
    assert!(signals[1].shared);

    // cond = shared(0): result = y = 7, tainted shared.
    let signals = common::run_taint_with_consts(
        &program,
        vec![],
        vec![common::shared(0), common::public(5), common::public(7)],
    );
    assert_eq!(signals[1].val, Fr::from(7u64));
    assert!(signals[1].shared);
}

// f(c1, c2, x, y, z) = if (shared c1) return x; if (shared c2) return y; return z.
// Two independent (sequential, not nested) shared-if early returns, then an
// unconditional one — the final Ret's accumulated condition must be ¬c1 ∧ ¬c2 (old
// mpc_vm.rs:756-787).
#[test]
fn shared_early_return_multi() {
    let f = FunctionCode {
        instrs: vec![
            /* 0 */
            Instr::SharedIf {
                cond: Src::Var(Addr::Const(0)),
                else_target: 2,
            },
            /* 1 */
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(2)),
                n: 1,
            }, // return x
            /* 2 */ Instr::SharedElse { end_target: 3 },
            /* 3 */ Instr::SharedEnd,
            /* 4 */
            Instr::SharedIf {
                cond: Src::Var(Addr::Const(1)),
                else_target: 6,
            },
            /* 5 */
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(3)),
                n: 1,
            }, // return y
            /* 6 */ Instr::SharedElse { end_target: 7 },
            /* 7 */ Instr::SharedEnd,
            /* 8 */
            Instr::Ret {
                src: RetSrc::Var(Addr::Const(4)),
                n: 1,
            }, // return z
        ],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 5,
        num_params: 5,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
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
            Instr::Mov {
                dst: Dst::Reg(3),
                src: Src::Signal(Addr::Const(4)),
            },
            Instr::Mov {
                dst: Dst::Reg(4),
                src: Src::Signal(Addr::Const(5)),
            },
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 5,
                ret: 5,
                ret_n: 1,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(5),
            },
            Instr::Return,
        ],
        6,
        0,
        0,
        5,
        1,
        7,
        vec![f],
        vec!["f"],
    );

    let x = 100u64;
    let y = 200u64;
    let z = 300u64;

    // c1 = 1 -> x, regardless of c2.
    for c2 in [0u64, 1u64] {
        let signals = common::run_taint_with_consts(
            &program,
            vec![],
            vec![
                common::shared(1),
                common::shared(c2),
                common::public(x),
                common::public(y),
                common::public(z),
            ],
        );
        assert_eq!(signals[1].val, Fr::from(x), "c1=1, c2={c2}");
        assert!(signals[1].shared, "c1=1, c2={c2}");
    }

    // c1 = 0, c2 = 1 -> y.
    let signals = common::run_taint_with_consts(
        &program,
        vec![],
        vec![
            common::shared(0),
            common::shared(1),
            common::public(x),
            common::public(y),
            common::public(z),
        ],
    );
    assert_eq!(signals[1].val, Fr::from(y));
    assert!(signals[1].shared);

    // c1 = 0, c2 = 0 -> z (the ¬c1 ∧ ¬c2 accumulation).
    let signals = common::run_taint_with_consts(
        &program,
        vec![],
        vec![
            common::shared(0),
            common::shared(0),
            common::public(x),
            common::public(y),
            common::public(z),
        ],
    );
    assert_eq!(signals[1].val, Fr::from(z));
    assert!(signals[1].shared);
}

// f() has no Ret instruction at all: falling off the end of its body with an empty
// shared-return accumulator must error, not silently return garbage.
#[test]
fn fn_falls_off_end_without_shared_returns_is_error() {
    let f = FunctionCode {
        instrs: vec![Instr::ISet { dst: 0, val: 0 }],
        num_field_regs: 0,
        num_int_regs: 1,
        num_vars: 0,
        num_params: 0,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 0,
                ret: 0,
                ret_n: 1,
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
        0,
        1,
        2,
        vec![f],
        vec!["f"],
    );
    let mut driver = PlainDriver::default();
    let mut machine =
        Machine::new(&program, &mut driver, VMConfig::default()).expect("Machine::new");
    let err = machine
        .run_main()
        .expect_err("must error, not return garbage");
    assert!(
        err.to_string().contains("ended without returning"),
        "error message was: {err}"
    );
}
