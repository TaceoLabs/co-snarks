mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::taint::TaintDriver;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::VMConfig;

// signal layout: [0]=1, [1]=out, [2]=cond (component-relative: out=addr0, cond=addr1)
//
// k:0  SharedIf   { cond, else_target: 3 }
// k+1:1  Mov out = 111        (truthy)
// t:2  SharedElse { end_target: 4 }
// t+1:3  Mov out = 222        (else, = e)
// x:4  SharedEnd
//    5  Return
#[test]
fn public_if_takes_branch() {
    let program = common::single_template_program(
        vec![
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(1)),
                else_target: 3,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::SharedElse { end_target: 4 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(1),
            },
            Instr::SharedEnd,
            Instr::Return,
        ],
        0,
        0,
        0,
        1,
        1,
        3,
    );
    let consts = vec![Fr::from(111u64), Fr::from(222u64)];

    // cond = true (public): only the truthy Mov executes.
    let signals = common::run_taint_with_consts(&program, consts.clone(), vec![common::public(1)]);
    assert_eq!(signals[1].val, Fr::from(111u64));
    assert_ne!(signals[1].val, Fr::from(222u64));
    assert!(!signals[1].shared);

    // cond = false (public): only the else Mov executes.
    let signals = common::run_taint_with_consts(&program, consts, vec![common::public(0)]);
    assert_eq!(signals[1].val, Fr::from(222u64));
    assert_ne!(signals[1].val, Fr::from(111u64));
    assert!(!signals[1].shared);
}

// signal layout: [0]=1, [1]=out, [2]=cond (same layout as above).
// out = cond ? 3 : 5, both branches store into `out`; the result must be cmux'd and
// tainted shared even though the stored constants are public.
#[test]
fn shared_if_merges_stores() {
    let program = common::single_template_program(
        vec![
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(1)),
                else_target: 3,
            },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0),
            },
            Instr::SharedElse { end_target: 4 },
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(1),
            },
            Instr::SharedEnd,
            Instr::Return,
        ],
        0,
        0,
        0,
        1,
        1,
        3,
    );
    let consts = vec![Fr::from(3u64), Fr::from(5u64)];

    let signals = common::run_taint_with_consts(&program, consts.clone(), vec![common::shared(1)]);
    assert_eq!(signals[1].val, Fr::from(3u64));
    assert!(signals[1].shared);

    let signals = common::run_taint_with_consts(&program, consts, vec![common::shared(0)]);
    assert_eq!(signals[1].val, Fr::from(5u64));
    assert!(signals[1].shared);
}

// signal layout: [0]=1, [1]=out, [2]=cond1, [3]=cond2.
// out = cond1 ? (cond2 ? 11 : 22) : (cond2 ? 33 : 44), two nested shared ifs.
#[test]
fn nested_shared_ifs() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(1)),
                else_target: 7,
            },
            /* 1 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(2)),
                else_target: 4,
            },
            /* 2 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0),
            }, // out = 11
            /* 3 */ Instr::SharedElse { end_target: 5 },
            /* 4 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(1),
            }, // out = 22
            /* 5 */ Instr::SharedEnd,
            /* 6 */ Instr::SharedElse { end_target: 12 },
            /* 7 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(2)),
                else_target: 10,
            },
            /* 8 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(2),
            }, // out = 33
            /* 9 */ Instr::SharedElse { end_target: 11 },
            /* 10 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(3),
            }, // out = 44
            /* 11 */ Instr::SharedEnd,
            /* 12 */ Instr::SharedEnd,
            /* 13 */ Instr::Return,
        ],
        0,
        0,
        0,
        2,
        1,
        4,
    );
    let consts = vec![
        Fr::from(11u64),
        Fr::from(22u64),
        Fr::from(33u64),
        Fr::from(44u64),
    ];

    let cases = [
        (1u64, 1u64, 11u64),
        (1u64, 0u64, 22u64),
        (0u64, 1u64, 33u64),
        (0u64, 0u64, 44u64),
    ];
    for (c1, c2, expected) in cases {
        let signals = common::run_taint_with_consts(
            &program,
            consts.clone(),
            vec![common::shared(c1), common::shared(c2)],
        );
        assert_eq!(signals[1].val, Fr::from(expected), "cond1={c1}, cond2={c2}");
        assert!(signals[1].shared, "cond1={c1}, cond2={c2}");
    }
}

// signal layout: [0]=1, [1]=out, [2]=cond1 (outer, shared), [3]=cond2 (inner, public).
// A public if nested inside a shared if still takes a real jump (only one of its two
// stores executes), but that store is still predicated by the *outer* shared condition.
#[test]
fn public_inside_shared() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(1)),
                else_target: 7,
            },
            /* 1 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(2)),
                else_target: 4,
            },
            /* 2 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0),
            }, // out = 11
            /* 3 */ Instr::SharedElse { end_target: 5 },
            /* 4 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(1),
            }, // out = 22
            /* 5 */ Instr::SharedEnd,
            /* 6 */ Instr::SharedElse { end_target: 7 },
            /* 7 */ Instr::SharedEnd,
            /* 8 */ Instr::Return,
        ],
        0,
        0,
        0,
        2,
        1,
        4,
    );
    let consts = vec![Fr::from(11u64), Fr::from(22u64)];

    // Outer true, inner false: inner really jumps to its else (out = 22), and the
    // outer condition being true keeps the store.
    let signals = common::run_taint_with_consts(
        &program,
        consts.clone(),
        vec![common::shared(1), common::public(0)],
    );
    assert_eq!(signals[1].val, Fr::from(22u64));
    assert!(signals[1].shared);

    // Outer false, inner true: inner really jumps to its truthy branch (computing 11),
    // but the outer predicate is false, so the store is discarded — value stays at the
    // default (0) — yet the destination is still tainted shared by the outer cmux.
    let signals =
        common::run_taint_with_consts(&program, consts, vec![common::shared(0), common::public(1)]);
    assert_eq!(signals[1].val, Fr::from(0u64));
    assert!(signals[1].shared);
}

// signal layout: [0]=1, [1]=out, [2]=cond (shared), [3]=a (public, dividend).
// out = a / b inside the *else* branch of a shared if, where b is the literal
// constant 0. Without the guard this would error (or panic) on the field division;
// with the guard the divisor is replaced by 1 whenever the branch's effective
// predicate is false, so the division never actually happens on 0.
// Mirrors old circom-mpc-vm/src/mpc_vm.rs:614-622.
#[test]
fn shared_div_guard() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(1)),
                else_target: 2,
            },
            /* 1 */ Instr::SharedElse { end_target: 4 },
            /* 2 */
            Instr::Bin {
                op: BinOp::Div,
                dst: 0,
                a: Src::Signal(Addr::Const(2)),
                b: Src::Const(0),
            },
            /* 3 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(0),
            },
            /* 4 */ Instr::SharedEnd,
            /* 5 */ Instr::Return,
        ],
        1,
        0,
        0,
        2,
        1,
        4,
    );
    let consts = vec![Fr::from(0u64)];

    // cond = true, so the truthy region's effective predicate is true and the *else*
    // region (containing the divide-by-the-literal-0) has effective predicate false —
    // exactly the "shared-false branch" the guard must protect.
    let signals =
        common::run_taint_with_consts(&program, consts, vec![common::shared(1), common::public(5)]);
    // Must not error; the discarded division result never reaches `out`.
    assert_eq!(signals[1].val, Fr::from(0u64));
    assert!(signals[1].shared);
}

// signal layout: [0]=1, [1]=cond (component-relative addr 0; no outputs in this
// program). Documents current (old-VM-matching) semantics: `Assert` is NOT predicated
// by shared ifs — it inspects the literal computed value regardless of which branch's
// effective predicate is active. Matches old mpc_vm.rs:553-561, which has no
// `if_stack` check before the assertion.
#[test]
fn assert_inside_shared_false_branch() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(0)),
                else_target: 2,
            },
            /* 1 */ Instr::SharedElse { end_target: 3 },
            /* 2 */
            Instr::Assert {
                cond: Src::Const(0),
                line: 99,
            },
            /* 3 */ Instr::SharedEnd,
            /* 4 */ Instr::Return,
        ],
        0,
        0,
        0,
        1,
        0,
        2,
    );
    let mut program = program;
    program.constants = vec![Fr::from(0u64)];
    let mut driver = TaintDriver::<Fr>::default();
    let mut machine = Machine::new(&program, &mut driver, VMConfig::default()).unwrap();
    // cond = true, so the else branch (containing the literal-zero assert) has
    // effective predicate false — a naively-predicated Assert would consider it
    // "not really executed" and skip the check. The old (and this) VM does not do
    // that: the assert fires unconditionally and the run errors out.
    let info = program.main_input_list.first().unwrap();
    machine.signals[info.offset] = common::shared(1);
    let err = machine.run_main().unwrap_err();
    assert!(err.to_string().contains("99"), "error message was: {err}");
}
