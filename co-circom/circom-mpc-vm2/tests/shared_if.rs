mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::drivers::taint::TaintDriver;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::{FunctionCode, VMConfig};

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

// signal layout (component-relative addresses; global index = comp.offset(1) + addr):
// [0]=1, [1..3]=out (2 elements, addr 0..2), [3]=cond (addr 2, shared), [4..6]=a (addr
// 3..5, public dividends). out[0..2] = a[0..2] / b[0..2] inside the *else* branch of a
// shared if,
// vectorized via `BinN`, where the divisors are the literal constants [0, 3] — one of
// them is zero. Without the guard the vectorized `bin_many` call would bypass the
// scalar `Bin` guard and error (or panic) on the field division; with the guard the
// divisors are replaced by 1 whenever the branch's effective predicate is false, so
// the division never actually happens on the zero divisor.
#[test]
fn shared_div_guard_binn() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(2)),
                else_target: 2,
            },
            /* 1 */ Instr::SharedElse { end_target: 5 },
            /* 2 */
            Instr::BinN {
                op: BinOp::Div,
                dst: 0,
                a: Src::Signal(Addr::Const(3)),
                b: Src::Const(0),
                n: 2,
            },
            /* 3 */
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(0)),
                src: 0,
                n: 2,
            },
            /* 4 */ Instr::SharedEnd,
            /* 5 */ Instr::Return,
        ],
        2,
        0,
        0,
        3,
        2,
        6,
    );
    let consts = vec![Fr::from(0u64), Fr::from(3u64)];

    // cond = true, so the truthy region's effective predicate is true and the *else*
    // region (containing the vectorized divide-by-the-literal-[0, 3]) has effective
    // predicate false — exactly the "shared-false branch" the guard must protect.
    let signals = common::run_taint_with_consts(
        &program,
        consts,
        vec![common::shared(1), common::public(5), common::public(7)],
    );
    // Must not error; the discarded division results never reach `out`.
    assert_eq!(signals[1].val, Fr::from(0u64));
    assert!(signals[1].shared);
    assert_eq!(signals[2].val, Fr::from(0u64));
    assert!(signals[2].shared);
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

// `f(x) = x + 100`, called from inside a caller-side `SharedIf` on a *tainted* cond,
// where `f`'s own `Ret` is unconditional (no `SharedIf` inside `f` at all). The callee
// still sees the caller's shared predication (threaded through by reference — see
// `Machine::run_function`), so its `Ret` must take the accumulating path and return
// `cond * f(x)`, not the raw `f(x)` (that would be the fast path firing incorrectly).
// The caller then stores that into `out` (pre-set to 999) under the same predicate, so
// the final value must equal `cond*f(x) + (1-cond)*999` — i.e. `f(x)` when cond=1, and
// the untouched pre-existing 999 when cond=0 — and `out` must be tainted shared in both
// cases (the predicate itself is shared).
//
// signal layout: [0]=1, [1]=out, [2]=cond, [3]=x.
#[test]
fn callfn_inside_shared_if_merges_with_pre_existing_value() {
    let f = FunctionCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Var(Addr::Const(0)),
                b: Src::Const(1), // consts[1] = 100
            },
            Instr::Ret {
                src: RetSrc::Reg(0),
                n: 1,
            },
        ],
        num_field_regs: 1,
        num_int_regs: 0,
        num_vars: 1,
        num_params: 1,
        name_id: 1,
    };
    let program = common::program_with_functions(
        vec![
            /* 0 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Const(0), // out = 999 (pre-existing value)
            },
            /* 1 */
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Signal(Addr::Const(2)), // r0 = x
            },
            /* 2 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(1)), // cond
                else_target: 6,
            },
            /* 3 */
            Instr::CallFn {
                fn_id: FnId(0),
                args_start: 0,
                args_n: 1,
                ret: 1,
                ret_n: 1,
            }, // r1 = f(x), merged with caller's shared cond internally
            /* 4 */
            Instr::Mov {
                dst: Dst::Signal(Addr::Const(0)),
                src: Src::Reg(1), // out = r1, predicated by the still-active SharedIf
            },
            /* 5 */ Instr::SharedElse { end_target: 6 },
            /* 6 */ Instr::SharedEnd,
            /* 7 */ Instr::Return,
        ],
        2,
        0,
        0,
        2,
        1,
        4,
        vec![f],
        vec!["f"],
    );
    let consts = vec![Fr::from(999u64), Fr::from(100u64)];

    // cond shared(1): result = f(x) = x + 100.
    let signals = common::run_taint_with_consts(
        &program,
        consts.clone(),
        vec![common::shared(1), common::public(7)],
    );
    assert_eq!(signals[1].val, Fr::from(107u64));
    assert!(signals[1].shared);

    // cond shared(0): result = the pre-existing 999, not f(x).
    let signals =
        common::run_taint_with_consts(&program, consts, vec![common::shared(0), common::public(7)]);
    assert_eq!(signals[1].val, Fr::from(999u64));
    assert!(signals[1].shared);
}

// signal layout (component-relative addresses; global index = comp.offset(1) + addr):
// [0]=1, [1..9]=out (8 elements, addr 0..8), [9]=cond (addr 8), [10..18]=a (addr 9..17,
// mixed shared/public values). `out[0..8] = a[0..8]` inside the truthy branch of a
// (possibly shared) `if`, batched through a single `StoreN{n:8}` — exercises
// `write_dst_n`'s `cmux_many` path (see `exec.rs`) end to end, per-element, with a
// distinct value at every index (order/scatter bugs would show as a mismatch at some
// index) and a deliberately mixed shared/public pattern across `a` (index parity) so a
// per-element taint mixup would also show up.
#[test]
fn predicated_storen_batch_values_and_flags() {
    let program = common::single_template_program(
        vec![
            /* 0 */
            Instr::LoadN {
                dst: 0,
                src: Src::Signal(Addr::Const(9)),
                n: 8,
            },
            /* 1 */
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(8)),
                else_target: 3,
            },
            /* 2 */
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(0)),
                src: 0,
                n: 8,
            },
            /* 3 */ Instr::SharedElse { end_target: 4 },
            /* 4 */ Instr::SharedEnd,
            /* 5 */ Instr::Return,
        ],
        8,
        0,
        0,
        9,
        8,
        18,
    );

    // a[i] = 10 + i, alternating shared/public by parity.
    let a_inputs: Vec<_> = (0..8u64)
        .map(|i| {
            if i % 2 == 0 {
                common::shared(10 + i)
            } else {
                common::public(10 + i)
            }
        })
        .collect();
    let expected_a: Vec<Fr> = (0..8u64).map(|i| Fr::from(10 + i)).collect();

    // cond = shared(1): truthy branch selected — out[i] == a[i], and every element is
    // shared regardless of a[i]'s own flag (the merge ORs in the shared cond).
    let mut inputs = vec![common::shared(1)];
    inputs.extend(a_inputs.iter().cloned());
    let signals = common::run_taint_with_consts(&program, vec![], inputs);
    for i in 0..8 {
        assert_eq!(
            signals[1 + i].val,
            expected_a[i],
            "index {i}, cond=shared(1)"
        );
        assert!(signals[1 + i].shared, "index {i}, cond=shared(1)");
    }

    // cond = shared(0): truthy branch's effective predicate is false — out keeps its
    // pre-existing value (default 0), still tagged shared (cond is shared).
    let mut inputs = vec![common::shared(0)];
    inputs.extend(a_inputs.iter().cloned());
    let signals = common::run_taint_with_consts(&program, vec![], inputs);
    for i in 0..8 {
        assert_eq!(
            signals[1 + i].val,
            Fr::from(0u64),
            "index {i}, cond=shared(0)"
        );
        assert!(signals[1 + i].shared, "index {i}, cond=shared(0)");
    }

    // cond = public(1): a real jump is taken, no predication at all — out[i] == a[i]
    // exactly, each element keeping its own (mixed) shared flag.
    let mut inputs = vec![common::public(1)];
    inputs.extend(a_inputs.iter().cloned());
    let signals = common::run_taint_with_consts(&program, vec![], inputs);
    for i in 0..8 {
        assert_eq!(
            signals[1 + i].val,
            expected_a[i],
            "index {i}, cond=public(1)"
        );
        assert_eq!(
            signals[1 + i].shared,
            i % 2 == 0,
            "index {i}, cond=public(1)"
        );
    }
}
