mod common;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::isa::Instr;
use circom_mpc_vm2::program::VMConfig;
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn get_public_inputs_works() {
    let config = circom_mpc_compiler2::CompilerConfig::default();
    let inputs = circom_mpc_compiler2::CoCircomCompiler::<ark_bn254::Bn254>::get_public_inputs(
        "../../test_vectors/WitnessExtension/tests/multiplier2.circom".to_owned(),
        config,
    )
    .unwrap();
    assert!(inputs.is_empty()); // multiplier2 has no public inputs
}

/// The milestone test for the whole `circom-mpc-compiler2` plan: a circom circuit
/// compiled all the way down to the register ISA and executed to a correct witness.
///
/// `multiplier2` (the closest circuit in `test_vectors/WitnessExtension/tests/`) has no
/// KAT directory and additionally calls `log(...)`, which isn't lowered yet; every
/// KAT-backed circuit under `test_vectors/WitnessExtension/kats/` uses loops,
/// conditionals, or subcomponents (out of scope until Tasks 3+). Per the plan's
/// sanctioned fallback for this task, this instead exercises a purpose-written minimal
/// circuit (`tests/circuits/mul2.circom`, no loops/branches/functions/subcomponents)
/// with hand-chosen inputs, checked both via `get_output` and against a hand-computed
/// full witness vector. Real KAT circuits take over task by task as their required
/// features (loops, branches, subcomponents, ...) land.
#[test]
fn mul2_straight_line_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program =
        Arc::new(CoCircomCompiler::<Bn254>::parse("tests/circuits/mul2.circom", config).unwrap());

    let inputs = BTreeMap::from([
        ("a".to_string(), Fr::from(6u64)),
        ("b".to_string(), Fr::from(7u64)),
    ]);
    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();

    assert_eq!(finalized.get_output("c"), Some(vec![Fr::from(42u64)]));

    let witness = finalized.into_shared_witness();
    // signal layout (hand-computed against the circuit source): [0] = 1 (constant),
    // [1] = c (output), [2] = a, [3] = b (private inputs — mul2 declares no public
    // inputs).
    assert_eq!(witness.public_inputs, vec![Fr::from(1u64), Fr::from(42u64)]);
    assert_eq!(witness.witness, vec![Fr::from(6u64), Fr::from(7u64)]);
}

/// Regression test for the multi-register `LoadN` frame-size bug: a size-2 array copy
/// (`b <== a`) lowers its right-hand side through a size-2 `LoadBucket`, which
/// materializes into a *contiguous block* of registers (see
/// `circom-mpc-compiler2/src/codegen/expr.rs`'s `materialize`). The allocator previously
/// reserved only one register for the whole block, undercounting the frame by `n - 1` and
/// letting the VM read/write past the register file (or alias later temporaries) — this
/// exercises exactly that path end to end.
#[test]
fn array_copy_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/array_copy.circom", config).unwrap(),
    );

    // The template must have reserved a contiguous 2-register block for the array load,
    // not just one register for its base.
    assert!(
        program.templates[program.main.0 as usize].num_field_regs >= 2,
        "template must reserve at least 2 field registers for the size-2 array load"
    );

    // Array inputs of size n are passed as `name[0]..name[n-1]` keys (circom's own
    // naming convention — see `WitnessExtension::run`'s doc comment).
    let inputs = BTreeMap::from([
        ("a[0]".to_string(), Fr::from(7u64)),
        ("a[1]".to_string(), Fr::from(9u64)),
    ]);

    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();

    assert_eq!(
        finalized.get_output("b"),
        Some(vec![Fr::from(7u64), Fr::from(9u64)])
    );
}

/// The milestone test for Task 3 (symbolic index evaluation): a signal-valued array
/// index (`out1 <-- a[idx]`, the brief's own `in[a]` example) exercises the
/// `ToAddress`->`Instr::ToIndex`->`Dynamic` path in `codegen::index`; a 2D array indexed
/// by two signals (`out2 <-- b[i][j]`) exercises the same path nested inside
/// `AddAddress`/`MulAddress` folding (both operands `Dynamic`, materializing into
/// `IMul`/`IAdd`); a 2D array indexed by literals (`out3 <== b[0][1]`) exercises the
/// `Const` leaf through the very same `addr_from_location_rule`/`eval_index` path that
/// replaced Task 2's constant-only special case.
///
/// None of the KAT suite's candidate circuits (`array_equals`, `constants_test`,
/// `isequal`, `iszero`, `winner`) exercise computed array indexing at all — the only one
/// that compiles today without loops/branches/functions/subcomponents is `array_equals`,
/// and it never indexes its arrays (see `array_equals_kat`, this file). Per the plan's
/// sanctioned fallback, this instead exercises a purpose-written circuit.
#[test]
fn dynamic_index_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/dynamic_index.circom", config).unwrap(),
    );

    let mut inputs = BTreeMap::new();
    for k in 0..4 {
        inputs.insert(format!("a[{k}]"), Fr::from(10 + k as u64));
    }
    inputs.insert("idx".to_string(), Fr::from(2u64));
    for k in 0..6 {
        // `b[2][3]` is passed flat, row-major (circom's own convention): `b[r][c]` lives
        // at input key `b[r*3 + c]`.
        inputs.insert(format!("b[{k}]"), Fr::from(100 + k as u64));
    }
    inputs.insert("i".to_string(), Fr::from(1u64));
    inputs.insert("j".to_string(), Fr::from(2u64));

    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();

    assert_eq!(
        finalized.get_output("out1"),
        Some(vec![Fr::from(12u64)]),
        "a[idx=2]"
    );
    assert_eq!(
        finalized.get_output("out2"),
        Some(vec![Fr::from(105u64)]),
        "b[i=1][j=2] = b[1*3+2] = b[5]"
    );
    assert_eq!(
        finalized.get_output("out3"),
        Some(vec![Fr::from(101u64)]),
        "b[0][1] = b[1]"
    );
}

/// A real KAT circuit exercising `EqN`: `a === b` on two size-2 arrays lowers to
/// `AssertBucket { evaluate: ComputeBucket { op: Eq(2), .. } }` (circom's front end
/// always wraps `===` this way, regardless of array size — see
/// `codegen::stmt::lower_assert`'s doc comment), so this is also the milestone test for
/// `Instr::Assert` (implemented this task specifically to make `EqN` reachable: it is the
/// *only* IR shape that ever carries an `Eq` operator of size > 1). `array_equals` is the
/// one candidate from the brief's KAT list that compiles today without loops, branches,
/// functions, or subcomponents (`constants_test` needs a loop, `isequal`/`iszero` need a
/// branch, `winner` needs functions, loops, and subcomponents — all out of scope until
/// their own tasks).
#[test]
fn array_equals_kat() {
    common::assert_kats("array_equals", CompilerConfig::default());
}

/// The real-KAT milestone test for Task 4 (rolled loops, induction-variable promotion):
/// `BinSum(4, 3)` (circomlib's `binsum.circom`, `component main = BinSum(4,3);`) has two
/// top-level loops — a nested ascending pair (`for(k) for(j)` summing weighted bits into
/// `lin`) and a second ascending loop (`for(k)` decomposing `lin` back into `out` bits) —
/// no branches, no subcomponents (its one dependency, `nbits(...)`, is a `function` used
/// only to compute the *template parameter* `nout` at monomorphization time, so it never
/// appears as a runtime `Call` bucket; confirmed empirically — every other candidate from
/// the brief's own list, `binsub_test`/`aliascheck_test`/`constants_test`/the comparator
/// family, instantiates at least one subcomponent *somewhere* in its template graph and
/// so still bails on `CreateCmp`, Task 8). Both loops match `detect_conforming`'s pattern
/// (see `inspect_binsum_takes_the_affine_path` below, which confirms this on the same
/// circuit): this is a real circuit exercising the conforming/`Affine` path end to end,
/// not just the purpose-built fixtures below.
#[test]
fn binsum_test_kat() {
    common::assert_kats("binsum_test", CompilerConfig::default());
}

/// White-box companion to [`binsum_test_kat`]: confirms the KAT circuit actually takes
/// the conforming (`Affine`) path — an `Addr::Affine` operand and at least one
/// `Instr::ISet` (the induction variable's mirror register being initialized) must appear
/// in the compiled template — rather than merely happening to produce the right answer
/// via the (always-correct) fallback path.
#[test]
fn inspect_binsum_takes_the_affine_path() {
    let program = common::compile("binsum_test", CompilerConfig::default());
    let instrs = &program.templates[program.main.0 as usize].instrs;
    assert!(
        instrs.iter().any(|i| matches!(i, Instr::ISet { .. })),
        "a conforming loop's induction variable must be mirrored via ISet"
    );
    assert!(
        instrs.iter().any(instr_uses_affine),
        "an index-position read of a promoted induction variable must resolve to \
         Addr::Affine"
    );
}

/// Returns whether `instr` reads or writes through an [`Addr::Affine`] operand (a
/// `Debug`-string check is enough here — this is diagnostic test code, not codegen).
fn instr_uses_affine(instr: &Instr) -> bool {
    format!("{instr:?}").contains("Affine")
}

/// The Affine-path milestone test the brief asks for explicitly (`tests/circuits/
/// loop_ascending.circom`, a purpose-built fixture since `binsum_test`'s real KAT above
/// exercises the same path but bundled with a lot of unrelated bit arithmetic): a plain
/// ascending `for` loop indexing an array on both sides (`out[i] <== a[i] + 1`) must
/// compile to `Addr::Affine` addressing and produce the correct witness.
#[test]
fn loop_ascending_takes_the_affine_path() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_ascending.circom", config).unwrap(),
    );

    let instrs = &program.templates[program.main.0 as usize].instrs;
    assert!(
        instrs.iter().any(instr_uses_affine),
        "a[i]/out[i] inside a conforming loop must resolve to Addr::Affine"
    );

    let mut inputs = BTreeMap::new();
    for k in 0..5 {
        inputs.insert(format!("a[{k}]"), Fr::from(10 + k as u64));
    }
    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();
    assert_eq!(
        finalized.get_output("out"),
        Some((0..5).map(|k| Fr::from(11 + k as u64)).collect())
    );
}

/// The fallback-correctness milestone test the brief asks for explicitly (`tests/
/// circuits/loop_descending.circom`): a descending `for` loop is non-conforming by
/// design (see the circuit's own doc comment and `detect_conforming`'s docs) — its
/// induction variable stays a plain `FieldSlot`, and `a[i]`/`out[i]` fall through the
/// ordinary `ToAddress`/`Instr::ToIndex`/`Dynamic` path. This asserts both that no
/// `Instr::ISet` appears (confirming the fallback path was actually taken, not just
/// "happened to produce the right answer") and that the witness is still correct.
#[test]
fn loop_descending_stays_correct_via_fallback() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_descending.circom", config).unwrap(),
    );

    let instrs = &program.templates[program.main.0 as usize].instrs;
    assert!(
        !instrs.iter().any(|i| matches!(i, Instr::ISet { .. })),
        "a descending loop must never promote its induction variable"
    );

    let mut inputs = BTreeMap::new();
    for k in 0..5 {
        inputs.insert(format!("a[{k}]"), Fr::from(20 + k as u64));
    }
    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();
    assert_eq!(
        finalized.get_output("out"),
        Some((0..5).map(|k| Fr::from(21 + k as u64)).collect())
    );
}

/// The nested-loop `ireg`-scoping regression test (`tests/circuits/loop_nested.circom`):
/// the outer loop's `out[i] <== sum` write happens *after* the inner `j` loop has
/// allocated and released its own persistent mirror register, so a wrong scoping
/// discipline (the outer's `ireg` clobbered or prematurely freed) would show up as a
/// wrong witness here, even though every individual constraint still type-checks (see
/// `codegen::stmt::lower_loop`'s module docs, "Where the persistent integer register
/// lives").
#[test]
fn loop_nested_ireg_scoping_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_nested.circom", config).unwrap(),
    );

    let mut inputs = BTreeMap::new();
    let mut expected = Vec::new();
    for i in 0..3u64 {
        let mut sum = 0u64;
        for j in 0..4u64 {
            let v = i * 4 + j + 1;
            inputs.insert(format!("a[{}]", i * 4 + j), Fr::from(v));
            sum += v;
        }
        expected.push(Fr::from(sum));
    }

    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();
    assert_eq!(finalized.get_output("out"), Some(expected));
}
