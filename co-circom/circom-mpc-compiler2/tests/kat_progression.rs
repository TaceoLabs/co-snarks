mod common;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use circom_mpc_vm2::api::PlainWitnessExtension;
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
