mod common;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig, SimplificationLevel, UnrollConfig};
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::isa::{ISrc, Instr};
use circom_mpc_vm2::program::{CompiledProgram, VMConfig};
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
/// via the (always-correct) fallback path. `unroll.threshold: 0` pins this to the
/// rolled/mirror-promoted path specifically (Task 5's default threshold is large enough
/// that `binsum_test`'s loops unroll away entirely under `CompilerConfig::default()`,
/// which would make this assertion moot, not wrong).
#[test]
fn inspect_binsum_takes_the_affine_path() {
    let config = CompilerConfig {
        unroll: UnrollConfig { threshold: 0 },
        ..CompilerConfig::default()
    };
    let program = common::compile("binsum_test", config);
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
/// compile to `Addr::Affine` addressing and produce the correct witness. `unroll.
/// threshold: 0` pins this to the rolled/mirror-promoted path (see
/// [`inspect_binsum_takes_the_affine_path`] for why: this circuit's 5-iteration loop is
/// well within Task 5's default unroll threshold).
#[test]
fn loop_ascending_takes_the_affine_path() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        unroll: UnrollConfig { threshold: 0 },
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
/// lives"). `unroll.threshold: 0` pins this to the rolled/mirror-promoted path — the
/// mechanism this regression test actually targets — rather than Task 5's unrolling,
/// which this small nested loop would otherwise qualify for under the default threshold.
#[test]
fn loop_nested_ireg_scoping_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        unroll: UnrollConfig { threshold: 0 },
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

/// Counts `Jmp`/`JmpIfZero` instructions across every template — a rolled loop always
/// contributes exactly one of each ([`emit_loop_head`]/[`finish_loop`] in
/// `codegen::stmt`); a fully-unrolled loop contributes zero. Used by the Task 5 tests
/// below as a size-independent, mechanism-level signal that unrolling actually engaged
/// (as opposed to merely happening to still produce a correct witness).
fn jmp_count(program: &CompiledProgram<Fr>) -> usize {
    program
        .templates
        .iter()
        .flat_map(|t| t.instrs.iter())
        .filter(|i| matches!(i, Instr::Jmp { .. } | Instr::JmpIfZero { .. }))
        .count()
}

/// Every `Instr::BinN` across every template, paired with its `n` — used by the BinN-
/// fusion tests below both to confirm fusion engaged (a nonempty result with some `n >=
/// 4`) and to confirm it was correctly skipped (an empty result, e.g. for an unrolled
/// body containing a branch — see `codegen::stmt`'s BinN-fusion module docs).
fn binn_instrs(program: &CompiledProgram<Fr>) -> Vec<u32> {
    program
        .templates
        .iter()
        .flat_map(|t| t.instrs.iter())
        .filter_map(|i| match i {
            Instr::BinN { n, .. } => Some(*n),
            _ => None,
        })
        .collect()
}

/// The Task 5 milestone test: `binsum_test` (already the proven componentless,
/// loop-heavy KAT — see [`binsum_test_kat`] above) run twice, once with unrolling
/// disabled entirely (`threshold: 0`) and once forced wherever statically possible
/// (`threshold: usize::MAX`) — both must still match the KAT witness exactly (unrolling
/// is a codegen-only optimization; it must never change what a circuit computes) — via
/// [`common::assert_kats_with`]. Beyond witness equivalence, the fully-unrolled program
/// must have strictly fewer `Jmp`/`JmpIfZero` instructions than the rolled one ([`jmp_
/// count`]) — the sanity that unrolling actually eliminated loops, not just happened to
/// still produce a correct answer via the (always-correct) rolled path.
#[test]
fn binsum_test_unrolling_matches_rolled_kat() {
    common::assert_kats_with("binsum_test", |cfg| cfg.unroll.threshold = 0);
    common::assert_kats_with("binsum_test", |cfg| cfg.unroll.threshold = usize::MAX);

    let rolled = common::compile(
        "binsum_test",
        CompilerConfig {
            unroll: UnrollConfig { threshold: 0 },
            ..Default::default()
        },
    );
    let unrolled = common::compile(
        "binsum_test",
        CompilerConfig {
            unroll: UnrollConfig {
                threshold: usize::MAX,
            },
            ..Default::default()
        },
    );

    let rolled_jumps = jmp_count(&rolled);
    let unrolled_jumps = jmp_count(&unrolled);
    assert!(
        unrolled_jumps < rolled_jumps,
        "a fully-unrolled program must have strictly fewer Jmp/JmpIfZero instructions \
         than the rolled one (rolled={rolled_jumps}, unrolled={unrolled_jumps})"
    );
}

/// Default-threshold sanity check (not a forced outcome — see the brief's Step 1): with
/// `CompilerConfig::default()`'s `unroll.threshold` (`4096`), `binsum_test`'s loops (5
/// iterations outer, small inner; well under the default budget once estimated) unroll
/// away *entirely* — the compiled program has zero `Jmp`/`JmpIfZero` instructions,
/// confirmed empirically via [`binsum_test_unrolling_matches_rolled_kat`]'s own
/// `threshold: usize::MAX` case producing the same `jmp_count` of `0` as the default
/// config does. This assertion pins that observation as a regression signal (default
/// unrolling engaging at all) without pinning *how much* unrolls, so a future change to
/// the default threshold's exact value doesn't spuriously break this test as long as
/// `binsum_test` still unrolls under whatever the default becomes.
#[test]
fn binsum_test_default_config_unrolls() {
    let default_program = common::compile("binsum_test", CompilerConfig::default());
    let rolled_program = common::compile(
        "binsum_test",
        CompilerConfig {
            unroll: UnrollConfig { threshold: 0 },
            ..Default::default()
        },
    );
    assert!(
        jmp_count(&default_program) < jmp_count(&rolled_program),
        "binsum_test must unroll at least partially under the default unroll threshold"
    );
}

/// The Task 5 BinN-fusion milestone test (`tests/circuits/elementwise_mul.circom`, a
/// purpose-written `out[i] <== a[i] * b[i]` loop over 8 elements — no KAT directory of
/// its own, same rationale as `mul2_straight_line_end_to_end`/`array_copy_end_to_end`
/// above): at `unroll.threshold: usize::MAX` the unrolled body's 16 `Bin`/`Mov`
/// instructions must collapse into one `BinN{n: 8}` + one `StoreN` (fewer total
/// instructions than the `threshold: 0` compile, which never unrolls and so never fuses
/// either), and both thresholds must still agree on the hand-computed witness — fusion
/// is a codegen-only optimization, never a semantic one.
#[test]
fn elementwise_mul_binn_fusion_end_to_end() {
    let rolled = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        unroll: UnrollConfig { threshold: 0 },
        ..Default::default()
    };
    let unrolled = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        unroll: UnrollConfig {
            threshold: usize::MAX,
        },
        ..Default::default()
    };

    let rolled_program =
        CoCircomCompiler::<Bn254>::parse("tests/circuits/elementwise_mul.circom", rolled).unwrap();
    let unrolled_program =
        CoCircomCompiler::<Bn254>::parse("tests/circuits/elementwise_mul.circom", unrolled)
            .unwrap();

    assert!(
        binn_instrs(&rolled_program).is_empty(),
        "a rolled body must never fuse into BinN"
    );
    assert_eq!(
        binn_instrs(&unrolled_program),
        vec![8],
        "the fully-unrolled body must fuse its 8-iteration run into one BinN{{n: 8}}"
    );

    let rolled_len: usize = rolled_program
        .templates
        .iter()
        .map(|t| t.instrs.len())
        .sum();
    let unrolled_len: usize = unrolled_program
        .templates
        .iter()
        .map(|t| t.instrs.len())
        .sum();
    assert!(
        unrolled_len < rolled_len,
        "fusion must leave the fully-unrolled program with fewer total instructions than \
         the rolled one (rolled={rolled_len}, unrolled={unrolled_len})"
    );

    let a_vals: Vec<u64> = (0..8u64).map(|i| 10 + i).collect();
    let b_vals: Vec<u64> = (0..8u64).map(|i| 20 + i).collect();
    let expected: Vec<Fr> = a_vals
        .iter()
        .zip(&b_vals)
        .map(|(a, b)| Fr::from(a * b))
        .collect();
    for (name, program) in [("rolled", rolled_program), ("unrolled", unrolled_program)] {
        let mut inputs = BTreeMap::new();
        for (i, v) in a_vals.iter().enumerate() {
            inputs.insert(format!("a[{i}]"), Fr::from(*v));
        }
        for (i, v) in b_vals.iter().enumerate() {
            inputs.insert(format!("b[{i}]"), Fr::from(*v));
        }
        let finalized = PlainWitnessExtension::new_plain(Arc::new(program), VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        assert_eq!(
            finalized.get_output("out"),
            Some(expected.clone()),
            "{name}"
        );
    }
}

/// Non-unit loop-step end-to-end fixture (Task 7 of the rep3-accel-bench plan):
/// `tests/circuits/loop_step_gather.circom`'s `for (i = 0; i < 10; i += 3)` is the first
/// fixture in this suite whose induction variable does not increment by exactly `1` per
/// iteration. Run at `unroll.threshold: 0` (rolled — `detect_conforming`'s mirrored
/// `ireg` path, stepping by `3` each `IAdd`) and `usize::MAX` (fully unrolled — each `a[i]`
/// index folds to a compile-time constant instead), both must gather the same four
/// elements (`a[0], a[3], a[6], a[9]`, each `+ 1`) into `out`.
#[test]
fn loop_step_gather_non_unit_step_both_thresholds() {
    let a_vals: Vec<u64> = (0..10u64).map(|i| 100 + i).collect();
    let expected: Vec<Fr> = [0usize, 3, 6, 9]
        .iter()
        .map(|&i| Fr::from(a_vals[i] + 1))
        .collect();

    for threshold in [0, usize::MAX] {
        let config = CompilerConfig {
            simplification: SimplificationLevel::O2(usize::MAX),
            unroll: UnrollConfig { threshold },
            ..Default::default()
        };
        let program = Arc::new(
            CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_step_gather.circom", config)
                .unwrap(),
        );

        let mut inputs = BTreeMap::new();
        for (i, v) in a_vals.iter().enumerate() {
            inputs.insert(format!("a[{i}]"), Fr::from(*v));
        }
        let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        assert_eq!(
            finalized.get_output("out"),
            Some(expected.clone()),
            "threshold={threshold}"
        );
    }
}

/// The Task 5 BinN-fusion real-KAT test: `winner` (`test_vectors/WitnessExtension/tests/
/// winner.circom`, already a proven KAT — see `winner_kat` above) happens to contain an
/// unrolled elementwise loop (inside its `UniqueHighestValWithId` library component) that
/// fuses into a `BinN{n: 4}` at `unroll.threshold: usize::MAX` — a real circuit's fused
/// path exercised end to end, run through [`common::assert_kats_with`] at both `0`
/// (rolled — must never fuse) and `usize::MAX` (fused) against the same ground-truth
/// witnesses `winner_kat` already checks.
#[test]
fn winner_binn_fusion_matches_rolled_kat() {
    common::assert_kats_with("winner", |cfg| cfg.unroll.threshold = 0);
    common::assert_kats_with("winner", |cfg| cfg.unroll.threshold = usize::MAX);

    let rolled = common::compile(
        "winner",
        CompilerConfig {
            unroll: UnrollConfig { threshold: 0 },
            ..Default::default()
        },
    );
    let unrolled = common::compile(
        "winner",
        CompilerConfig {
            unroll: UnrollConfig {
                threshold: usize::MAX,
            },
            ..Default::default()
        },
    );

    assert!(
        binn_instrs(&rolled).is_empty(),
        "a rolled body must never fuse into BinN"
    );
    assert!(
        binn_instrs(&unrolled).iter().any(|&n| n >= 4),
        "winner's fully-unrolled compile must contain a fused BinN with n >= 4, got {:?}",
        binn_instrs(&unrolled)
    );
}

/// The highest-risk unrolling scenario's end-to-end correctness check
/// (`tests/circuits/loop_final_value.circom`): a loop that unrolls, followed by a
/// *value-position* read of its induction variable after the loop has finished (`final_i
/// <== i;`). Unrolling skips the loop's own real increment store outright and only ever
/// binds `i` to a compile-time `ConstUsize` *inside* the loop body (see `codegen::stmt`'s
/// "Unrolling" module docs), so if this crate ever got the post-loop value wrong, it
/// would show up here. Run at both `unroll.threshold: 0` (rolled/mirror-promoted path) and
/// `usize::MAX` (fully unrolled): both must agree that `final_i == 5`.
///
/// This does *not*, however, actually exercise `try_unroll_loop`'s trailing resync `Mov`:
/// circom's own front end resolves a conforming loop's induction variable to a literal
/// constant at any point after the loop where its value is provably known (which, for a
/// literal-bounded ascending counter, is always) — confirmed empirically, this circuit
/// compiles `final_i <== i;` straight to a constant `Mov`, at both thresholds, with no
/// runtime `Load` of the variable at all, so this test would still pass even with the
/// resync `Mov` deleted. The real regression test for that is a white-box, hand-built-IR
/// unit test that bypasses circom's front end entirely:
/// `codegen::stmt::tests::try_unroll_loop_resyncs_slot_to_final_value_for_post_loop_reads`.
#[test]
fn loop_final_value_post_loop_read_both_thresholds() {
    for threshold in [0, usize::MAX] {
        let config = CompilerConfig {
            simplification: SimplificationLevel::O2(usize::MAX),
            unroll: UnrollConfig { threshold },
            ..Default::default()
        };
        let program = Arc::new(
            CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_final_value.circom", config)
                .unwrap(),
        );

        let mut inputs = BTreeMap::new();
        for k in 0..5u64 {
            inputs.insert(format!("in[{k}]"), Fr::from(10 + k));
        }
        let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
            .run(inputs, 0)
            .unwrap();

        assert_eq!(
            finalized.get_output("final_i"),
            Some(vec![Fr::from(5u64)]),
            "post-loop read of the induction variable must see its final value \
             (threshold={threshold})"
        );
        assert_eq!(
            finalized.get_output("acc_out"),
            Some(vec![Fr::from(10 + 11 + 12 + 13 + 14u64)]),
            "loop body itself must still be correct (threshold={threshold})"
        );
    }
}

/// The mixed-mode milestone test: an inner conforming loop unrolls while its outer
/// conforming loop stays rolled, both decisions made independently per the same size
/// heuristic against the same [`CompilerConfig::unroll`] threshold (see `codegen::stmt`'s
/// "Unrolling" module docs on how nesting composes). `tests/circuits/loop_nested.circom`
/// (outer `i < 3`, inner `j < 4`, one `Bin`+`Mov` per inner iteration) has a wide empirical
/// window (`threshold` in `8..=32`, confirmed by sweeping every threshold from `0` to
/// `usize::MAX`) where the inner loop's small per-iteration cost clears the bar but the
/// outer loop's — which, since it's evaluated *after* the inner loop has already been
/// (unrolled-)lowered inside the same estimation pass, includes the inner loop's own
/// unrolled cost — doesn't; `16` sits comfortably inside it. `jmp_count == 2` (exactly the
/// outer loop's own head/back-edge pair) distinguishes this from both the fully-rolled
/// baseline (`4`, two loops' worth) and the fully-unrolled one (`0`), and the witness must
/// still be correct.
#[test]
fn loop_nested_mixed_unroll_inner_only() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        unroll: UnrollConfig { threshold: 16 },
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_nested.circom", config).unwrap(),
    );

    assert_eq!(
        jmp_count(&program),
        2,
        "only the outer loop should stay rolled (contributing its own Jmp+JmpIfZero \
         pair); the inner loop must unroll away entirely"
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

/// Counts how many instructions across every template match `matches`, for the Task 6
/// shape assertions below (mirroring [`jmp_count`]'s pattern for `Instr::SharedIf`/
/// `SharedElse`/`SharedEnd`).
fn instr_count(program: &CompiledProgram<Fr>, matches: impl Fn(&Instr) -> bool) -> usize {
    program
        .templates
        .iter()
        .flat_map(|t| t.instrs.iter())
        .filter(|i| matches(i))
        .count()
}

/// The Task 6 "with else" milestone test (`tests/circuits/branch_if_else.circom`):
/// correctness in both directions of the branch (`a < 5` and `a >= 5`) plus the
/// instruction-shape assertion the brief calls for — exactly one `SharedIf`, one
/// `SharedElse`, and one `SharedEnd`, matching `codegen::stmt::lower_branch`'s documented
/// "with else" layout exactly (no stray extra branch-related instructions).
#[test]
fn branch_if_else_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/branch_if_else.circom", config).unwrap(),
    );

    assert_eq!(
        instr_count(&program, |i| matches!(i, Instr::SharedIf { .. })),
        1
    );
    assert_eq!(
        instr_count(&program, |i| matches!(i, Instr::SharedElse { .. })),
        1,
        "an if/else must emit exactly one SharedElse"
    );
    assert_eq!(instr_count(&program, |i| matches!(i, Instr::SharedEnd)), 1);

    for (a, expected) in [(3u64, 103u64), (7u64, 207u64)] {
        let inputs = BTreeMap::from([("a".to_string(), Fr::from(a))]);
        let finalized = PlainWitnessExtension::new_plain(program.clone(), VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        assert_eq!(
            finalized.get_output("out"),
            Some(vec![Fr::from(expected)]),
            "a={a}"
        );
    }
}

/// Coverage-gap fix (Task 6 review): every other test in this file drives
/// `PlainDriver`/`PlainWitnessExtension`, whose `is_shared` is always `false` — no
/// compiler2-emitted branch code has ever actually run the SHARED half of `Instr::SharedIf`'s
/// runtime dispatch (`circom_mpc_vm2::exec::Machine::step`'s `self.driver.is_shared(&c)?`
/// check, which decides between a plain jump and the both-arms-run/cmux "predicated merge"
/// path). This test reuses the same purpose-built `branch_if_else.circom` fixture as
/// [`branch_if_else_end_to_end`] above, but drives it with
/// [`circom_mpc_vm2::drivers::taint::TaintDriver`] (`VmType = Taint<F> { val, shared }`)
/// with the condition's input signal `a` marked `shared: true`, so `is_shared` genuinely
/// returns `true` at runtime and the predicated-merge path actually executes.
///
/// Drives [`circom_mpc_vm2::exec::Machine`] directly (rather than going through
/// `WitnessExtension::run_with_flat`/`FinalizedWitnessExtension`) because
/// `TaintDriver::open`/`to_share` both intentionally return only the bare value — the
/// whole point of a "finalized" witness is that it's been opened/shared, so it can't carry
/// a `shared` tag any more. Inspecting the raw post-`run_main` signal is the only way to
/// observe the taint that the SHARED path is actually responsible for propagating.
#[test]
fn branch_if_else_shared_condition_takes_predicated_merge_path() {
    use circom_mpc_vm2::drivers::taint::{Taint, TaintDriver};
    use circom_mpc_vm2::exec::Machine;

    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/branch_if_else.circom", config).unwrap(),
    );

    let a_offset = program
        .main_input_list
        .iter()
        .find(|info| info.name == "a")
        .expect("branch_if_else.circom declares input `a`")
        .offset;
    let (out_offset, out_size) = program.output_mapping["out"];
    assert_eq!(out_size, 1);

    for (a, expected) in [(3u64, 103u64), (7u64, 207u64)] {
        let mut driver = TaintDriver::<Fr>::default();
        let mut machine = Machine::new(&program, &mut driver, VMConfig::default()).unwrap();
        machine.signals[a_offset] = Taint {
            val: Fr::from(a),
            shared: true,
        };
        machine.run_main().unwrap();

        let out = machine.signals[out_offset];
        assert_eq!(out.val, Fr::from(expected), "a={a}");
        assert!(
            out.shared,
            "a={a}: `out` must come out shared — a shared condition must take the \
             predicated-merge (cmux) path through both `SharedIf` arms, not a plain \
             jump that would only taint whichever arm's store the runtime value happens \
             to run"
        );
    }
}

/// The Task 6 "without else" milestone test (`tests/circuits/branch_no_else.circom`):
/// correctness in both directions plus the brief-mandated instruction-shape assertion —
/// `SharedIf` and `SharedEnd` are both present, but **no** `SharedElse` appears anywhere
/// in the compiled program at all, confirming the else-less elision (see
/// `codegen::stmt::lower_branch`'s doc comment: this saves a Rep3 communication round
/// when the condition turns out to be shared at runtime).
#[test]
fn branch_no_else_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/branch_no_else.circom", config).unwrap(),
    );

    assert_eq!(
        instr_count(&program, |i| matches!(i, Instr::SharedIf { .. })),
        1
    );
    assert_eq!(instr_count(&program, |i| matches!(i, Instr::SharedEnd)), 1);
    assert_eq!(
        instr_count(&program, |i| matches!(i, Instr::SharedElse { .. })),
        0,
        "an else-less if must never emit a SharedElse instruction"
    );

    for (a, expected) in [(3u64, 100u64), (7u64, 0u64)] {
        let inputs = BTreeMap::from([("a".to_string(), Fr::from(a))]);
        let finalized = PlainWitnessExtension::new_plain(program.clone(), VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        assert_eq!(
            finalized.get_output("out"),
            Some(vec![Fr::from(expected)]),
            "a={a}"
        );
    }
}

/// The Task 6 nested-composition milestone test (`tests/circuits/loop_with_branch.circom`):
/// a conforming loop containing a `Branch` that only reads (never writes) the induction
/// variable, run at both `unroll.threshold: 0` (rolled — the `Branch` lowers inside
/// `lower_conforming_loop`'s per-iteration body) and `usize::MAX` (fully unrolled — the
/// `Branch` lowers once per re-lowered iteration inside `try_unroll_loop`); both must
/// agree on the same correct witness, confirming loops and branches compose through
/// ordinary recursion with no special-casing needed on either side.
///
/// Also the Task 5 BinN-fusion negative test: at `usize::MAX`, the loop's body — each
/// iteration a `SharedIf`/`Bin`/`Mov`/`SharedElse`/`Bin`/`Mov`/`SharedEnd` run —
/// contains `SharedIf`/`SharedElse` throughout, so fusion must skip the whole unrolled
/// range outright (see `codegen::stmt`'s BinN-fusion module docs, option (1)):
/// `binn_instrs` must be empty at *both* thresholds. That the witness above still comes
/// out correct at `usize::MAX` is exactly "targets intact, correct results" — a
/// corrupted `SharedIf`/`SharedElse` target from an incorrectly-attempted fusion would
/// show up as a wrong `out[i]` (or a panic) here, not just as extra instructions.
#[test]
fn loop_with_branch_composes_rolled_and_unrolled() {
    for threshold in [0, usize::MAX] {
        let config = CompilerConfig {
            simplification: SimplificationLevel::O2(usize::MAX),
            unroll: UnrollConfig { threshold },
            ..Default::default()
        };
        let program = Arc::new(
            CoCircomCompiler::<Bn254>::parse("tests/circuits/loop_with_branch.circom", config)
                .unwrap(),
        );

        assert!(
            binn_instrs(&program).is_empty(),
            "threshold={threshold}: a branch-containing unrolled loop must never fuse into \
             BinN (fusion must skip the whole range — see the BinN-fusion module docs)"
        );

        let mut inputs = BTreeMap::new();
        for k in 0..5u64 {
            inputs.insert(format!("a[{k}]"), Fr::from(10 + k));
        }
        let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        let expected: Vec<Fr> = (0..5u64)
            .map(|i| Fr::from(10 + i + if i < 3 { 1 } else { 2 }))
            .collect();
        assert_eq!(
            finalized.get_output("out"),
            Some(expected),
            "threshold={threshold}"
        );
    }
}

/// The real-KAT milestone test for Task 6 (branch lowering): `ControlFlow(4)`
/// (`test_vectors/WitnessExtension/tests/control_flow.circom`) is the brief's own named
/// candidate — nested loops (`for`/`while`) each containing `if`/`else`/`else if` chains,
/// plus one else-less `if` buried inside a triple-nested loop (`if (i == 2) { ... }` with
/// no `else`), and no subcomponents or functions anywhere in its template graph, so it's
/// the first real KAT-backed circuit to exercise `codegen::stmt::lower_branch` end to end
/// rather than a purpose-built fixture.
#[test]
fn control_flow_kat() {
    common::assert_kats("control_flow", CompilerConfig::default());
}

/// A real KAT circuit exercising the "with else" branch layout via a different source
/// mechanism than an explicit `if`/`else` statement: `IsZero`'s `inv <-- in!=0 ? 1/in :
/// 0;` is a ternary (`InlineSwitchOp`), which circom's own front end desugars into a real
/// `IfThenElse` statement with both arms assigning the same variable (see the `circom`
/// compiler's `hir::sugar_cleaner::rhe_switch_case`) — i.e. a genuine `BranchBucket` with
/// a non-empty `else_branch`, not a special ternary opcode. Confirmed newly compiling end
/// to end by this task (previously bailed on the `Branch` this ternary desugars to); no
/// subcomponents or functions.
#[test]
fn iszero_kat() {
    common::assert_kats("iszero", CompilerConfig::default());
}

/// Additional componentless, function-free KAT circuits confirmed (empirically, by
/// compiling every candidate in `test_vectors/WitnessExtension/kats/`) to now compile end
/// to end with branches plus everything prior. None of these actually use an `if`/`else`/
/// ternary themselves (they're plain straight-line/loop field and curve arithmetic), but
/// per the brief's "add every other KAT circuit that now compiles ... without
/// functions/subcomponents", they round out real-circuit coverage for this task's
/// combined feature set.
#[test]
fn babyadd_tester_kat() {
    common::assert_kats("babyadd_tester", CompilerConfig::default());
}

#[test]
fn babycheck_test_kat() {
    common::assert_kats("babycheck_test", CompilerConfig::default());
}

#[test]
fn edwards2montgomery_kat() {
    common::assert_kats("edwards2montgomery", CompilerConfig::default());
}

#[test]
fn montgomery2edwards_kat() {
    common::assert_kats("montgomery2edwards", CompilerConfig::default());
}

#[test]
fn montgomeryadd_kat() {
    common::assert_kats("montgomeryadd", CompilerConfig::default());
}

#[test]
fn montgomerydouble_kat() {
    common::assert_kats("montgomerydouble", CompilerConfig::default());
}

#[test]
fn mimc_test_kat() {
    common::assert_kats("mimc_test", CompilerConfig::default());
}

#[test]
fn mimc_sponge_test_kat() {
    common::assert_kats("mimc_sponge_test", CompilerConfig::default());
}

/// The named KAT candidate for this task (function lowering): `sub(x, y)` (`assert(x >
/// y); return x - y;`) called directly as a `<==` store's RHS — the single-value-return
/// (`with_size == 1`) `Ret`/`CallFn` path end to end, with a real argument (the template
/// parameter `N`, monomorphized to a literal) and a real assertion inside the function
/// body.
#[test]
fn functions_kat() {
    common::assert_kats("functions", CompilerConfig::default());
}

/// A real KAT circuit exercising a *pure* function whose body itself has the full
/// statement machinery this crate lowers — nested `while` loops, `if`s with no `else`,
/// early `return`s — called from a template with no subcomponents anywhere in its graph
/// (confirmed by empirically probing every KAT circuit's compile result; `sqrt` lives in
/// `test_vectors/WitnessExtension/tests/libs/pointbits.circom` and is called once per
/// witness from `Main`). This is the milestone test for "a function containing a loop
/// (and a branch) works" via a real circuit, not just a purpose-built one (see
/// `func_loop_and_branch_end_to_end` below for the purpose-built companion with a
/// mechanism-level shape assertion).
#[test]
fn sqrt_test_kat() {
    common::assert_kats("sqrt_test", CompilerConfig::default());
}

/// Two more real KAT circuits confirmed (empirically, by compiling every candidate in
/// `test_vectors/WitnessExtension/kats/`) to now compile *and* produce a matching
/// witness end to end with function lowering plus everything prior: both call
/// `EscalarMulW4Table(base, 0)` (`test_vectors/WitnessExtension/tests/libs/
/// escalarmulw4table.circom`), a function returning a `256`-element nested array
/// (`Dimension` of `[16][2]` folded into one flat `with_size`), entirely computed in
/// `var`s inside `Main` with no subcomponents anywhere in either circuit's template
/// graph.
#[test]
fn escalarmulw4table_test_kat() {
    common::assert_kats("escalarmulw4table_test", CompilerConfig::default());
}

#[test]
fn escalarmulw4table_test3_kat() {
    common::assert_kats("escalarmulw4table_test3", CompilerConfig::default());
}

/// The purpose-built multi-value-return milestone (`with_size > 1`): none of the KAT
/// candidates' functions return more than one value in a shape that isolates the
/// `RetSrc::Var`/`eval_index` path this cleanly (`escalarmulw4table`'s `256`-element
/// return, exercised above, already proves the mechanism works, but at a size that
/// obscures a hand-checkable expected value). `tests/circuits/func_multi_return.circom`'s
/// `minmax(a, b)` returns a compile-time-sized 2-element array (`var r[2]; r[0] = ...;
/// r[1] = ...; return r;`) — a `ReturnBucket` with `with_size == 2` whose value is a
/// `Load` of that array's var-slot range, lowered via `Instr::Ret { src: RetSrc::Var(..),
/// n: 2 }` (`lower_return`'s multi-value path) and copied out on the caller side via
/// `Instr::StoreN` (the normal multi-element `CallBucket` result-store path,
/// `lower_call`).
#[test]
fn func_multi_return_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/func_multi_return.circom", config)
            .unwrap(),
    );

    for (a, b) in [(3u64, 7u64), (9u64, 2u64), (5u64, 5u64)] {
        let inputs = BTreeMap::from([
            ("a".to_string(), Fr::from(a)),
            ("b".to_string(), Fr::from(b)),
        ]);
        let finalized = PlainWitnessExtension::new_plain(program.clone(), VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        assert_eq!(
            finalized.get_output("out"),
            Some(vec![Fr::from(a.min(b)), Fr::from(a.max(b))]),
            "a={a}, b={b}"
        );
    }
}

/// The purpose-built "function called inside an expression" milestone
/// (`tests/circuits/func_call_in_expr.circom`): `square(a) + square(b)` combines two
/// separate `CallBucket`s' results with an ordinary `Add` — each call is still its own
/// top-level statement (see `lower_call`'s doc comment on why `ReturnType::Intermediate`,
/// a call truly nested inside another expression's tree, stays unsupported), but this
/// confirms a call's *result*, once stored to a `var`, composes with ordinary expression
/// lowering exactly like any other value — nothing about `Instr::CallFn`/`Ret` needs the
/// consuming expression to know a function was involved at all. `square_of_sum` also
/// exercises a call whose own argument is itself a non-trivial expression (`square(a +
/// b)`, not just a bare variable).
#[test]
fn func_call_in_expr_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/func_call_in_expr.circom", config)
            .unwrap(),
    );

    for (a, b) in [(3u64, 4u64), (5u64, 6u64)] {
        let inputs = BTreeMap::from([
            ("a".to_string(), Fr::from(a)),
            ("b".to_string(), Fr::from(b)),
        ]);
        let finalized = PlainWitnessExtension::new_plain(program.clone(), VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        assert_eq!(
            finalized.get_output("sum_of_squares"),
            Some(vec![Fr::from(a * a + b * b)]),
            "a={a}, b={b}"
        );
        assert_eq!(
            finalized.get_output("square_of_sum"),
            Some(vec![Fr::from((a + b) * (a + b))]),
            "a={a}, b={b}"
        );
    }
}

/// The recursion milestone (`tests/circuits/func_recursion.circom`): circom functions
/// can be recursive (confirmed both by the front end's own docs,
/// `mkdocs/docs/circom-language/functions.md`: "Functions can be recursive", and
/// empirically — this circuit compiles and runs correctly), so `factorial(n)` is a
/// direct, literal recursive function (`if (n == 0) return 1; return n * factorial(n -
/// 1);`), calling through `Instr::CallFn` into a fresh `run_function` activation for
/// every level of recursion (`circom_mpc_vm2::exec::Machine::run_function` recurses via
/// ordinary Rust call stack depth — see its own doc comment/the `vm2` `recursion` test).
#[test]
fn func_recursion_end_to_end() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/func_recursion.circom", config).unwrap(),
    );

    for n in [0u64, 1, 5, 7] {
        let inputs = BTreeMap::from([("n".to_string(), Fr::from(n))]);
        let finalized = PlainWitnessExtension::new_plain(program.clone(), VMConfig::default())
            .run(inputs, 0)
            .unwrap();
        let expected: u64 = (1..=n).product::<u64>().max(1);
        assert_eq!(
            finalized.get_output("out"),
            Some(vec![Fr::from(expected)]),
            "n={n}"
        );
    }
}

/// The "function body contains a loop and a branch" milestone
/// (`tests/circuits/func_loop_and_branch.circom`): function bodies lower with the exact
/// same statement machinery as template bodies (`CodeGen::lower_function` calls
/// `stmt::lower_stmt` on each body statement, identically to
/// `CodeGen::lower_template`), so a function whose body is a conforming `for` loop over
/// a *literal* bound (`i < 5`, so it promotes/unrolls exactly like a template's loop
/// would — unlike `func_recursion.circom`/`func_multi_return.circom`, whose functions
/// have no loop at all, and unlike a loop bounded by the function's own runtime
/// argument, which would be non-conforming by construction, see
/// `detect_conforming`'s docs) containing an `if`/`else` (adding a scaled bonus on even
/// iterations) must lower and run correctly — exercising loop unrolling/rolling,
/// induction-variable promotion, and `SharedIf`/`SharedElse`/`SharedEnd` all *inside* a
/// function frame rather than a template's. `scale` is a genuine runtime (signal-derived)
/// argument, so only the loop's own bound is compile-time-known. Run at both
/// `unroll.threshold: 0` (rolled) and `usize::MAX` (fully unrolled) to also confirm the
/// mechanism-level claim (`Instr::ISet`/`Instr::SharedIf` appear in the function's own
/// compiled instructions at `threshold: 0`), not just witness correctness.
#[test]
fn func_loop_and_branch_end_to_end() {
    for threshold in [0, usize::MAX] {
        let config = CompilerConfig {
            simplification: SimplificationLevel::O2(usize::MAX),
            unroll: UnrollConfig { threshold },
            ..Default::default()
        };
        let program = Arc::new(
            CoCircomCompiler::<Bn254>::parse("tests/circuits/func_loop_and_branch.circom", config)
                .unwrap(),
        );

        if threshold == 0 {
            let f = &program.functions[0];
            assert!(
                f.instrs.iter().any(|i| matches!(i, Instr::ISet { .. })),
                "the function's own conforming loop must mirror its induction variable, \
                 just like a template's would"
            );
            assert!(
                f.instrs.iter().any(|i| matches!(i, Instr::SharedIf { .. })),
                "the function's own if/else must lower to SharedIf, just like a \
                 template's would"
            );
        }

        for scale in [0u64, 1, 3, 7] {
            let inputs = BTreeMap::from([("scale".to_string(), Fr::from(scale))]);
            let finalized = PlainWitnessExtension::new_plain(program.clone(), VMConfig::default())
                .run(inputs, 0)
                .unwrap();
            // sum_{i=0}^{4} (i + bonus) * scale, bonus = 10 on even i, 0 on odd i:
            // (10 + 1 + 12 + 3 + 14) * scale = 40 * scale.
            let expected: u64 = 40 * scale;
            assert_eq!(
                finalized.get_output("out"),
                Some(vec![Fr::from(expected)]),
                "scale={scale}, threshold={threshold}"
            );
        }
    }
}

/// The Task 8 milestone test: `bitonic_sort` is the brief's own named component-array
/// candidate — a network of `Compare`/swap subcomponents wired up across a `for`-loop-
/// indexed array (`component comp[...]`), no functions anywhere in its template graph, so
/// this is the first real KAT-backed circuit to exercise [`Instr::CreateCmp`]/[`Instr::
/// InputSub`]/[`Instr::OutputSub`] end to end rather than a purpose-built fixture.
#[test]
fn bitonic_sort_kat() {
    common::assert_kats("bitonic_sort", CompilerConfig::default());
}

/// `babypbk_test` instantiates `BabyPbk()` (baby-jubjub public-key derivation from a
/// private key), which wires up two non-array subcomponents of its own (`Num2Bits`,
/// `EscalarMulFix`) — real `count: 1` `CreateCmp`/`InputSub`/`OutputSub` coverage, just not
/// of `BabyAdd` itself despite this test's former name; real `BabyAdd` coverage is
/// [`babyadd_tester_kat`] above.
#[test]
fn babypbk_test_kat() {
    common::assert_kats("babypbk_test", CompilerConfig::default());
}

/// `AliasCheck` instantiates a *tree* of subcomponents (a `Num2Bits`-shaped bit
/// decomposition feeding a `CompConstant`), i.e. subcomponents whose own template body in
/// turn creates further subcomponents — the "multi-level component tree" case the brief
/// calls out explicitly.
#[test]
fn aliascheck_test_kat() {
    common::assert_kats("aliascheck_test", CompilerConfig::default());
}

/// `BinSub(4, 4)` (bit subtraction with borrow) — another real-circuit component tree
/// (via `Num2Bits`-style decomposition), deferred from Task 4 (it needs subcomponents) per
/// this crate's own progression notes; now unlocked by this task.
#[test]
fn binsub_test_kat() {
    common::assert_kats("binsub_test", CompilerConfig::default());
}

/// `IsEqual` wraps a single `IsZero` subcomponent behind a `<==`-computed difference —
/// confirms a subcomponent's *output* signal (`isz.out`) feeding straight into an ordinary
/// expression composes correctly with everything from prior tasks (branches, `EqN`, ...).
#[test]
fn isequal_kat() {
    common::assert_kats("isequal", CompilerConfig::default());
}

/// The comparator family (`LessThan`/`GreaterThan`/`LessEqThan`/`GreaterEqThan`), each
/// wrapping a `Num2Bits` subcomponent: four more real KATs confirmed to compile and match
/// their KAT witnesses end to end.
#[test]
fn lessthan_kat() {
    common::assert_kats("lessthan", CompilerConfig::default());
}

#[test]
fn greaterthan_kat() {
    common::assert_kats("greaterthan", CompilerConfig::default());
}

#[test]
fn lesseqthan_kat() {
    common::assert_kats("lesseqthan", CompilerConfig::default());
}

#[test]
fn greatereqthan_kat() {
    common::assert_kats("greatereqthan", CompilerConfig::default());
}

/// The `Mux1`/`Mux2`/`Mux3` family: `mux3_1` wires `Num2Bits` and `Constants` into `Mux3`,
/// which in turn instantiates a single (non-array, `count: 1`) `MultiMux3(1)` subcomponent
/// — `MultiMux3` itself has no subcomponents of its own at all, just plain signal-array
/// arithmetic (`c[n][8]`/`s[3]`/`out[n]`); real component-*array* coverage is
/// `bitonic_sort_kat` above, not this family.
#[test]
fn mux1_1_kat() {
    common::assert_kats("mux1_1", CompilerConfig::default());
}

#[test]
fn mux2_1_kat() {
    common::assert_kats("mux2_1", CompilerConfig::default());
}

#[test]
fn mux3_1_kat() {
    common::assert_kats("mux3_1", CompilerConfig::default());
}

/// `MiMCHash(...)` chains a `component mimc[...]` array of `MiMCFeistel` permutation
/// rounds, and `MiMCSponge` likewise — two more real component-array KATs beyond
/// `bitonic_sort`/`mux3_1`.
#[test]
fn mimc_hasher_kat() {
    common::assert_kats("mimc_hasher", CompilerConfig::default());
}

#[test]
fn mimc_sponge_hash_test_kat() {
    common::assert_kats("mimc_sponge_hash_test", CompilerConfig::default());
}

/// The brief's own named *mapped-IO* candidates: `EscalarMulAny`/`EscalarMulFix` build a
/// `component[n]` array whose element template varies across positions (a genuinely mixed
/// component-array cluster), so named-signal access into it — `dbl[i].out`, `adr[i].in`,
/// ... — compiles through `LocationRule::Mapped` (`Instr::InputSub`/`OutputSub`'s
/// `mapped: Some(_)`) rather than the plain `Indexed` addressing every other KAT above
/// exercises. `escalarmul_test`/`escalarmul_test_min` (already function-lowering KATs)
/// keep passing unchanged now that their own component graphs lower too.
#[test]
fn escalarmul_test_kat() {
    common::assert_kats("escalarmul_test", CompilerConfig::default());
}

#[test]
fn escalarmul_test_min_kat() {
    common::assert_kats("escalarmul_test_min", CompilerConfig::default());
}

#[test]
fn escalarmulany_test_kat() {
    common::assert_kats("escalarmulany_test", CompilerConfig::default());
}

#[test]
fn escalarmulfix_test_kat() {
    common::assert_kats("escalarmulfix_test", CompilerConfig::default());
}

/// The brief's own "heavy, time-box it" candidates: `eddsa_test`/`eddsa_verify` build the
/// deepest component tree in the whole KAT suite (`EdDSAVerifier` -> `EdDSAMiMCVerifier`/
/// `EdDSAPoseidonVerifier`-style signature checks -> `EscalarMulAny`/`BabyDbl`/`MiMCSponge`/
/// `Poseidon` subcomponents, several levels deep, with mapped IO throughout the
/// `EscalarMulAny` layer) — confirmed to compile and match their KAT witnesses with no
/// special-casing beyond what every KAT above already exercises.
#[test]
fn eddsa_test_kat() {
    common::assert_kats("eddsa_test", CompilerConfig::default());
}

#[test]
fn eddsa_verify_kat() {
    common::assert_kats("eddsa_verify", CompilerConfig::default());
}

/// Two more real component-tree KATs confirmed alongside the `eddsa_*` pair above: the
/// MiMC- and Poseidon-hash variants of EdDSA signature verification.
#[test]
fn eddsamimc_test_kat() {
    common::assert_kats("eddsamimc_test", CompilerConfig::default());
}

#[test]
fn eddsaposeidon_test_kat() {
    common::assert_kats("eddsaposeidon_test", CompilerConfig::default());
}

/// The Pedersen-hash family: `Pedersen(...)` builds a `component[n]` array of
/// `EscalarMulFix`-style window lookups (mapped IO again) chained through `BabyAdd`
/// accumulation — real multi-level component-tree coverage independent of the `eddsa_*`
/// tree above.
#[test]
fn pedersen_test_kat() {
    common::assert_kats("pedersen_test", CompilerConfig::default());
}

#[test]
fn pedersen2_test_kat() {
    common::assert_kats("pedersen2_test", CompilerConfig::default());
}

#[test]
fn pedersen_hasher_kat() {
    common::assert_kats("pedersen_hasher", CompilerConfig::default());
}

/// The Poseidon-hash family: `Poseidon(...)` builds a `component[nRoundsF+nRoundsP]` array
/// of S-box/mix-layer subcomponents — another independent real component-array KAT.
#[test]
fn poseidon3_test_kat() {
    common::assert_kats("poseidon3_test", CompilerConfig::default());
}

/// Confirms the crate compiles every remaining component-heavy candidate from the brief's
/// own list that this task's probing found to compile and match its KAT witness, beyond
/// the individually-documented tests above: more of the Poseidon family, the full SHA-256
/// family, and the sparse-Merkle-tree (`smt*`) family — real multi-level component trees
/// (an `smt` processor/verifier instantiates a chain of `SMTHash`/`SMTVerifier`-style
/// subcomponents down the tree's depth) and, for SHA-256, large `Sha256compression`
/// component arrays.
#[test]
fn poseidon_family_kats() {
    for name in [
        "poseidon6_test",
        "poseidon_hasher1",
        "poseidon_hasher2",
        "poseidon_hasher16",
        "poseidonex_test",
    ] {
        common::assert_kats(name, CompilerConfig::default());
    }
}

#[test]
fn sha256_family_kats() {
    for name in ["sha256_2_test", "sha256_test448", "sha256_test512"] {
        common::assert_kats(name, CompilerConfig::default());
    }
}

#[test]
fn smt_family_kats() {
    for name in ["smtprocessor10_test", "smtverifier10_test"] {
        common::assert_kats(name, CompilerConfig::default());
    }
}

/// Rounds out real-circuit coverage with the remaining component-bearing KATs confirmed to
/// compile and match end to end by this task's probing (accelerators, sign/sum helpers,
/// and the `pointbits_loopback`/`multiplier16`/`constants_test` fixtures already used as
/// milestones by earlier tasks, now exercised with real subcomponents in their graphs too).
#[test]
fn misc_component_kats() {
    for name in [
        "num2bits_accelerator",
        "reclaim_addbits_accelerator",
        "reclaim_addbits_accelerator_small",
        "sign_test",
        "sum_test",
        "multiplier16",
        "constants_test",
        "pointbits_loopback",
    ] {
        common::assert_kats(name, CompilerConfig::default());
    }
}

/// The brief-mandated instruction-shape test: a component-*array* circuit accessed with a
/// loop-indexed (not literal-constant) subscript must lower `cmp` as `ISrc::Reg` — i.e. the
/// subcomponent index itself is a runtime value read out of an integer register, not folded
/// away to `ISrc::Const` — confirming the codegen's index-materialization path (`codegen::
/// index`'s `IndexExpr::to_isrc`, internal to the compiler crate, so this test can only
/// observe its effect on the emitted `Instr` shape) actually materializes the loop variable
/// rather than only ever exercising the `count: 1`/literal-index case the other KATs above
/// could in principle satisfy via constant folding alone.
/// `tests/circuits/cmp_array.circom` (purpose-built, since none of the brief's named KATs
/// isolate this mechanism-level claim as cleanly as a small fixture does) instantiates
/// `component c[3]` inside a conforming `for (i = 0; i < 3; i++)` loop and both stores to
/// and reads from `c[i]` — the loop's own promoted mirror register (an `Instr::ISet`-backed
/// `ireg`, see `codegen::stmt`'s loop docs) is exactly what ends up as `InputSub`/
/// `OutputSub`'s `cmp: ISrc::Reg(_)`.
#[test]
fn component_array_uses_isrc_reg_for_loop_indexed_cmp() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        unroll: UnrollConfig { threshold: 0 },
        ..Default::default()
    };
    let program = Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/cmp_array.circom", config).unwrap(),
    );

    let instrs = &program.templates[program.main.0 as usize].instrs;
    assert!(
        instrs.iter().any(|i| matches!(
            i,
            Instr::InputSub {
                cmp: ISrc::Reg(_),
                ..
            }
        )),
        "a loop-indexed component array store must lower InputSub's cmp as ISrc::Reg, got: \
         {instrs:?}"
    );
    assert!(
        instrs.iter().any(|i| matches!(
            i,
            Instr::OutputSub {
                cmp: ISrc::Reg(_),
                ..
            }
        )),
        "a loop-indexed component array load must lower OutputSub's cmp as ISrc::Reg, got: \
         {instrs:?}"
    );

    let mut inputs = BTreeMap::new();
    for k in 0..3u64 {
        inputs.insert(format!("a[{k}]"), Fr::from(10 + k));
        inputs.insert(format!("b[{k}]"), Fr::from(k + 1));
    }
    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();
    assert_eq!(
        finalized.get_output("out"),
        Some((0..3u64).map(|k| Fr::from((10 + k) * (k + 1))).collect())
    );
}

/// The Task 9 milestone test, ported from the old stack-based compiler's own
/// `test_release_build_creates_no_assert_and_logs` (`circom-mpc-compiler/src/lib.rs:
/// 809-865`), adapted to the new register ISA: a debug build of `log_and_asserts.circom`
/// (`log(...)` plus `assert(...)`, both inside `Multiplier2`'s single template) must
/// contain `Instr::Assert`/`Instr::Log`/`Instr::LogFlush` (this circuit's one `log` call
/// takes a string-literal argument followed by an expression, so `Instr::LogStr` and
/// `Instr::Log` both appear); a release build (`CompilerConfig::release()`, `debug:
/// false`) must contain none of the four log/assert instruction kinds at all.
#[test]
fn debug_release_build_parity_for_log_and_asserts() {
    let debug_config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..CompilerConfig::default()
    };
    let release_config = CompilerConfig::release();

    let debug = CoCircomCompiler::<Bn254>::parse(
        "../../test_vectors/WitnessExtension/tests/log_and_asserts.circom".to_owned(),
        debug_config,
    )
    .expect("debug config compiles");
    let release = CoCircomCompiler::<Bn254>::parse(
        "../../test_vectors/WitnessExtension/tests/log_and_asserts.circom".to_owned(),
        release_config,
    )
    .expect("release config compiles");

    assert!(debug.functions.is_empty());
    assert_eq!(debug.templates.len(), 1);
    let debug_instrs = &debug.templates[debug.main.0 as usize].instrs;
    assert!(
        debug_instrs
            .iter()
            .any(|i| matches!(i, Instr::Assert { .. })),
        "debug build must contain Instr::Assert"
    );
    assert!(
        debug_instrs.iter().any(|i| matches!(i, Instr::Log { .. })),
        "debug build must contain Instr::Log"
    );
    assert!(
        debug_instrs
            .iter()
            .any(|i| matches!(i, Instr::LogStr { .. })),
        "debug build must contain Instr::LogStr"
    );
    assert!(
        debug_instrs
            .iter()
            .any(|i| matches!(i, Instr::LogFlush { .. })),
        "debug build must contain Instr::LogFlush"
    );

    assert!(release.functions.is_empty());
    assert_eq!(release.templates.len(), 1);
    let release_instrs = &release.templates[release.main.0 as usize].instrs;
    assert!(
        !release_instrs
            .iter()
            .any(|i| matches!(i, Instr::Assert { .. })),
        "release build must not contain Instr::Assert"
    );
    assert!(
        !release_instrs
            .iter()
            .any(|i| matches!(i, Instr::Log { .. })),
        "release build must not contain Instr::Log"
    );
    assert!(
        !release_instrs
            .iter()
            .any(|i| matches!(i, Instr::LogStr { .. })),
        "release build must not contain Instr::LogStr"
    );
    assert!(
        !release_instrs
            .iter()
            .any(|i| matches!(i, Instr::LogFlush { .. })),
        "release build must not contain Instr::LogFlush"
    );
}

/// Unblocks the last real KAT candidate whose only prior blocker was the `Log` gap:
/// `Winner(10, 7)` (`test_vectors/WitnessExtension/tests/winner.circom`) instantiates a
/// component array (`commit[nInputs]`) inside a conforming loop plus one more
/// subcomponent (`highest`), and ends with a single top-level `log("win guess: ",
/// win_guess);` — everything else it needs (loops, component arrays, `EqN` via `===`) was
/// already covered by earlier tasks.
#[test]
fn winner_kat() {
    common::assert_kats("winner", CompilerConfig::default());
}

/// Unblocks `shared_control_flow` (`test_vectors/WitnessExtension/tests/
/// shared_control_flow.circom`): a deeply nested `if`/`else if`/`else` chain across
/// several *functions* (`someValue`/`anotherFunction`/`evenAnotherFunction`), whose
/// condition (`t`, the template parameter passed as `y`) is a plain public value at
/// runtime under the `PlainDriver` this harness uses — so every `Instr::SharedIf` this
/// compiles to takes the ordinary (non-predicated) jump path, not the cmux/predicated-merge
/// path (see `codegen::stmt::lower_branch`'s doc comment and
/// `branch_if_else_shared_condition_takes_predicated_merge_path` above for where that
/// other path *is* exercised). One dead branch (`y != 4`) contains a `log(...)` plus an
/// `assert(0)` that never actually executes for this KAT's inputs — confirming a
/// never-taken `Log`/`Assert` lowers and simply never fires, not just that a taken one
/// does.
#[test]
fn shared_control_flow_kat() {
    common::assert_kats("shared_control_flow", CompilerConfig::default());
}

/// The array-valued companion to [`shared_control_flow_kat`]:
/// `shared_control_flow_arrays.circom` is the same nested `if`/`else if`/`else` control
/// flow across functions, but every function returns a 2-element array instead of a
/// scalar (`ReturnBucket` with `with_size == 2`, `RetSrc::Var`/`Instr::StoreN` on the
/// caller side — see `codegen::stmt::lower_return`'s doc comment), including one function
/// (`evenAnotherFunction`) returning a `var`-array literal instead of a computed one. Same
/// dead `log(...)`/`assert(0)` branch as above, now returning `[0, 0]` instead of `0`.
#[test]
fn shared_control_flow_arrays_kat() {
    common::assert_kats("shared_control_flow_arrays", CompilerConfig::default());
}

/// Regression test for the per-statement field-register leak fixed in
/// `codegen::stmt::lower_stmt`: it used to rewind only `cg.iregs`, never `cg.regs`, on
/// every top-level statement, so a statement's top-level result register (e.g. a
/// `StoreBucket`'s materialized source) stayed permanently allocated for the rest of the
/// enclosing body instead of being freed once the one instruction consuming it was
/// emitted — `num_field_regs` grew with the body's *length*, not its (small, constant)
/// maximum expression width. `tests/circuits/many_sequential_stores.circom` is 21
/// sequential `var x_{i} = x_{i-1} + 1;` statements (plus the final `out <== x20;`), each
/// a trivially small expression (depth 1): pre-fix this reserved on the order of one
/// field register per statement (>20); post-fix it stays small and constant regardless of
/// how many more such statements are added.
#[test]
fn many_sequential_stores_bounds_field_regs() {
    let config = CompilerConfig {
        simplification: SimplificationLevel::O2(usize::MAX),
        ..CompilerConfig::default()
    };
    let program = std::sync::Arc::new(
        CoCircomCompiler::<Bn254>::parse("tests/circuits/many_sequential_stores.circom", config)
            .unwrap(),
    );
    let num_field_regs = program.templates[program.main.0 as usize].num_field_regs;
    assert!(
        num_field_regs < 16,
        "expected num_field_regs to stay small (bounded by expression width, not body \
         length) for 21 sequential single-op statements, got {num_field_regs}"
    );

    let inputs = BTreeMap::from([("a".to_string(), Fr::from(1u64))]);
    let finalized = PlainWitnessExtension::new_plain(program, VMConfig::default())
        .run(inputs, 0)
        .unwrap();
    // x0 = 1, x1..x20 each add 1 twenty times -> out = 1 + 20 = 21.
    assert_eq!(finalized.get_output("out"), Some(vec![Fr::from(21u64)]));
}

/// Re-asserts the same fix's effect on a real, large compiled circuit end to end:
/// `sha256_2_test` (`test_vectors/WitnessExtension/tests/sha256_2_test.circom`, via
/// `common::compile`, which threads in `link_library` for its `sha256compression`
/// dependency) was the fix's other measured before/after case, alongside `chacha20` (see
/// this commit's message for both numbers). Measured post-fix (this task, `--release`):
/// the largest `num_field_regs` of any template in the compiled program is **1024**
/// (`main`'s own template needs only a handful — the blowup was in `Sha256compression`'s
/// body) — pre-fix the same circuit at `unroll.threshold: usize::MAX` reached **42,752**.
/// `< 1200` leaves headroom above the measured value for incidental future codegen
/// changes without masking a regression back toward the old, unbounded-with-body-length
/// behavior.
#[test]
fn sha256_2_test_bounds_field_regs() {
    let program = std::sync::Arc::new(common::compile("sha256_2_test", CompilerConfig::default()));
    let max_num_field_regs = program
        .templates
        .iter()
        .map(|t| t.num_field_regs)
        .max()
        .expect("sha256_2_test compiles to at least one template");
    assert!(
        max_num_field_regs < 1200,
        "expected every template's num_field_regs to stay well below the pre-fix, \
         body-length-scaled blowup (42,752 at unroll.threshold: usize::MAX) for \
         sha256_2_test, got {max_num_field_regs}"
    );
}
