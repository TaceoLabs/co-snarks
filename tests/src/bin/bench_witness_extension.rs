//! Old-vs-new witness-extension benchmark: the coCircom-compiler-rewrite acceptance
//! measurement.
//!
//! Compares the old pipeline (`circom_mpc_compiler` + `circom_mpc_vm`) against the new
//! pipeline (`circom_mpc_compiler2` + `circom_mpc_vm2`, with BinN fusion, batched Rep3
//! and accelerators) on every KAT circuit under `test_vectors/WitnessExtension`, for:
//!
//! 1. Plain execute-only (median of [`PLAIN_REPS`] runs of `run_with_flat`, KAT input 0).
//! 2. Compile time (median of [`COMPILE_REPS`] parses).
//! 3. Rep3/local 3-party wall time (median of [`REP3_REPS`] runs), for the subset of
//!    circuits the new pipeline's Rep3 KATs actually cover (`REP3_CIRCUITS`).
//! 4. For the Poseidon-family circuits, an extra pair of rows with the `Poseidon2`
//!    accelerator forced off via `CIRCOM_MPC_ACCELERATOR_POSEIDON2=0`.
//!
//! # What's inside the timed region (symmetric across pipelines)
//!
//! For plain and Rep3, the *parse* step happens once per circuit/pipeline outside the
//! timing loop (its own median is measured separately, see `bench_compile_old`/
//! `bench_compile_new`). What's
//! timed per repetition is exactly: constructing a fresh VM/driver from the
//! already-parsed program (`to_plain_vm`/`new_plain`, or the Rep3 driver handshake), plus
//! `run_with_flat`. Old's `to_plain_vm`/`Rep3WitnessExtension::new` take the parsed
//! program by value, so a fresh to-be-consumed copy is prepared (`Clone`d from the single
//! parse, for plain; a fresh per-party parse, for Rep3 — mirroring the old rep3 test
//! harness exactly) *before* the timer starts; new's API takes `Arc<CompiledProgram>`, so
//! the analogous step is an `Arc::clone` (~free). This keeps the comparison fair: both
//! pipelines pay for "build a fresh VM for this run", neither pays for "make another
//! owned copy of the parse result", which is a harness artifact of repeating a
//! conceptually one-shot pipeline for a median, not real per-run work.
//!
//! For Rep3, the parse happens *inside* each of the 3 per-party threads (matching the old
//! rep3 test harness structure exactly — every party independently compiles), so Rep3
//! wall time does include one parse per party, for both pipelines, symmetrically.
//!
//! # Accelerator env vars
//!
//! `MpcAcceleratorConfig::from_env` is re-read on every VM/driver construction, so the
//! `CIRCOM_MPC_ACCELERATOR_POSEIDON2` env var is set immediately before the "no-accel"
//! measurement block for a Poseidon circuit (covering all reps in that block) and removed
//! immediately after — never left set across circuits, and never mutated concurrently
//! with other measurements (the whole binary is single-threaded except for the Rep3
//! per-circuit thread group, which is always joined before the next circuit starts).
//!
//! # Usage
//!
//! With no arguments, benchmarks every circuit in [`PLAIN_CIRCUITS`] and writes the full
//! report (table + summary) to `../.superpowers/sdd/bench-results.md`. With one or more
//! circuit-name arguments, benchmarks only those circuits, preserving whatever the output
//! file already contains and appending new rows after it (the summary block is only
//! (re)written on a full, no-argument run) — use this to chunk a long run into batches.
//! Progress is flushed to the output file after every circuit, so a killed run still
//! leaves a readable partial table, and progress lines go to stderr.
//!
//! Correctness of both pipelines against the KAT witnesses is established by the
//! existing test suites (`plain_vm.rs`, `plain_vm2.rs`, `rep3.rs`, `rep3_vm2.rs`); this
//! binary measures performance only and does not re-verify it, other than a best-effort
//! sanity check against the KAT witness on the very first repetition of each
//! circuit/pipeline/mode (in case a harness bug silently produced a nonsensical-but-fast
//! run).
use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler2::CoCircomCompiler as CoCircomCompiler2;
use circom_mpc_vm::mpc_vm::VMConfig as VMConfigOld;
use circom_mpc_vm::{
    mpc_vm::Rep3WitnessExtension as Rep3WitnessExtensionOld, Rep3VmType as Rep3VmTypeOld,
};
use circom_mpc_vm2::api::{
    PlainWitnessExtension as PlainWitnessExtension2, Rep3WitnessExtension as Rep3WitnessExtension2,
};
use circom_mpc_vm2::drivers::rep3::Rep3VmType as Rep3VmType2;
use circom_mpc_vm2::program::VMConfig as VMConfig2;
use circom_types::Witness;
use itertools::izip;
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const KATS_DIR: &str = "../test_vectors/WitnessExtension/kats";
const CIRCUITS_DIR: &str = "../test_vectors/WitnessExtension/tests";
const LINK_LIBS_DIR: &str = "../test_vectors/WitnessExtension/tests/libs/";
const OUTPUT_PATH: &str = "../.superpowers/sdd/bench-results.md";

const PLAIN_REPS: usize = 5;
const REP3_REPS: usize = 3;
const COMPILE_REPS: usize = 3;
/// A single run over this threshold aborts further reps for that measurement; the
/// (partial) median is still reported, flagged with a note.
const SLOW_THRESHOLD: Duration = Duration::from_secs(60);

/// The full 66-circuit plain KAT list (`plain_vm2.rs`'s macro invocations, in source
/// order).
const PLAIN_CIRCUITS: &[&str] = &[
    "aliascheck_test",
    "array_equals",
    "babyadd_tester",
    "babycheck_test",
    "babypbk_test",
    "binsub_test",
    "binsum_test",
    "constants_test",
    "control_flow",
    "eddsa_test",
    "eddsa_verify",
    "eddsamimc_test",
    "eddsaposeidon_test",
    "edwards2montgomery",
    "escalarmul_test",
    "escalarmul_test_min",
    "escalarmulany_test",
    "escalarmulfix_test",
    "escalarmulw4table",
    "escalarmulw4table_test",
    "escalarmulw4table_test3",
    "functions",
    "greatereqthan",
    "greaterthan",
    "isequal",
    "iszero",
    "lesseqthan",
    "lessthan",
    "mimc_hasher",
    "mimc_sponge_hash_test",
    "mimc_sponge_test",
    "mimc_test",
    "montgomery2edwards",
    "montgomeryadd",
    "montgomerydouble",
    "multiplier16",
    "multiplier2",
    "mux1_1",
    "mux2_1",
    "mux3_1",
    "mux4_1",
    "pedersen2_test",
    "pedersen_hasher",
    "pedersen_test",
    "pointbits_loopback",
    "poseidon3_test",
    "poseidon6_test",
    "poseidon_hasher1",
    "poseidon_hasher16",
    "poseidon_hasher2",
    "poseidonex_test",
    "sha256_2_test",
    "sha256_test448",
    "sha256_test512",
    "shared_control_flow",
    "shared_control_flow_arrays",
    "sign_test",
    "sqrt_test",
    "smtprocessor10_test",
    "smtverifier10_test",
    "sum_test",
    "winner",
    "bitonic_sort",
    "num2bits_accelerator",
    "reclaim_addbits_accelerator",
    "reclaim_addbits_accelerator_small",
];

/// The subset of [`PLAIN_CIRCUITS`] that the new pipeline's Rep3 KATs (`rep3_vm2.rs`)
/// actually run non-`#[ignore]`d (53 of 63 total invocations there; the remaining 13
/// `PLAIN_CIRCUITS` entries have no Rep3 row).
const REP3_CIRCUITS: &[&str] = &[
    "shared_control_flow",
    "shared_control_flow_arrays",
    "functions",
    "sqrt_test",
    "aliascheck_test",
    "array_equals",
    "babyadd_tester",
    "babycheck_test",
    "babypbk_test",
    "binsub_test",
    "binsum_test",
    "constants_test",
    "control_flow",
    "edwards2montgomery",
    "escalarmul_test",
    "escalarmul_test_min",
    "escalarmulany_test",
    "escalarmulw4table_test",
    "escalarmulw4table_test3",
    "greatereqthan",
    "greaterthan",
    "isequal",
    "iszero",
    "lesseqthan",
    "lessthan",
    "mimc_hasher",
    "mimc_sponge_hash_test",
    "mimc_sponge_test",
    "mimc_test",
    "montgomery2edwards",
    "montgomeryadd",
    "montgomerydouble",
    "multiplier16",
    "mux1_1",
    "mux2_1",
    "mux3_1",
    "mux4_1",
    "pedersen_hasher",
    "pointbits_loopback",
    "poseidon3_test",
    "poseidon6_test",
    "poseidon_hasher1",
    "poseidon_hasher16",
    "poseidon_hasher2",
    "poseidonex_test",
    "sign_test",
    "smtprocessor10_test",
    "smtverifier10_test",
    "sum_test",
    "winner",
    "bitonic_sort",
    "num2bits_accelerator",
    "reclaim_addbits_accelerator",
];

/// Poseidon-family circuits (by substring match, same as used ad hoc while triaging this
/// benchmark): these additionally get a "no-accel" row with
/// `CIRCOM_MPC_ACCELERATOR_POSEIDON2=0`.
fn is_poseidon(name: &str) -> bool {
    name.to_ascii_lowercase().contains("poseidon")
}

fn old_config() -> circom_mpc_compiler::CompilerConfig {
    circom_mpc_compiler::CompilerConfig {
        simplification: circom_mpc_compiler::SimplificationLevel::O2(usize::MAX),
        link_library: vec![LINK_LIBS_DIR.into()],
        ..Default::default()
    }
}

fn new_config() -> circom_mpc_compiler2::CompilerConfig {
    circom_mpc_compiler2::CompilerConfig {
        simplification: circom_mpc_compiler2::SimplificationLevel::O2(usize::MAX),
        link_library: vec![LINK_LIBS_DIR.into()],
        ..Default::default()
    }
}

fn circuit_path(name: &str) -> String {
    format!("{CIRCUITS_DIR}/{name}.circom")
}

fn read_field_element(s: &str) -> Fr {
    if let Some(striped) = s.strip_prefix('-') {
        -Fr::from_str(striped).unwrap()
    } else {
        Fr::from_str(s).unwrap()
    }
}

/// Loads KAT input-set 0 (`input0.json`'s `"in"` array) and the matching expected
/// witness (`witness0.wtns`) for `name`.
/// Returns `None` if `name` has no KAT input-set 0 on disk. This matches the existing
/// KAT test harness's own tolerance for circuits with no KAT directory at all (its
/// `from_test_name` loop just runs zero iterations in that case, e.g. `multiplier2` and
/// `escalarmulw4table`) — we skip those circuits instead, since there is nothing to time.
fn load_kat0(name: &str) -> Option<(Vec<Fr>, Vec<Fr>)> {
    let witness_file = File::open(format!("{KATS_DIR}/{name}/witness0.wtns")).ok()?;
    let witness = Witness::<Fr>::from_reader(witness_file).unwrap();
    let input_file = File::open(format!("{KATS_DIR}/{name}/input0.json")).ok()?;
    let json: serde_json::Value = serde_json::from_reader(input_file).unwrap();
    let input = json
        .get("in")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|s| read_field_element(s.as_str().unwrap()))
        .collect();
    Some((input, witness.values))
}

/// Result of a repeated, timed measurement: the median duration, how many repetitions
/// actually ran, and whether it was cut short for taking too long.
struct Measurement {
    median: Duration,
    reps_run: usize,
    capped: bool,
}

fn median_of(mut durs: Vec<Duration>) -> Duration {
    durs.sort();
    durs[durs.len() / 2]
}

/// Runs `f` up to `reps` times, stopping early (and flagging `capped`) if any single run
/// exceeds [`SLOW_THRESHOLD`].
fn timed_reps(reps: usize, mut f: impl FnMut(usize) -> Duration) -> Measurement {
    let mut durs = Vec::with_capacity(reps);
    let mut capped = false;
    for i in 0..reps {
        let d = f(i);
        durs.push(d);
        if d > SLOW_THRESHOLD {
            capped = true;
            break;
        }
    }
    let reps_run = durs.len();
    Measurement {
        median: median_of(durs),
        reps_run,
        capped,
    }
}

// ---------------------------------------------------------------------------
// Plain
// ---------------------------------------------------------------------------

fn bench_plain_old(name: &str, input: &[Fr], expected: &[Fr]) -> Measurement {
    let path = circuit_path(name);
    let parsed = CoCircomCompiler::<Bn254>::parse(path, old_config())
        .unwrap_or_else(|e| panic!("old parse failed for {name}: {e}"));
    timed_reps(PLAIN_REPS, |i| {
        let p = parsed.clone();
        let inp = input.to_vec();
        let start = Instant::now();
        let vm = p.to_plain_vm(VMConfigOld::default());
        let witness = vm.run_with_flat(inp, 0).unwrap().into_shared_witness();
        let elapsed = start.elapsed();
        if i == 0 {
            let mut full = witness.public_inputs.clone();
            full.extend(witness.witness);
            assert_eq!(full, expected, "old plain KAT mismatch for {name}");
        }
        elapsed
    })
}

fn bench_plain_new(name: &str, input: &[Fr], expected: &[Fr]) -> Measurement {
    let path = circuit_path(name);
    let parsed = CoCircomCompiler2::<Bn254>::parse(path, new_config())
        .unwrap_or_else(|e| panic!("new parse failed for {name}: {e}"));
    let arc = Arc::new(parsed);
    timed_reps(PLAIN_REPS, |i| {
        let p = Arc::clone(&arc);
        let inp = input.to_vec();
        let start = Instant::now();
        let vm = PlainWitnessExtension2::new_plain(p, VMConfig2::default());
        let witness = vm.run_with_flat(inp, 0).unwrap().into_shared_witness();
        let elapsed = start.elapsed();
        if i == 0 {
            let mut full = witness.public_inputs.clone();
            full.extend(witness.witness);
            assert_eq!(full, expected, "new plain KAT mismatch for {name}");
        }
        elapsed
    })
}

// ---------------------------------------------------------------------------
// Compile time
// ---------------------------------------------------------------------------

fn bench_compile_old(name: &str) -> Measurement {
    let path = circuit_path(name);
    timed_reps(COMPILE_REPS, |_| {
        let start = Instant::now();
        let _parsed = CoCircomCompiler::<Bn254>::parse(path.clone(), old_config())
            .unwrap_or_else(|e| panic!("old parse failed for {name}: {e}"));
        start.elapsed()
    })
}

fn bench_compile_new(name: &str) -> Measurement {
    let path = circuit_path(name);
    timed_reps(COMPILE_REPS, |_| {
        let start = Instant::now();
        let _parsed = CoCircomCompiler2::<Bn254>::parse(path.clone(), new_config())
            .unwrap_or_else(|e| panic!("new parse failed for {name}: {e}"));
        start.elapsed()
    })
}

// ---------------------------------------------------------------------------
// Rep3 / local
// ---------------------------------------------------------------------------

fn bench_rep3_old(name: &str, input: &[Fr], expected: &[Fr]) -> Measurement {
    let path = circuit_path(name);
    timed_reps(REP3_REPS, |i| {
        let mut rng = thread_rng();
        let inputs = mpc_core::protocols::rep3::share_field_elements(input, &mut rng);
        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
        let config = old_config();

        let start = Instant::now();
        let mut threads = vec![];
        for (net0, net1, inp) in izip!(nets0, nets1, inputs) {
            let file = path.clone();
            let cfg = config.clone();
            threads.push(std::thread::spawn(move || {
                let circuit = CoCircomCompiler::<Bn254>::parse(file, cfg).unwrap();
                let we =
                    Rep3WitnessExtensionOld::new(&net0, &net1, &circuit, VMConfigOld::default())
                        .unwrap();
                we.run_with_flat(inp.into_iter().map(Rep3VmTypeOld::Arithmetic).collect(), 0)
                    .unwrap()
                    .into_shared_witness()
            }));
        }
        let r3 = threads.pop().unwrap().join().unwrap();
        let r2 = threads.pop().unwrap().join().unwrap();
        let r1 = threads.pop().unwrap().join().unwrap();
        let elapsed = start.elapsed();
        if i == 0 {
            let combined = tests::test_utils::combine_field_elements_for_vm(r1, r2, r3);
            assert_eq!(combined, expected, "old rep3 KAT mismatch for {name}");
        }
        elapsed
    })
}

fn bench_rep3_new(name: &str, input: &[Fr], expected: &[Fr]) -> Measurement {
    let path = circuit_path(name);
    timed_reps(REP3_REPS, |i| {
        let mut rng = thread_rng();
        let inputs = mpc_core::protocols::rep3::share_field_elements(input, &mut rng);
        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
        let config = new_config();

        let start = Instant::now();
        let mut threads = vec![];
        for (net0, net1, inp) in izip!(nets0, nets1, inputs) {
            let file = path.clone();
            let cfg = config.clone();
            threads.push(std::thread::spawn(move || {
                let circuit = CoCircomCompiler2::<Bn254>::parse(file, cfg).unwrap();
                let we = Rep3WitnessExtension2::new_rep3(
                    &net0,
                    &net1,
                    Arc::new(circuit),
                    VMConfig2::default(),
                )
                .unwrap();
                we.run_with_flat(inp.into_iter().map(Rep3VmType2::Arithmetic).collect(), 0)
                    .unwrap()
                    .into_shared_witness()
            }));
        }
        let r3 = threads.pop().unwrap().join().unwrap();
        let r2 = threads.pop().unwrap().join().unwrap();
        let r1 = threads.pop().unwrap().join().unwrap();
        let elapsed = start.elapsed();
        if i == 0 {
            let combined = tests::test_utils::combine_field_elements_for_vm(r1, r2, r3);
            assert_eq!(combined, expected, "new rep3 KAT mismatch for {name}");
        }
        elapsed
    })
}

// ---------------------------------------------------------------------------
// Accelerator env-var control
// ---------------------------------------------------------------------------

const POSEIDON2_ACCEL_VAR: &str = "CIRCOM_MPC_ACCELERATOR_POSEIDON2";

/// Disables the Poseidon2 accelerator for the duration of `f` by setting
/// `CIRCOM_MPC_ACCELERATOR_POSEIDON2=0`, then restores its previous value. Never left
/// changed across circuits; never runs concurrently with anything else touching this var (the
/// binary is single-threaded outside of Rep3 per-circuit thread groups, which are always
/// joined before this returns).
fn with_poseidon2_accel_off<T>(f: impl FnOnce() -> T) -> T {
    struct RestoreEnv(Option<std::ffi::OsString>);

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            // SAFETY: the caller guarantees this benchmark is not concurrently mutating
            // or reading accelerator environment variables; Drop also runs on unwind.
            unsafe {
                match self.0.take() {
                    Some(previous) => std::env::set_var(POSEIDON2_ACCEL_VAR, previous),
                    None => std::env::remove_var(POSEIDON2_ACCEL_VAR),
                }
            }
        }
    }

    // SAFETY: no other thread reads/writes this process's env vars concurrently at this
    // point — the only other env-var access in this binary (`MpcAcceleratorConfig::from_env`)
    // happens inside VM/driver construction calls made by `f` itself (or by prior/later
    // calls on this same thread), and any Rep3 worker threads spawned by `f` are always
    // joined before `f` returns, so the set/remove below strictly bracket all reads of it.
    let restore = RestoreEnv(std::env::var_os(POSEIDON2_ACCEL_VAR));
    unsafe {
        std::env::set_var(POSEIDON2_ACCEL_VAR, "0");
    }
    let result = f();
    drop(restore);
    result
}

// ---------------------------------------------------------------------------
// Formatting / reporting
// ---------------------------------------------------------------------------

fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 {
        format!("{secs:.3}s")
    } else {
        format!("{:.3}ms", secs * 1000.0)
    }
}

/// old/new: >1 means new is faster.
fn ratio(old: Duration, new: Duration) -> f64 {
    old.as_secs_f64() / new.as_secs_f64()
}

struct Row {
    circuit: String,
    old_plain: Measurement,
    new_plain: Measurement,
    rep3: Option<(Measurement, Measurement)>,
    /// `None` for the Poseidon "no-accel" rows: compile time doesn't depend on
    /// accelerator config, so it isn't re-measured there (the main row above already has
    /// it) — printed as `-` rather than a possibly-confusing duplicate number.
    compile: Option<(Measurement, Measurement)>,
}

fn note(m: &Measurement) -> String {
    if m.capped {
        format!(" (capped at {} rep(s), slow)", m.reps_run)
    } else {
        String::new()
    }
}

fn write_row(out: &mut String, row: &Row) {
    let plain_ratio = ratio(row.old_plain.median, row.new_plain.median);
    let (old_rep3_s, new_rep3_s, rep3_ratio_s) = match &row.rep3 {
        Some((o, n)) => (
            format!("{}{}", fmt_dur(o.median), note(o)),
            format!("{}{}", fmt_dur(n.median), note(n)),
            format!("{:.2}", ratio(o.median, n.median)),
        ),
        None => ("n/a".into(), "n/a".into(), "n/a".into()),
    };
    let (old_compile_s, new_compile_s) = match &row.compile {
        Some((o, n)) => (
            format!("{}{}", fmt_dur(o.median), note(o)),
            format!("{}{}", fmt_dur(n.median), note(n)),
        ),
        None => ("-".into(), "-".into()),
    };
    let _ = writeln!(
        out,
        "| {} | {}{} | {}{} | {:.2} | {} | {} | {} | {} | {} |",
        row.circuit,
        fmt_dur(row.old_plain.median),
        note(&row.old_plain),
        fmt_dur(row.new_plain.median),
        note(&row.new_plain),
        plain_ratio,
        old_rep3_s,
        new_rep3_s,
        rep3_ratio_s,
        old_compile_s,
        new_compile_s,
    );
}

/// Returns `None` if `name` has no KAT input-set 0 (see [`load_kat0`]) — nothing to
/// benchmark for that circuit.
fn bench_one(name: &str, do_rep3: bool) -> Option<Row> {
    let (input, witness) = load_kat0(name)?;

    eprintln!("[{name}] plain (old)...");
    let old_plain = bench_plain_old(name, &input, &witness);
    eprintln!("[{name}] plain (new)...");
    let new_plain = bench_plain_new(name, &input, &witness);

    eprintln!("[{name}] compile (old)...");
    let old_compile = bench_compile_old(name);
    eprintln!("[{name}] compile (new)...");
    let new_compile = bench_compile_new(name);

    let rep3 = if do_rep3 {
        eprintln!("[{name}] rep3 (old)...");
        let o = bench_rep3_old(name, &input, &witness);
        eprintln!("[{name}] rep3 (new)...");
        let n = bench_rep3_new(name, &input, &witness);
        Some((o, n))
    } else {
        None
    };

    Some(Row {
        circuit: name.to_string(),
        old_plain,
        new_plain,
        rep3,
        compile: Some((old_compile, new_compile)),
    })
}

const HEADER: &str = "\
# Old-vs-new witness-extension benchmark\n\
\n\
Old pipeline: `circom-mpc-compiler` + `circom-mpc-vm`. New pipeline: \
`circom-mpc-compiler2` + `circom-mpc-vm2` (BinN fusion, batched Rep3, accelerators).\n\
\n\
- **Plain**: median of 5 runs of `run_with_flat` (KAT input set 0); parse happens once \
outside the timing loop, per pipeline. What's timed: constructing a fresh VM from the \
already-parsed program (`to_plain_vm`/`new_plain`) + `run_with_flat`. See the harness's \
module doc (`tests/src/bin/bench_witness_extension.rs`) for exactly what is/isn't inside \
the timed region and why.\n\
- **Rep3/local**: median of 3 runs, 3-party `LocalNetwork`, wall time from thread-spawn \
to join (each party parses its own copy inside the timed region, mirroring the existing \
Rep3 KAT test harness).\n\
- **Compile**: median of 3 parses, timed separately.\n\
- Config: `CompilerConfig::default()` with `simplification = O2(usize::MAX)` and the \
test `libs/` directory pushed onto `link_library` — identical to what the KAT tests use \
(`plain_vm.rs`/`plain_vm2.rs`/`rep3.rs`/`rep3_vm2.rs`). New pipeline's `UnrollConfig` is \
left at its default.\n\
- `ratio` = old/new: **>1 means new is faster**.\n\
- Rep3 columns are `n/a` for circuits with no non-`#[ignore]`d Rep3 KAT in `rep3_vm2.rs`.\n\
- Poseidon-family circuits get an extra `(no-accel)` row with \
`CIRCOM_MPC_ACCELERATOR_POSEIDON2=0` for both pipelines; compile time is unaffected by \
accelerator config so those rows omit it (`-`).\n\
- Correctness is established by the existing KAT test suites, not re-verified in full \
here; each measurement does assert its first repetition's witness against the KAT on a \
best-effort basis.\n\
\n\
| circuit | old-plain | new-plain | ratio | old-rep3 | new-rep3 | ratio | old-compile | new-compile |\n\
|---|---|---|---|---|---|---|---|---|\n\
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let circuits: Vec<&str> = if args.is_empty() {
        PLAIN_CIRCUITS.to_vec()
    } else {
        args.iter()
            .map(|a| {
                PLAIN_CIRCUITS
                    .iter()
                    .find(|c| **c == a.as_str())
                    .unwrap_or_else(|| panic!("unknown circuit: {a}"))
            })
            .copied()
            .collect()
    };
    let full_run = args.is_empty();
    let out_path = Path::new(OUTPUT_PATH);

    // Previously-written content to preserve when chunking a run across invocations;
    // empty on a full run (fresh file) or when no output file exists yet.
    let prefix = if full_run {
        String::new()
    } else {
        fs::read_to_string(out_path).unwrap_or_default()
    };
    let mut body = String::new();
    if prefix.is_empty() {
        body.push_str(HEADER);
    }

    let mut rows = Vec::new();
    for name in &circuits {
        let do_rep3 = REP3_CIRCUITS.contains(name);
        let Some(row) = bench_one(name, do_rep3) else {
            eprintln!("[{name}] skipped: no KAT input-set 0 on disk");
            let _ = writeln!(
                body,
                "| {name} | (skipped: no KAT input-set 0) | | | | | | | |"
            );
            fs::write(out_path, format!("{prefix}{body}")).unwrap();
            continue;
        };
        write_row(&mut body, &row);

        if is_poseidon(name) {
            eprintln!("[{name}] (no-accel) plain (old)...");
            let (input, witness) =
                load_kat0(name).expect("already loaded successfully above for the main row");
            let old_plain_na = with_poseidon2_accel_off(|| bench_plain_old(name, &input, &witness));
            eprintln!("[{name}] (no-accel) plain (new)...");
            let new_plain_na = with_poseidon2_accel_off(|| bench_plain_new(name, &input, &witness));
            let rep3_na = if do_rep3 {
                eprintln!("[{name}] (no-accel) rep3 (old)...");
                let o = with_poseidon2_accel_off(|| bench_rep3_old(name, &input, &witness));
                eprintln!("[{name}] (no-accel) rep3 (new)...");
                let n = with_poseidon2_accel_off(|| bench_rep3_new(name, &input, &witness));
                Some((o, n))
            } else {
                None
            };
            let na_row = Row {
                circuit: format!("{name} (no-accel)"),
                old_plain: old_plain_na,
                new_plain: new_plain_na,
                rep3: rep3_na,
                compile: None,
            };
            write_row(&mut body, &na_row);
            rows.push(na_row);
        }

        rows.push(row);

        // Flush progress after every circuit so a long background run is inspectable
        // (and a killed run still leaves a readable partial table).
        fs::write(out_path, format!("{prefix}{body}")).unwrap();
    }

    if full_run {
        body.push_str(&build_summary(&rows));
        fs::write(out_path, format!("{prefix}{body}")).unwrap();
    }

    eprintln!("done: {} row(s) written to {}", rows.len(), OUTPUT_PATH);
}

fn gmean(ratios: &[f64]) -> f64 {
    if ratios.is_empty() {
        return f64::NAN;
    }
    let sum_ln: f64 = ratios.iter().map(|r| r.ln()).sum();
    (sum_ln / ratios.len() as f64).exp()
}

/// Builds the report's `## Summary` block from every measured row: per-column
/// (plain/Rep3/compile) faster/slower/within-noise counts, geometric-mean ratio, and
/// worst regression -- self-reproducing so these numbers never again have to be
/// eyeballed and computed by hand from the table (see `build_summary_matches_a_hand_
/// computed_synthetic_table` below, and the Task 6 review finding this fixes).
fn build_summary(rows: &[Row]) -> String {
    let plain: Vec<(&str, f64)> = rows
        .iter()
        .map(|row| {
            (
                row.circuit.as_str(),
                ratio(row.old_plain.median, row.new_plain.median),
            )
        })
        .collect();
    let rep3: Vec<(&str, f64)> = rows
        .iter()
        .filter_map(|row| {
            row.rep3
                .as_ref()
                .map(|(o, n)| (row.circuit.as_str(), ratio(o.median, n.median)))
        })
        .collect();
    let compile: Vec<(&str, f64)> = rows
        .iter()
        .filter_map(|row| {
            row.compile
                .as_ref()
                .map(|(o, n)| (row.circuit.as_str(), ratio(o.median, n.median)))
        })
        .collect();

    let mut s = String::new();
    let _ = writeln!(s, "\n## Summary\n");
    let _ = writeln!(s, "- Rows measured: {}", rows.len());
    write_column_summary(&mut s, "Plain", &plain);
    write_column_summary(&mut s, "Rep3/local", &rep3);
    write_column_summary(&mut s, "Compile", &compile);
    let _ = writeln!(
        s,
        "\nNote: acceptance (\"faster on most, regression on none\") is for the user to \
judge from the table above, not asserted here."
    );
    s
}

/// Writes one column's summary lines (counts, geometric mean, worst regression) to `s` —
/// `label` names the column (`"Plain"`, `"Rep3/local"`, `"Compile"`); `ratios` is that
/// column's `(circuit name, old/new ratio)` pairs, already restricted to the rows that
/// actually have this measurement (e.g. Rep3 only has the subset of rows with a Rep3
/// KAT).
fn write_column_summary(s: &mut String, label: &str, ratios: &[(&str, f64)]) {
    if ratios.is_empty() {
        let _ = writeln!(s, "- {label}: no rows have this measurement.");
        return;
    }

    let (mut faster, mut slower, mut noise) = (0usize, 0usize, 0usize);
    let mut worst: Option<(&str, f64)> = None;
    for &(name, r) in ratios {
        classify(r, &mut faster, &mut slower, &mut noise);
        if worst.is_none_or(|(_, wr)| r < wr) {
            worst = Some((name, r));
        }
    }
    let vals: Vec<f64> = ratios.iter().map(|&(_, r)| r).collect();

    let _ = writeln!(
        s,
        "- {label}, over {} row(s) with this measurement: faster (ratio > 1.1) / slower \
(< 0.9) / within-noise (0.9-1.1): {faster} / {slower} / {noise}",
        ratios.len()
    );
    let _ = writeln!(s, "- {label} geometric mean ratio: {:.3}", gmean(&vals));
    let (name, r) = worst.expect("ratios is non-empty, so at least one worst candidate was set");
    let _ = writeln!(
        s,
        "- {label} worst regression (lowest old/new ratio): {name}, ratio {r:.3}"
    );
}

fn classify(r: f64, faster: &mut usize, slower: &mut usize, noise: &mut usize) {
    if r > 1.1 {
        *faster += 1;
    } else if r < 0.9 {
        *slower += 1;
    } else {
        *noise += 1;
    }
}

// Named `summary_tests`, not `tests` -- this binary's own crate is named `tests`
// (`tests::test_utils::...` is used elsewhere in this file), and a same-named local
// module would shadow that extern crate reference in name resolution.
#[cfg(test)]
mod summary_tests {
    use super::*;

    /// A [`Measurement`] with the given millisecond median — `reps_run`/`capped` don't
    /// feed into `build_summary`'s output, so any fixed value is fine for these tests.
    fn measurement(ms: u64) -> Measurement {
        Measurement {
            median: Duration::from_millis(ms),
            reps_run: 1,
            capped: false,
        }
    }

    /// A small synthetic table exercising every column independently: one circuit is
    /// faster everywhere it's measured; one has a Rep3 regression but no compile
    /// measurement; one has a plain *and* compile regression but no Rep3 KAT. Hand-
    /// computed expectations (ratio = old/new) live in the assertions below.
    fn synthetic_rows() -> Vec<Row> {
        vec![
            Row {
                circuit: "faster_everywhere".to_string(),
                old_plain: measurement(100),
                new_plain: measurement(50), // ratio 2.0 -> faster
                rep3: Some((measurement(100), measurement(50))), // ratio 2.0 -> faster
                compile: Some((measurement(100), measurement(50))), // ratio 2.0 -> faster
            },
            Row {
                circuit: "rep3_regression".to_string(),
                old_plain: measurement(100),
                new_plain: measurement(100), // ratio 1.0 -> noise
                rep3: Some((measurement(100), measurement(200))), // ratio 0.5 -> slower
                compile: None,
            },
            Row {
                circuit: "plain_and_compile_regression".to_string(),
                old_plain: measurement(100),
                new_plain: measurement(120), // ratio 0.833 -> slower
                rep3: None,
                compile: Some((measurement(100), measurement(300))), // ratio 0.333 -> slower
            },
        ]
    }

    #[test]
    fn build_summary_matches_a_hand_computed_synthetic_table() {
        let summary = build_summary(&synthetic_rows());

        assert!(summary.contains("Rows measured: 3"), "summary:\n{summary}");

        // Plain ratios: 2.0 (faster), 1.0 (noise), 0.833 (slower) — one of each, over all
        // 3 rows (every row has a plain measurement).
        assert!(
            summary.contains(
                "Plain, over 3 row(s) with this measurement: faster (ratio > 1.1) / slower \
(< 0.9) / within-noise (0.9-1.1): 1 / 1 / 1"
            ),
            "summary:\n{summary}"
        );
        assert!(
            summary.contains(
                "Plain worst regression (lowest old/new ratio): plain_and_compile_regression, \
ratio 0.833"
            ),
            "summary:\n{summary}"
        );

        // Rep3 ratios: 2.0 (faster), 0.5 (slower) — over only the 2 rows with a Rep3
        // measurement (`plain_and_compile_regression` has none).
        assert!(
            summary.contains(
                "Rep3/local, over 2 row(s) with this measurement: faster (ratio > 1.1) / \
slower (< 0.9) / within-noise (0.9-1.1): 1 / 1 / 0"
            ),
            "summary:\n{summary}"
        );
        assert!(
            summary.contains(
                "Rep3/local worst regression (lowest old/new ratio): rep3_regression, ratio \
0.500"
            ),
            "summary:\n{summary}"
        );

        // Compile ratios: 2.0 (faster), 0.333 (slower) — over only the 2 rows with a
        // compile measurement (`rep3_regression` has none).
        assert!(
            summary.contains(
                "Compile, over 2 row(s) with this measurement: faster (ratio > 1.1) / slower \
(< 0.9) / within-noise (0.9-1.1): 1 / 1 / 0"
            ),
            "summary:\n{summary}"
        );
        assert!(
            summary.contains(
                "Compile worst regression (lowest old/new ratio): \
plain_and_compile_regression, ratio 0.333"
            ),
            "summary:\n{summary}"
        );
    }

    #[test]
    fn write_column_summary_reports_absence_instead_of_dividing_by_zero() {
        let mut s = String::new();
        write_column_summary(&mut s, "Rep3/local", &[]);
        assert_eq!(s, "- Rep3/local: no rows have this measurement.\n");
    }

    #[test]
    fn accelerator_override_restores_the_previous_environment_value() {
        struct RestoreOriginal(Option<std::ffi::OsString>);
        impl Drop for RestoreOriginal {
            fn drop(&mut self) {
                // SAFETY: serialized by ENV_LOCK within this test binary.
                unsafe {
                    match self.0.take() {
                        Some(value) => std::env::set_var(POSEIDON2_ACCEL_VAR, value),
                        None => std::env::remove_var(POSEIDON2_ACCEL_VAR),
                    }
                }
            }
        }

        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let _restore_original = RestoreOriginal(std::env::var_os(POSEIDON2_ACCEL_VAR));
        // SAFETY: serialized by ENV_LOCK within this test binary.
        unsafe {
            std::env::set_var(POSEIDON2_ACCEL_VAR, "previous");
        }
        let observed = with_poseidon2_accel_off(|| std::env::var(POSEIDON2_ACCEL_VAR).unwrap());
        assert_eq!(observed, "0");
        assert_eq!(std::env::var(POSEIDON2_ACCEL_VAR).unwrap(), "previous");
    }
}
