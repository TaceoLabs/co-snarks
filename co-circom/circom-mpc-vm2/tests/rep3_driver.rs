//! Rep3 driver tests: 3-party replicated-secret-sharing execution over
//! `mpc_net::local::LocalNetwork`, mirroring the old `circom-mpc-vm` Rep3 test harness
//! (`tests/tests/circom/witness_extension_tests/rep3.rs`) but scaled down to this
//! crate's hand-assembled-program style (see `tests/common/mod.rs`).
mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::api::Rep3WitnessExtension;
use circom_mpc_vm2::driver::VmDriver;
use circom_mpc_vm2::drivers::rep3::{Rep3Driver, Rep3VmType};
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::{CompiledProgram, VMConfig};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, conversion::A2BType};
use mpc_net::bytes::Bytes;
use mpc_net::local::LocalNetwork;
use mpc_net::{ConnectionStats, Network};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Runs three per-party closures concurrently, each handed its own pair of
/// `LocalNetwork`s (`net0`/`net1`) — [`Rep3Driver`] needs two independent connections
/// so ops that need two concurrent conversions (e.g. `bit_xor` on two shared operands)
/// can run them without serializing on a single network. Mirrors the old Rep3 test
/// harness's `nets0`/`nets1` + thread-per-party setup.
fn run_3_parties<T, F0, F1, F2>(f0: F0, f1: F1, f2: F2) -> [T; 3]
where
    T: Send + 'static,
    F0: FnOnce(&LocalNetwork, &LocalNetwork) -> T + Send + 'static,
    F1: FnOnce(&LocalNetwork, &LocalNetwork) -> T + Send + 'static,
    F2: FnOnce(&LocalNetwork, &LocalNetwork) -> T + Send + 'static,
{
    let [net0_0, net0_1, net0_2] = LocalNetwork::new_3_parties();
    let [net1_0, net1_1, net1_2] = LocalNetwork::new_3_parties();
    let t0 = std::thread::spawn(move || f0(&net0_0, &net1_0));
    let t1 = std::thread::spawn(move || f1(&net0_1, &net1_1));
    let t2 = std::thread::spawn(move || f2(&net0_2, &net1_2));
    [
        t0.join().expect("party 0 panicked"),
        t1.join().expect("party 1 panicked"),
        t2.join().expect("party 2 panicked"),
    ]
}

/// Scalar-op matrix: shared×shared mul, shared+public add, comparisons on shared
/// operands, equality, and a `cmux` predicated by a genuinely shared condition. Every
/// party runs the same sequence of [`VmDriver`] calls on its own shares and opens the
/// results; the opened values must agree across parties and match the plain-field
/// expectation.
#[test]
fn rep3_scalar_ops() {
    let mut rng = rand::thread_rng();
    let a_val = Fr::from(7u64);
    let b_val = Fr::from(3u64);
    let cond_val = Fr::from(1u64); // genuinely shared cond = true (selects `a`)

    let a_shares = rep3::share_field_elements(&[a_val], &mut rng);
    let b_shares = rep3::share_field_elements(&[b_val], &mut rng);
    let cond_shares = rep3::share_field_elements(&[cond_val], &mut rng);

    let body =
        |a: Rep3PrimeFieldShare<Fr>, b: Rep3PrimeFieldShare<Fr>, cond: Rep3PrimeFieldShare<Fr>| {
            move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Fr> {
                let mut driver = Rep3Driver::new(net0, net1, A2BType::default()).expect("driver");
                let a = Rep3VmType::Arithmetic(a);
                let b = Rep3VmType::Arithmetic(b);
                let ten = Rep3VmType::Public(Fr::from(10u64));
                let cond = Rep3VmType::Arithmetic(cond);

                let mul = driver.mul(&a, &b).expect("mul");
                let add = driver.add(&a, &ten).expect("add");
                let lt = driver.lt(&a, &b).expect("lt");
                let eq = driver.eq(&a, &b).expect("eq");
                let cmux = driver.cmux(&cond, &a, &b).expect("cmux");

                vec![
                    driver.open(&mul).expect("open mul"),
                    driver.open(&add).expect("open add"),
                    driver.open(&lt).expect("open lt"),
                    driver.open(&eq).expect("open eq"),
                    driver.open(&cmux).expect("open cmux"),
                ]
            }
        };

    let results = run_3_parties(
        body(a_shares[0][0], b_shares[0][0], cond_shares[0][0]),
        body(a_shares[1][0], b_shares[1][0], cond_shares[1][0]),
        body(a_shares[2][0], b_shares[2][0], cond_shares[2][0]),
    );

    assert_eq!(results[0], results[1], "party 0/1 must agree");
    assert_eq!(results[1], results[2], "party 1/2 must agree");
    let opened = &results[0];
    assert_eq!(opened[0], a_val * b_val, "mul");
    assert_eq!(opened[1], a_val + Fr::from(10u64), "add");
    assert_eq!(opened[2], Fr::from(0u64), "7 < 3 is false");
    assert_eq!(opened[3], Fr::from(0u64), "7 == 3 is false");
    assert_eq!(opened[4], a_val, "cmux(true, a, b) == a");
}

/// The hand-assembled two-signal multiplier (`out <== a * b`, see
/// `common::multiplier_program`), run end-to-end through [`Rep3WitnessExtension`] with
/// both inputs genuinely shared. The reconstructed witness must equal the plain result.
#[test]
fn rep3_engine_end_to_end() {
    let program = Arc::new(common::multiplier_program());
    let mut rng = rand::thread_rng();
    let a_shares = rep3::share_field_elements(&[Fr::from(6u64)], &mut rng);
    let b_shares = rep3::share_field_elements(&[Fr::from(7u64)], &mut rng);

    let body = |program: Arc<CompiledProgram<Fr>>,
                a: Rep3PrimeFieldShare<Fr>,
                b: Rep3PrimeFieldShare<Fr>| {
        move |net0: &LocalNetwork, net1: &LocalNetwork| {
            let wex = Rep3WitnessExtension::new_rep3(net0, net1, program, VMConfig::default())
                .expect("new_rep3");
            wex.run_with_flat(
                vec![Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)],
                0,
            )
            .expect("run_with_flat")
            .into_shared_witness()
        }
    };

    let [w0, w1, w2] = run_3_parties(
        body(program.clone(), a_shares[0][0], b_shares[0][0]),
        body(program.clone(), a_shares[1][0], b_shares[1][0]),
        body(program, a_shares[2][0], b_shares[2][0]),
    );

    assert_eq!(w0.public_inputs, w1.public_inputs);
    assert_eq!(w1.public_inputs, w2.public_inputs);
    assert_eq!(w0.public_inputs, vec![Fr::from(1u64), Fr::from(42u64)]);

    let witness = rep3::combine_field_elements(&w0.witness, &w1.witness, &w2.witness);
    assert_eq!(witness, vec![Fr::from(6u64), Fr::from(7u64)]);
}

/// Hand-assembled shared-if program (mirrors `shared_if::shared_if_merges_stores`):
/// `out = cond ? 3 : 5`, both branches storing a public constant into `out`, run
/// end-to-end through the Rep3 engine with a genuinely shared `cond`. Both arms must
/// execute (predication, not a real branch), merging to the value selected by `cond`
/// once opened.
#[test]
fn rep3_shared_if_predication() {
    let mut program = common::single_template_program(
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
    program.constants = vec![Fr::from(3u64), Fr::from(5u64)];
    program.output_mapping.insert("out".to_string(), (1, 1));
    let program = Arc::new(program);

    for (cond_val, expected) in [(1u64, 3u64), (0u64, 5u64)] {
        let mut rng = rand::thread_rng();
        let cond_shares = rep3::share_field_elements(&[Fr::from(cond_val)], &mut rng);

        let body = |program: Arc<CompiledProgram<Fr>>, cond: Rep3PrimeFieldShare<Fr>| {
            move |net0: &LocalNetwork, net1: &LocalNetwork| {
                let wex = Rep3WitnessExtension::new_rep3(net0, net1, program, VMConfig::default())
                    .expect("new_rep3");
                let finalized = wex
                    .run_with_flat(vec![Rep3VmType::Arithmetic(cond)], 0)
                    .expect("run_with_flat");
                finalized.get_output("out").expect("out")[0]
            }
        };

        let results = run_3_parties(
            body(program.clone(), cond_shares[0][0]),
            body(program.clone(), cond_shares[1][0]),
            body(program.clone(), cond_shares[2][0]),
        );

        for r in results {
            assert_eq!(r, Fr::from(expected), "cond={cond_val}");
        }
    }
}

/// A `Network` wrapper counting `send`/`recv` calls (round-trip "messages"), used by
/// the round-count assertion below. Built purely against the public `Network` trait —
/// does not touch `mpc-net` itself.
struct CountingNetwork<'a> {
    inner: &'a LocalNetwork,
    sends: AtomicUsize,
    recvs: AtomicUsize,
}

impl<'a> CountingNetwork<'a> {
    fn new(inner: &'a LocalNetwork) -> Self {
        Self {
            inner,
            sends: AtomicUsize::new(0),
            recvs: AtomicUsize::new(0),
        }
    }

    /// Total number of `send` + `recv` calls made so far.
    fn message_count(&self) -> usize {
        self.sends.load(Ordering::Relaxed) + self.recvs.load(Ordering::Relaxed)
    }
}

impl Network for CountingNetwork<'_> {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.sends.fetch_add(1, Ordering::Relaxed);
        self.inner.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.recvs.fetch_add(1, Ordering::Relaxed);
        self.inner.recv(from)
    }

    fn flush(&self) -> eyre::Result<()> {
        self.inner.flush()
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

/// Runs three per-party closures concurrently over [`CountingNetwork`]-wrapped
/// `LocalNetwork`s instead of plain ones — same shape as [`run_3_parties`], needed so
/// the round-count test can observe `send`/`recv` call counts.
fn run_3_parties_counting<T, F0, F1, F2>(f0: F0, f1: F1, f2: F2) -> [T; 3]
where
    T: Send + 'static,
    F0: FnOnce(&CountingNetwork, &CountingNetwork) -> T + Send + 'static,
    F1: FnOnce(&CountingNetwork, &CountingNetwork) -> T + Send + 'static,
    F2: FnOnce(&CountingNetwork, &CountingNetwork) -> T + Send + 'static,
{
    let [net0_0, net0_1, net0_2] = LocalNetwork::new_3_parties();
    let [net1_0, net1_1, net1_2] = LocalNetwork::new_3_parties();
    let t0 = std::thread::spawn(move || {
        let cn0 = CountingNetwork::new(&net0_0);
        let cn1 = CountingNetwork::new(&net1_0);
        f0(&cn0, &cn1)
    });
    let t1 = std::thread::spawn(move || {
        let cn0 = CountingNetwork::new(&net0_1);
        let cn1 = CountingNetwork::new(&net1_1);
        f1(&cn0, &cn1)
    });
    let t2 = std::thread::spawn(move || {
        let cn0 = CountingNetwork::new(&net0_2);
        let cn1 = CountingNetwork::new(&net1_2);
        f2(&cn0, &cn1)
    });
    [
        t0.join().expect("party 0 panicked"),
        t1.join().expect("party 1 panicked"),
        t2.join().expect("party 2 panicked"),
    ]
}

/// A compiler-proven boolean condition must not pay for Circom's general
/// zero/non-zero normalization. The two programs differ only in `SharedIf` versus
/// `SharedIfBit`; with a genuinely shared bit, the latter performs no network IO at
/// branch entry while the former runs the Rep3 `neq(cond, 0)` protocol.
#[test]
fn rep3_shared_if_bit_skips_condition_normalization_messages() {
    fn program(bit: bool) -> CompiledProgram<Fr> {
        let branch = if bit {
            Instr::SharedIfBit {
                cond: Src::Signal(Addr::Const(0)),
                else_target: 1,
            }
        } else {
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(0)),
                else_target: 1,
            }
        };
        common::single_template_program(
            vec![branch, Instr::SharedEnd, Instr::Return],
            0,
            0,
            0,
            1,
            0,
            2,
        )
    }

    let mut rng = rand::thread_rng();
    let cond_shares = rep3::share_field_elements(&[Fr::from(1u64)], &mut rng);

    let body = |cond: Rep3PrimeFieldShare<Fr>| {
        move |net0: &CountingNetwork, net1: &CountingNetwork| -> (usize, usize) {
            let mut driver = Rep3Driver::new(net0, net1, A2BType::default()).expect("driver");

            let run = |program: CompiledProgram<Fr>, driver: &mut Rep3Driver<'_, Fr, _>| {
                let mut machine = Machine::new(&program, driver, VMConfig::default()).unwrap();
                machine.signals[program.main_input_list[0].offset] = Rep3VmType::Arithmetic(cond);
                let start = net0.message_count();
                machine.run_main().unwrap();
                net0.message_count() - start
            };

            let normalized = run(program(false), &mut driver);
            let already_bit = run(program(true), &mut driver);
            (normalized, already_bit)
        }
    };

    let results = run_3_parties_counting(
        body(cond_shares[0][0]),
        body(cond_shares[1][0]),
        body(cond_shares[2][0]),
    );
    for (party, (normalized, already_bit)) in results.into_iter().enumerate() {
        assert!(
            normalized > already_bit,
            "party {party}: SharedIf used {normalized} messages, SharedIfBit used {already_bit}"
        );
        assert_eq!(
            already_bit, 0,
            "party {party}: a top-level SharedIfBit should require no network messages"
        );
    }
}

/// (a)/(b): `bin_many` batched correctness AND order preservation, in one pass.
/// Interleaved public/shared operand shapes on both sides — `a` is
/// `[pub, shared, pub, shared]`, `b` is `[shared, shared, pub, pub]`, exactly the
/// scatter/gather-bug-prone pattern the brief calls out — for every op-kind that
/// `bin_many` batches (`Mul`, `BoolAnd`, `Eq`, `Neq`), plus one op with no vectorized
/// primitive (`Lt`) to confirm the scalar-loop fallback still lines up. For each op,
/// results from `bin_many` and from a per-element scalar loop are opened and compared
/// against each other and against the plain expectation, at every index.
#[test]
fn rep3_bin_many_matches_scalar_loop_and_preserves_order() {
    let mut rng = rand::thread_rng();

    // Shapes: a = [Public, Arithmetic, Public, Arithmetic], b = [Arithmetic, Arithmetic, Public, Public].
    let a_vals = [
        Fr::from(7u64),
        Fr::from(5u64),
        Fr::from(9u64),
        Fr::from(4u64),
    ];
    let b_vals = [
        Fr::from(3u64),
        Fr::from(5u64),
        Fr::from(9u64),
        Fr::from(4u64),
    ];
    // Elements that are shared: a[1], a[3], b[0], b[1].
    let shared_vals = [a_vals[1], a_vals[3], b_vals[0], b_vals[1]];
    let shares = rep3::share_field_elements(&shared_vals, &mut rng);

    // Boolean (0/1) values for BoolAnd, same interleaved shape pattern.
    let a_bool = [
        Fr::from(1u64),
        Fr::from(0u64),
        Fr::from(1u64),
        Fr::from(1u64),
    ];
    let b_bool = [
        Fr::from(0u64),
        Fr::from(1u64),
        Fr::from(1u64),
        Fr::from(0u64),
    ];
    let shared_bool_vals = [a_bool[1], a_bool[3], b_bool[0], b_bool[1]];
    let bool_shares = rep3::share_field_elements(&shared_bool_vals, &mut rng);

    let body = |shares: [Rep3PrimeFieldShare<Fr>; 4], bool_shares: [Rep3PrimeFieldShare<Fr>; 4]| {
        move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Vec<Fr>> {
            let mut driver = Rep3Driver::new(net0, net1, A2BType::default()).expect("driver");
            let [a1, a3, b0, b1] = shares;
            let a = vec![
                Rep3VmType::Public(a_vals[0]),
                Rep3VmType::Arithmetic(a1),
                Rep3VmType::Public(a_vals[2]),
                Rep3VmType::Arithmetic(a3),
            ];
            let b = vec![
                Rep3VmType::Arithmetic(b0),
                Rep3VmType::Arithmetic(b1),
                Rep3VmType::Public(b_vals[2]),
                Rep3VmType::Public(b_vals[3]),
            ];

            let [a1b, a3b, b0b, b1b] = bool_shares;
            let a_b = vec![
                Rep3VmType::Public(a_bool[0]),
                Rep3VmType::Arithmetic(a1b),
                Rep3VmType::Public(a_bool[2]),
                Rep3VmType::Arithmetic(a3b),
            ];
            let b_b = vec![
                Rep3VmType::Arithmetic(b0b),
                Rep3VmType::Arithmetic(b1b),
                Rep3VmType::Public(b_bool[2]),
                Rep3VmType::Public(b_bool[3]),
            ];

            let mut out = Vec::new();
            for (op, av, bv) in [
                (BinOp::Mul, &a, &b),
                (BinOp::Eq, &a, &b),
                (BinOp::Neq, &a, &b),
                (BinOp::Lt, &a, &b),
                (BinOp::BoolAnd, &a_b, &b_b),
            ] {
                let batched = driver.bin_many(op, av, bv).expect("bin_many");
                let scalar = av
                    .iter()
                    .zip(bv)
                    .map(|(x, y)| circom_mpc_vm2::driver::apply_bin(&mut driver, op, x, y))
                    .collect::<eyre::Result<Vec<_>>>()
                    .expect("scalar loop");
                assert_eq!(batched.len(), scalar.len());
                let opened_batched = batched
                    .iter()
                    .map(|v| driver.open(v).expect("open batched"))
                    .collect::<Vec<_>>();
                let opened_scalar = scalar
                    .iter()
                    .map(|v| driver.open(v).expect("open scalar"))
                    .collect::<Vec<_>>();
                assert_eq!(
                    opened_batched, opened_scalar,
                    "bin_many({op:?}) must match the scalar loop element-wise"
                );
                out.push(opened_batched);
            }
            out
        }
    };

    let results = run_3_parties(
        body(
            [shares[0][0], shares[0][1], shares[0][2], shares[0][3]],
            [
                bool_shares[0][0],
                bool_shares[0][1],
                bool_shares[0][2],
                bool_shares[0][3],
            ],
        ),
        body(
            [shares[1][0], shares[1][1], shares[1][2], shares[1][3]],
            [
                bool_shares[1][0],
                bool_shares[1][1],
                bool_shares[1][2],
                bool_shares[1][3],
            ],
        ),
        body(
            [shares[2][0], shares[2][1], shares[2][2], shares[2][3]],
            [
                bool_shares[2][0],
                bool_shares[2][1],
                bool_shares[2][2],
                bool_shares[2][3],
            ],
        ),
    );

    assert_eq!(results[0], results[1], "party 0/1 must agree");
    assert_eq!(results[1], results[2], "party 1/2 must agree");
    let [mul, eq, neq, lt, bool_and] = <[Vec<Fr>; 5]>::try_from(results[0].clone()).unwrap();

    // Expected values, index-by-index, in the original (pre-partition) order.
    let expected_mul: Vec<Fr> = (0..4).map(|i| a_vals[i] * b_vals[i]).collect();
    let expected_eq: Vec<Fr> = (0..4)
        .map(|i| {
            if a_vals[i] == b_vals[i] {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            }
        })
        .collect();
    let expected_neq: Vec<Fr> = expected_eq.iter().map(|e| Fr::from(1u64) - e).collect();
    let expected_lt: Vec<Fr> = (0..4)
        .map(|i| {
            if a_vals[i] < b_vals[i] {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            }
        })
        .collect();
    let expected_bool_and: Vec<Fr> = (0..4)
        .map(|i| {
            if a_bool[i] == Fr::from(1u64) && b_bool[i] == Fr::from(1u64) {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            }
        })
        .collect();

    assert_eq!(mul, expected_mul, "Mul, order-preserving");
    assert_eq!(eq, expected_eq, "Eq, order-preserving");
    assert_eq!(neq, expected_neq, "Neq, order-preserving");
    assert_eq!(
        lt, expected_lt,
        "Lt (scalar-loop fallback), order-preserving"
    );
    assert_eq!(bool_and, expected_bool_and, "BoolAnd, order-preserving");
}

/// (c) `cmux_many` correctness for both possible values of a genuinely shared
/// condition, with interleaved public/shared shapes among the truthy/falsy vectors.
#[test]
fn rep3_cmux_many_correctness() {
    for cond_val in [0u64, 1u64] {
        let mut rng = rand::thread_rng();
        let cond_shares = rep3::share_field_elements(&[Fr::from(cond_val)], &mut rng);

        // truthy: [Public(1), Arithmetic(2), Public(3), Arithmetic(4)]
        // falsy:  [Arithmetic(10), Public(20), Arithmetic(30), Public(40)]
        let shared_vals = [
            Fr::from(2u64),
            Fr::from(4u64),
            Fr::from(10u64),
            Fr::from(30u64),
        ];
        let shares = rep3::share_field_elements(&shared_vals, &mut rng);

        let body = |cond: Rep3PrimeFieldShare<Fr>, s: [Rep3PrimeFieldShare<Fr>; 4]| {
            move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Fr> {
                let mut driver = Rep3Driver::new(net0, net1, A2BType::default()).expect("driver");
                let [t1, t3, f0, f2] = s;
                let cond = Rep3VmType::Arithmetic(cond);
                let truthy = vec![
                    Rep3VmType::Public(Fr::from(1u64)),
                    Rep3VmType::Arithmetic(t1),
                    Rep3VmType::Public(Fr::from(3u64)),
                    Rep3VmType::Arithmetic(t3),
                ];
                let falsy = vec![
                    Rep3VmType::Arithmetic(f0),
                    Rep3VmType::Public(Fr::from(20u64)),
                    Rep3VmType::Arithmetic(f2),
                    Rep3VmType::Public(Fr::from(40u64)),
                ];
                let res = driver.cmux_many(&cond, &truthy, &falsy).expect("cmux_many");
                res.into_iter()
                    .map(|v| driver.open(&v).expect("open"))
                    .collect()
            }
        };

        let results = run_3_parties(
            body(
                cond_shares[0][0],
                [shares[0][0], shares[0][1], shares[0][2], shares[0][3]],
            ),
            body(
                cond_shares[1][0],
                [shares[1][0], shares[1][1], shares[1][2], shares[1][3]],
            ),
            body(
                cond_shares[2][0],
                [shares[2][0], shares[2][1], shares[2][2], shares[2][3]],
            ),
        );

        assert_eq!(
            results[0], results[1],
            "party 0/1 must agree, cond={cond_val}"
        );
        assert_eq!(
            results[1], results[2],
            "party 1/2 must agree, cond={cond_val}"
        );

        let expected: Vec<Fr> = if cond_val == 1 {
            vec![
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
            ]
        } else {
            vec![
                Fr::from(10u64),
                Fr::from(20u64),
                Fr::from(30u64),
                Fr::from(40u64),
            ]
        };
        assert_eq!(results[0], expected, "cond={cond_val}");
    }
}

/// (d) Engine-level test: a hand-assembled program running `BinN{Mul, n:4}` over 4
/// shared signal pairs through the full [`Rep3WitnessExtension`] (`BinN` dispatches to
/// `bin_many`, so this exercises the batched path end-to-end, not just the driver in
/// isolation). Global signal layout: `[0]=1`, `[1..5)=out[4]`, `[5..9)=a[4]`,
/// `[9..13)=b[4]`; in-template addressing is relative to the main component's offset
/// (`1`, for the global constant slot), so local indices are `out=0`, `a=4`, `b=8`
/// (mirrors `common::multiplier_program`'s `Const(0)`-relative addressing).
#[test]
fn rep3_engine_bin_n_mul() {
    let instrs = vec![
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
    ];
    let mut program = common::single_template_program(instrs, 4, 0, 0, 8, 4, 13);
    program.output_mapping.insert("out".to_string(), (1, 4));
    let program = Arc::new(program);

    let a_vals = [
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(5u64),
        Fr::from(7u64),
    ];
    let b_vals = [
        Fr::from(11u64),
        Fr::from(13u64),
        Fr::from(17u64),
        Fr::from(19u64),
    ];
    let mut rng = rand::thread_rng();
    let a_shares = rep3::share_field_elements(&a_vals, &mut rng);
    let b_shares = rep3::share_field_elements(&b_vals, &mut rng);

    let body = |program: Arc<CompiledProgram<Fr>>,
                a: [Rep3PrimeFieldShare<Fr>; 4],
                b: [Rep3PrimeFieldShare<Fr>; 4]| {
        move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Fr> {
            let wex = Rep3WitnessExtension::new_rep3(net0, net1, program, VMConfig::default())
                .expect("new_rep3");
            let inputs = a.into_iter().chain(b).map(Rep3VmType::Arithmetic).collect();
            let finalized = wex.run_with_flat(inputs, 0).expect("run_with_flat");
            finalized.get_output("out").expect("out")
        }
    };

    let results = run_3_parties(
        body(
            program.clone(),
            [
                a_shares[0][0],
                a_shares[0][1],
                a_shares[0][2],
                a_shares[0][3],
            ],
            [
                b_shares[0][0],
                b_shares[0][1],
                b_shares[0][2],
                b_shares[0][3],
            ],
        ),
        body(
            program.clone(),
            [
                a_shares[1][0],
                a_shares[1][1],
                a_shares[1][2],
                a_shares[1][3],
            ],
            [
                b_shares[1][0],
                b_shares[1][1],
                b_shares[1][2],
                b_shares[1][3],
            ],
        ),
        body(
            program,
            [
                a_shares[2][0],
                a_shares[2][1],
                a_shares[2][2],
                a_shares[2][3],
            ],
            [
                b_shares[2][0],
                b_shares[2][1],
                b_shares[2][2],
                b_shares[2][3],
            ],
        ),
    );

    assert_eq!(results[0], results[1], "party 0/1 must agree");
    assert_eq!(results[1], results[2], "party 1/2 must agree");
    let expected: Vec<Fr> = (0..4).map(|i| a_vals[i] * b_vals[i]).collect();
    assert_eq!(results[0], expected);
}

/// Round-count assertion: `bin_many(Mul, ...)` over 8 shared pairs must not use more
/// network messages (`send`/`recv` calls, counted via [`CountingNetwork`]) than a
/// single scalar `mul` — both bottom out in exactly one `reshare`/`reshare_many` call
/// (one `send` + one `recv`), so batching 8 multiplications costs no more than 1.
#[test]
fn rep3_bin_many_mul_round_count_matches_single_scalar_mul() {
    let mut rng = rand::thread_rng();
    let n = 8;
    let a_vals: Vec<Fr> = (0..n as u64).map(Fr::from).collect();
    let b_vals: Vec<Fr> = (0..n as u64).map(|i| Fr::from(i + 100)).collect();
    let a_shares = rep3::share_field_elements(&a_vals, &mut rng);
    let b_shares = rep3::share_field_elements(&b_vals, &mut rng);
    let single_a = rep3::share_field_elements(&[Fr::from(3u64)], &mut rng);
    let single_b = rep3::share_field_elements(&[Fr::from(4u64)], &mut rng);

    let body = |a: Vec<Rep3PrimeFieldShare<Fr>>,
                b: Vec<Rep3PrimeFieldShare<Fr>>,
                sa: Rep3PrimeFieldShare<Fr>,
                sb: Rep3PrimeFieldShare<Fr>| {
        move |net0: &CountingNetwork, net1: &CountingNetwork| -> (usize, usize) {
            let mut driver = Rep3Driver::new(net0, net1, A2BType::default()).expect("driver");

            let start = net0.message_count();
            let a_vm = Rep3VmType::Arithmetic(sa);
            let b_vm = Rep3VmType::Arithmetic(sb);
            driver.mul(&a_vm, &b_vm).expect("scalar mul");
            let scalar_msgs = net0.message_count() - start;

            let a_vm: Vec<_> = a.into_iter().map(Rep3VmType::Arithmetic).collect();
            let b_vm: Vec<_> = b.into_iter().map(Rep3VmType::Arithmetic).collect();
            let start = net0.message_count();
            driver
                .bin_many(BinOp::Mul, &a_vm, &b_vm)
                .expect("bin_many mul");
            let batched_msgs = net0.message_count() - start;

            (scalar_msgs, batched_msgs)
        }
    };

    let results = run_3_parties_counting(
        body(
            a_shares[0].clone(),
            b_shares[0].clone(),
            single_a[0][0],
            single_b[0][0],
        ),
        body(
            a_shares[1].clone(),
            b_shares[1].clone(),
            single_a[1][0],
            single_b[1][0],
        ),
        body(
            a_shares[2].clone(),
            b_shares[2].clone(),
            single_a[2][0],
            single_b[2][0],
        ),
    );

    for (party, (scalar_msgs, batched_msgs)) in results.into_iter().enumerate() {
        assert!(
            batched_msgs <= scalar_msgs,
            "party {party}: bin_many(Mul) over {n} shared pairs used {batched_msgs} messages, \
             more than a single scalar mul's {scalar_msgs}"
        );
    }
}

/// Round-count assertion, at the `Machine`/`Instr` level: a predicated `StoreN{n:8}`
/// under a genuinely shared condition — the real `write_dst_n`/`cmux_many` path, driven
/// through an actual VM program rather than a direct driver call — must not use more
/// network messages than a single scalar `cmux`. Both bottom out in exactly one
/// reshare round (`arithmetic::cmux_vec` vs. `mul`'s reshare), so batching 8 predicated
/// stores into one costs no more than one normalized shared predicate plus one scalar
/// cmux. SharedIf first converts Circom's zero/non-zero condition into a bit, so the
/// baseline includes that same fixed normalization cost.
///
/// Signal layout (component-relative addresses; global index = comp.offset(1) + addr):
/// `[0]=1, [1..9]=out (8 elements, addr 0..8), [9]=cond (addr 8), [10..18]=a (addr
/// 9..17)`. The program: `LoadN` gathers `a` into regs, a `SharedIf` on `cond` guards a
/// `StoreN{n:8}` writing `out = a`, no `else` body.
#[test]
fn rep3_predicated_storen_round_count_matches_single_scalar_cmux() {
    let mut rng = rand::thread_rng();
    let n = 8usize;
    let cond_val = Fr::from(1u64);
    let a_vals: Vec<Fr> = (0..n as u64).map(|i| Fr::from(i + 10)).collect();
    let cond_shares = rep3::share_field_elements(&[cond_val], &mut rng);
    let a_shares = rep3::share_field_elements(&a_vals, &mut rng);
    let single_cond = rep3::share_field_elements(&[Fr::from(1u64)], &mut rng);
    let single_truthy = rep3::share_field_elements(&[Fr::from(4u64)], &mut rng);

    let program = common::single_template_program(
        vec![
            Instr::LoadN {
                dst: 0,
                src: Src::Signal(Addr::Const(9)),
                n: n as u32,
            },
            Instr::SharedIf {
                cond: Src::Signal(Addr::Const(8)),
                else_target: 3,
            },
            Instr::StoreN {
                dst: Dst::Signal(Addr::Const(0)),
                src: 0,
                n: n as u32,
            },
            Instr::SharedElse { end_target: 4 },
            Instr::SharedEnd,
            Instr::Return,
        ],
        n as u16,
        0,
        0,
        (n + 1) as u32,
        n as u32,
        2 + 2 * n,
    );

    let body = move |program: CompiledProgram<Fr>,
                     cond: Rep3PrimeFieldShare<Fr>,
                     a: Vec<Rep3PrimeFieldShare<Fr>>,
                     single_cond: Rep3PrimeFieldShare<Fr>,
                     single_truthy: Rep3PrimeFieldShare<Fr>| {
        move |net0: &CountingNetwork, net1: &CountingNetwork| -> (usize, usize) {
            let mut driver = Rep3Driver::new(net0, net1, A2BType::default()).expect("driver");

            let start = net0.message_count();
            let cond_vm = Rep3VmType::Arithmetic(single_cond);
            let truthy_vm = Rep3VmType::Arithmetic(single_truthy);
            let falsy_vm = Rep3VmType::Public(Fr::from(0u64));
            let zero_vm = Rep3VmType::Public(Fr::from(0u64));
            let cond_vm = driver
                .neq(&cond_vm, &zero_vm)
                .expect("normalize shared condition");
            driver
                .cmux(&cond_vm, &truthy_vm, &falsy_vm)
                .expect("normalized scalar cmux");
            let scalar_msgs = net0.message_count() - start;

            let mut machine =
                Machine::new(&program, &mut driver, VMConfig::default()).expect("Machine::new");
            let info = program.main_input_list[0].clone();
            machine.signals[info.offset] = Rep3VmType::Arithmetic(cond);
            for (i, v) in a.into_iter().enumerate() {
                machine.signals[info.offset + 1 + i] = Rep3VmType::Arithmetic(v);
            }
            let start = net0.message_count();
            machine.run_main().expect("run_main");
            let batched_msgs = net0.message_count() - start;

            (scalar_msgs, batched_msgs)
        }
    };

    let results = run_3_parties_counting(
        body(
            program.clone(),
            cond_shares[0][0],
            a_shares[0].clone(),
            single_cond[0][0],
            single_truthy[0][0],
        ),
        body(
            program.clone(),
            cond_shares[1][0],
            a_shares[1].clone(),
            single_cond[1][0],
            single_truthy[1][0],
        ),
        body(
            program,
            cond_shares[2][0],
            a_shares[2].clone(),
            single_cond[2][0],
            single_truthy[2][0],
        ),
    );

    for (party, (scalar_msgs, batched_msgs)) in results.into_iter().enumerate() {
        assert!(
            batched_msgs <= scalar_msgs,
            "party {party}: predicated StoreN{{n:{n}}} used {batched_msgs} messages, \
             more than one normalized scalar cmux's {scalar_msgs}"
        );
    }
}
