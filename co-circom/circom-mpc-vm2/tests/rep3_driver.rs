//! Rep3 driver tests: 3-party replicated-secret-sharing execution over
//! `mpc_net::local::LocalNetwork`, mirroring the old `circom-mpc-vm` Rep3 test harness
//! (`tests/tests/circom/witness_extension_tests/rep3.rs`) but scaled down to this
//! crate's hand-assembled-program style (see `tests/common/mod.rs`).
mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::api::Rep3WitnessExtension;
use circom_mpc_vm2::driver::VmDriver;
use circom_mpc_vm2::drivers::rep3::{Rep3Driver, Rep3VmType};
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::{CompiledProgram, VMConfig};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, conversion::A2BType};
use mpc_net::local::LocalNetwork;
use std::sync::Arc;

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
