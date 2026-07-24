//! Accelerator tests: function/component registration, construction-time binding
//! (`can_handle`), and the pre-defined `Num2Bits` registration exercised end-to-end
//! through the Rep3 driver.
mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::accel::{MpcAccelerator, MpcAcceleratorConfig, TemplateInfo};
use circom_mpc_vm2::api::Rep3WitnessExtension;
use circom_mpc_vm2::driver::VmDriver;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::drivers::rep3::Rep3VmType;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::{CompiledProgram, DebugInfo, FunctionCode, InputInfo, VMConfig};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare};
use mpc_net::local::LocalNetwork;
use std::collections::HashMap;
use std::sync::Arc;

/// f(a) = a + a — a function whose body computes doubling directly (so running it
/// normally, without any accelerator, gives the correct answer), used to check that a
/// registered `double_0` accelerator (computing the same value a different way) agrees.
///
/// f instrs: r0 = vars[0] + vars[0]; Ret r0, n=1.
/// template: r0 = signal(in); CallFn(f) -> r1; out = r1.
/// signal layout: [0]=1, [1]=out, [2]=in.
fn double_program() -> CompiledProgram<Fr> {
    let f = FunctionCode {
        instrs: vec![
            Instr::Bin {
                op: BinOp::Add,
                dst: 0,
                a: Src::Var(Addr::Const(0)),
                b: Src::Var(Addr::Const(0)),
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
    common::program_with_functions(
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
        vec![f],
        vec!["double_0"],
    )
}

/// (a) Function-accelerator on/off equivalence: the same [`double_program`] run once
/// with no accelerator bound (executes `f`'s body) and once with a `double_0`
/// accelerator registered (skips the body, computes `2*a` a different way) — both must
/// agree, since the body is constructed to be plainly executable and correct.
#[test]
fn function_accelerator_on_off_equivalence() {
    let program = double_program();

    // Off: no accelerator bound at all, runs the body.
    let mut driver_off = PlainDriver::default();
    let mut machine_off =
        Machine::new(&program, &mut driver_off, VMConfig::default()).expect("Machine::new");
    machine_off.signals[2] = Fr::from(21u64);
    machine_off.run_main().expect("run_main (off)");
    let off_result = machine_off.signals[1];

    // On: a `double_0` accelerator is registered and bound, body is skipped.
    let mut accel: MpcAccelerator<Fr, PlainDriver<Fr>> = MpcAccelerator::empty();
    accel.register_function("double_0", |driver, args| {
        let two = driver.public_from(Fr::from(2u64));
        Ok(vec![driver.mul(&args[0], &two)?])
    });
    let mut driver_on = PlainDriver::default();
    let mut machine_on =
        Machine::new_with_accelerator(&program, &mut driver_on, VMConfig::default(), &accel)
            .expect("Machine::new_with_accelerator");
    machine_on.signals[2] = Fr::from(21u64);
    machine_on.run_main().expect("run_main (on)");
    let on_result = machine_on.signals[1];

    assert_eq!(off_result, Fr::from(42u64), "body computes 2*21");
    assert_eq!(on_result, off_result, "accelerator on/off must agree");
}

/// Builds a single-template program named `component_name`, with the given
/// input/output signal counts, whose body writes a sentinel value (999) to every
/// output signal — so that a test asserting the *accelerator's* outputs landed (not
/// 999) also proves the body was skipped, and a test asserting 999 landed proves the
/// body ran (accelerator not dispatched).
fn sentinel_component_program(
    component_name: &str,
    input_signals: u32,
    output_signals: u32,
) -> CompiledProgram<Fr> {
    let total_signals = 1 + output_signals as usize + input_signals as usize + 1; // + 1 intermediate slot
    let mut instrs = Vec::new();
    for i in 0..output_signals {
        instrs.push(Instr::Mov {
            dst: Dst::Signal(Addr::Const(i)),
            src: Src::Const(0), // constants[0] = 999 (sentinel)
        });
    }
    instrs.push(Instr::Return);
    let template = circom_mpc_vm2::program::TemplateCode {
        instrs,
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 0,
        input_signals,
        output_signals,
        sub_components: 0,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    CompiledProgram {
        templates: vec![template],
        functions: vec![],
        constants: vec![Fr::from(999u64)],
        strings: vec![],
        main: TemplId(0),
        total_signals,
        main_inputs: input_signals as usize,
        main_outputs: output_signals as usize,
        main_input_list: vec![InputInfo {
            name: "in".to_string(),
            offset: 1 + output_signals as usize,
            size: input_signals as usize,
        }],
        output_mapping: HashMap::new(),
        signal_to_witness: (0..total_signals).collect(),
        public_inputs: vec![],
        debug: DebugInfo {
            names: vec![component_name.to_string()],
        },
    }
}

/// (b) Component accelerator: a registered `TestAccel` accelerator (input -> output =
/// 3*input, intermediate = input+100) must have its outputs AND intermediates land in
/// signal RAM at the expected offsets, with the sentinel-writing body skipped entirely.
#[test]
fn component_accelerator_writes_outputs_and_intermediates_body_skipped() {
    let program = sentinel_component_program("TestAccel", 1, 1);

    let mut accel: MpcAccelerator<Fr, PlainDriver<Fr>> = MpcAccelerator::empty();
    accel.register_component(
        "TestAccel",
        |_info: &TemplateInfo| true,
        |driver, args, _amount_outputs| {
            let three = driver.public_from(Fr::from(3u64));
            let hundred = driver.public_from(Fr::from(100u64));
            let output = driver.mul(&args[0], &three)?;
            let intermediate = driver.add(&args[0], &hundred)?;
            Ok(circom_mpc_vm2::accel::ComponentAcceleratorOutput {
                output: vec![output],
                intermediate: vec![intermediate],
            })
        },
    );

    let mut driver = PlainDriver::default();
    let mut machine =
        Machine::new_with_accelerator(&program, &mut driver, VMConfig::default(), &accel)
            .expect("Machine::new_with_accelerator");
    // Signal layout: [0]=1, [1]=out, [2]=in, [3]=intermediate.
    machine.signals[2] = Fr::from(7u64);
    machine.run_main().expect("run_main");

    assert_eq!(
        machine.signals[1],
        Fr::from(21u64),
        "output must be the accelerator's 3*input, not the body's 999 sentinel"
    );
    assert_eq!(
        machine.signals[3],
        Fr::from(107u64),
        "intermediate must be the accelerator's input+100"
    );
}

/// (c) `can_handle` rejection: a `TestAccel` accelerator registered with a predicate
/// that always rejects must fall back to the body's normal execution (the 999
/// sentinel lands, the accelerator's values do not).
#[test]
fn can_handle_rejection_falls_back_to_normal_execution() {
    let program = sentinel_component_program("TestAccel", 1, 1);

    let mut accel: MpcAccelerator<Fr, PlainDriver<Fr>> = MpcAccelerator::empty();
    accel.register_component(
        "TestAccel",
        |_info: &TemplateInfo| false, // never applies
        |driver, args, _amount_outputs| {
            let three = driver.public_from(Fr::from(3u64));
            let output = driver.mul(&args[0], &three)?;
            Ok(circom_mpc_vm2::accel::ComponentAcceleratorOutput {
                output: vec![output],
                intermediate: vec![],
            })
        },
    );

    let mut driver = PlainDriver::default();
    let mut machine =
        Machine::new_with_accelerator(&program, &mut driver, VMConfig::default(), &accel)
            .expect("Machine::new_with_accelerator");
    machine.signals[2] = Fr::from(7u64);
    machine.run_main().expect("run_main");

    assert_eq!(
        machine.signals[1],
        Fr::from(999u64),
        "can_handle always rejects, so the body's sentinel must run"
    );
}

/// (d) Env-config parsing: [`MpcAcceleratorConfig::default`] has every accelerator
/// enabled — a coarser cross-check of the table exercised in detail by `accel.rs`'s own
/// unit tests (`map_env_string_to_bool`/`from_env`).
#[test]
fn default_accelerator_config_enables_everything() {
    let cfg = MpcAcceleratorConfig::default();
    assert!(cfg.sqrt);
    assert!(cfg.num2bits);
    assert!(cfg.addbits);
    assert!(cfg.iszero);
    assert!(cfg.poseidon2);
}

/// Runs three per-party closures concurrently, each handed its own pair of
/// `LocalNetwork`s (mirrors `tests/rep3_driver.rs::run_3_parties`).
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

/// A hand-assembled program with a single template named `"Num2Bits"` (input_signals =
/// 1, output_signals = `bits`) — matched by the default `Num2Bits` accelerator
/// registration ([`MpcAcceleratorConfig::default`]/`from_env` both enable it), so its
/// (never-executed) body can be a bare `Return`.
fn num2bits_program(bits: u32) -> CompiledProgram<Fr> {
    let template = circom_mpc_vm2::program::TemplateCode {
        instrs: vec![Instr::Return],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 1,
        output_signals: bits,
        sub_components: 0,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let total_signals = 1 + bits as usize + 1;
    let mut program = CompiledProgram {
        templates: vec![template],
        functions: vec![],
        constants: vec![],
        strings: vec![],
        main: TemplId(0),
        total_signals,
        main_inputs: 1,
        main_outputs: bits as usize,
        main_input_list: vec![InputInfo {
            name: "in".to_string(),
            offset: 1 + bits as usize,
            size: 1,
        }],
        output_mapping: HashMap::new(),
        signal_to_witness: (0..total_signals).collect(),
        public_inputs: vec![],
        debug: DebugInfo {
            names: vec!["Num2Bits".to_string()],
        },
    };
    program
        .output_mapping
        .insert("out".to_string(), (1, bits as usize));
    program
}

/// The predefined `Num2Bits` component accelerator, exercised end-to-end through
/// [`Rep3WitnessExtension`] over a genuinely shared input: the opened result must equal
/// the plain bit decomposition (LSB first), i.e. [`VmDriver::num2bits`]'s Rep3 port is
/// correct, not just its plain fallback.
#[test]
fn rep3_num2bits_accelerator_matches_plain_expectation() {
    let bits = 4;
    let value = 11u64; // 0b1011 -> LSB-first bits: [1, 1, 0, 1]
    let program = Arc::new(num2bits_program(bits));

    let mut rng = rand::thread_rng();
    let shares = rep3::share_field_elements(&[Fr::from(value)], &mut rng);

    let body = |program: Arc<CompiledProgram<Fr>>, share: Rep3PrimeFieldShare<Fr>| {
        move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Fr> {
            let wex = Rep3WitnessExtension::new_rep3(net0, net1, program, VMConfig::default())
                .expect("new_rep3");
            let finalized = wex
                .run_with_flat(vec![Rep3VmType::Arithmetic(share)], 0)
                .expect("run_with_flat");
            finalized.get_output("out").expect("out")
        }
    };

    let results = run_3_parties(
        body(program.clone(), shares[0][0]),
        body(program.clone(), shares[1][0]),
        body(program, shares[2][0]),
    );

    assert_eq!(results[0], results[1], "party 0/1 must agree");
    assert_eq!(results[1], results[2], "party 1/2 must agree");

    let expected: Vec<Fr> = (0..bits).map(|i| Fr::from((value >> i) & 1)).collect();
    assert_eq!(results[0], expected, "Num2Bits(11), 4 bits, LSB first");
}
