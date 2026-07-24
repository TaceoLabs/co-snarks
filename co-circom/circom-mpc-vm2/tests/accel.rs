//! Accelerator tests: function/component registration, construction-time binding
//! (`can_handle`), and the pre-defined `Num2Bits` registration exercised end-to-end
//! through the Rep3 driver.
mod common;

use ark_bn254::Fr;
use circom_mpc_vm2::accel::{
    ComponentAcceleratorOutput, MpcAccelerator, MpcAcceleratorConfig, TemplateInfo,
};
use circom_mpc_vm2::api::{PlainWitnessExtension, Rep3WitnessExtension};
use circom_mpc_vm2::driver::VmDriver;
use circom_mpc_vm2::drivers::plain::PlainDriver;
use circom_mpc_vm2::drivers::rep3::Rep3VmType;
use circom_mpc_vm2::exec::Machine;
use circom_mpc_vm2::isa::*;
use circom_mpc_vm2::program::{CompiledProgram, DebugInfo, FunctionCode, InputInfo, VMConfig};
use mpc_core::gadgets::poseidon2::Poseidon2;
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
        intermediate_signals: 1,
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

#[test]
fn component_accelerator_rejects_wrong_intermediate_count() {
    let program = Arc::new(sentinel_component_program("Custom", 1, 1));
    let mut witness_extension = PlainWitnessExtension::new_plain(program, VMConfig::default());
    witness_extension.register_accelerator_component(
        "Custom",
        |_| true,
        |driver, _args, _outputs| {
            Ok(ComponentAcceleratorOutput {
                output: vec![driver.public_zero()],
                intermediate: vec![driver.public_zero(), driver.public_zero()],
            })
        },
    );

    let error = witness_extension
        .run_with_flat(vec![Fr::from(1u64)], 0)
        .err()
        .expect("wrong intermediate count must be rejected");
    assert!(
        error
            .to_string()
            .contains("returned 2 intermediate signal(s), but the template has only 1 slot(s)"),
        "{error:?}"
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
        intermediate_signals: 0,
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

/// Like [`sentinel_component_program`], but with a caller-chosen number of
/// intermediate signal slots after the inputs, instead of a hardcoded `+ 1` — the
/// `Poseidon2` accelerator's intermediate (round-trace) length isn't a small constant
/// shared with the other predefined accelerators, so it must be sized to whatever the
/// driver port actually produces.
fn sentinel_component_program_with_intermediate(
    component_name: &str,
    input_signals: u32,
    output_signals: u32,
    intermediate_signals: usize,
) -> CompiledProgram<Fr> {
    let total_signals = 1 + output_signals as usize + input_signals as usize + intermediate_signals;
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
        intermediate_signals: u32::try_from(intermediate_signals).unwrap(),
        sub_components: 0,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let mut program = CompiledProgram {
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
    };
    program
        .output_mapping
        .insert("out".to_string(), (1, output_signals as usize));
    program
}

/// Runs [`VmDriver::poseidon2_accelerator`] directly (on a throwaway all-zero input)
/// purely to learn the round-trace length it produces for a given state size `T` —
/// needed to size [`sentinel_component_program_with_intermediate`]'s intermediate
/// slots correctly, since that length isn't a small constant shared across `T`.
fn poseidon2_trace_len<const T: usize>() -> usize {
    let mut driver = PlainDriver::<Fr>::default();
    let inputs = vec![Fr::from(0u64); T];
    let (_, trace) = VmDriver::poseidon2_accelerator::<T>(&mut driver, &inputs)
        .expect("plain poseidon2_accelerator");
    trace.len()
}

/// (e) `Poseidon2` accelerator, state size 2: the plain driver port
/// ([`VmDriver::poseidon2_accelerator`]) must agree with calling
/// `mpc_core::gadgets::poseidon2::Poseidon2::permutation` directly (cross-validating
/// the port against the raw gadget, independent of any VM/accelerator plumbing), AND
/// the predefined `Poseidon2` component accelerator must actually dispatch for a
/// template literally named `"Poseidon2"` — proven by its sentinel body never running
/// (see [`sentinel_component_program_with_intermediate`]'s doc comment on that
/// pattern).
#[test]
fn poseidon2_accelerator_matches_direct_gadget_and_dispatches() {
    const T: usize = 2;
    let inputs = [Fr::from(3u64), Fr::from(5u64)];

    let (direct_state, direct_trace) = {
        let mut driver = PlainDriver::<Fr>::default();
        VmDriver::poseidon2_accelerator::<T>(&mut driver, &inputs)
            .expect("plain poseidon2_accelerator")
    };
    let expected = Poseidon2::<Fr, T, 5>::default().permutation(&inputs);
    assert_eq!(
        direct_state, expected,
        "the plain driver's poseidon2_accelerator port must match the raw gadget's \
         permutation output"
    );

    let program = sentinel_component_program_with_intermediate(
        "Poseidon2",
        T as u32,
        T as u32,
        direct_trace.len(),
    );
    let accel: MpcAccelerator<Fr, PlainDriver<Fr>> =
        MpcAccelerator::from_config(MpcAcceleratorConfig::default());
    let mut driver = PlainDriver::default();
    let mut machine =
        Machine::new_with_accelerator(&program, &mut driver, VMConfig::default(), &accel)
            .expect("Machine::new_with_accelerator");
    machine.signals[3] = inputs[0];
    machine.signals[4] = inputs[1];
    machine.run_main().expect("run_main");

    assert_eq!(
        machine.signals[1..3],
        expected,
        "output must be the accelerator's Poseidon2 permutation, not the body's 999 sentinel"
    );
    assert_eq!(
        machine.signals[5..5 + direct_trace.len()],
        direct_trace,
        "intermediate (round trace) signals must match the direct gadget computation"
    );
}

/// (f) `Poseidon2` accelerator over Rep3: the same state-size-2 permutation, run
/// through [`Rep3WitnessExtension`] with the *default* registry over genuinely shared
/// inputs — the opened output must equal the plain/direct gadget computation, proving
/// the Rep3 driver port (`precompute_rep3` +
/// `rep3_permutation_in_place_with_precomputation_intermediate`) is correct, not just
/// its all-public fast path.
#[test]
fn rep3_poseidon2_accelerator_matches_plain_expectation() {
    const T: usize = 2;
    let raw_inputs = [3u64, 5u64];
    let trace_len = poseidon2_trace_len::<T>();
    let expected = Poseidon2::<Fr, T, 5>::default()
        .permutation(&[Fr::from(raw_inputs[0]), Fr::from(raw_inputs[1])]);

    let program = Arc::new(sentinel_component_program_with_intermediate(
        "Poseidon2",
        T as u32,
        T as u32,
        trace_len,
    ));

    let mut rng = rand::thread_rng();
    let shares = rep3::share_field_elements(
        &[Fr::from(raw_inputs[0]), Fr::from(raw_inputs[1])],
        &mut rng,
    );

    let body = |program: Arc<CompiledProgram<Fr>>, share: Vec<Rep3PrimeFieldShare<Fr>>| {
        move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Fr> {
            let wex = Rep3WitnessExtension::new_rep3(net0, net1, program, VMConfig::default())
                .expect("new_rep3");
            let inputs: Vec<Rep3VmType<Fr>> =
                share.into_iter().map(Rep3VmType::Arithmetic).collect();
            let finalized = wex.run_with_flat(inputs, 0).expect("run_with_flat");
            finalized.get_output("out").expect("out")
        }
    };

    let results = run_3_parties(
        body(program.clone(), shares[0].clone()),
        body(program.clone(), shares[1].clone()),
        body(program, shares[2].clone()),
    );

    assert_eq!(results[0], results[1], "party 0/1 must agree");
    assert_eq!(results[1], results[2], "party 1/2 must agree");
    assert_eq!(
        results[0],
        expected.to_vec(),
        "Rep3-opened Poseidon2 output must match the direct gadget computation"
    );
}

/// A hand-assembled program with a single template named `"AddBits"` (input_signals =
/// `2 * bitlen`: the `a` bits followed by the `b` bits, both MSB-first per
/// [`VmDriver::addbits`]'s convention; output_signals = `bitlen`) — matched by the
/// default `AddBits` accelerator registration.
fn addbits_program(bitlen: u32) -> CompiledProgram<Fr> {
    let template = circom_mpc_vm2::program::TemplateCode {
        instrs: vec![Instr::Return],
        num_field_regs: 0,
        num_int_regs: 0,
        num_vars: 0,
        input_signals: 2 * bitlen,
        output_signals: bitlen,
        intermediate_signals: 1,
        sub_components: 0,
        mappings: vec![],
        name_id: 0,
        symbol_id: 0,
    };
    let total_signals = 1 + bitlen as usize + (2 * bitlen) as usize + 1; // +1 for the carry intermediate
    let mut program = CompiledProgram {
        templates: vec![template],
        functions: vec![],
        constants: vec![],
        strings: vec![],
        main: TemplId(0),
        total_signals,
        main_inputs: (2 * bitlen) as usize,
        main_outputs: bitlen as usize,
        main_input_list: vec![InputInfo {
            name: "in".to_string(),
            offset: 1 + bitlen as usize,
            size: (2 * bitlen) as usize,
        }],
        output_mapping: HashMap::new(),
        signal_to_witness: (0..total_signals).collect(),
        public_inputs: vec![],
        debug: DebugInfo {
            names: vec!["AddBits".to_string()],
        },
    };
    program
        .output_mapping
        .insert("out".to_string(), (1, bitlen as usize));
    program
}

/// (g) `AddBits` accelerator over Rep3: `13 + 5 = 18`, which overflows 4 bits
/// (`18 mod 16 = 2`, carry = `1`) — exercised through [`Rep3WitnessExtension`] with the
/// *default* registry over genuinely shared bit inputs; the opened result must equal
/// the plain MSB-first bit decomposition of the (wrapped) sum, proving the Rep3
/// `addbits` port (promote-and-sum + `a2b_selector` + `bit_inject_many`) is correct.
#[test]
fn rep3_addbits_accelerator_matches_plain_expectation() {
    let bitlen = 4u32;
    let a_bits = [1u64, 1, 0, 1]; // MSB-first: 1101b = 13
    let b_bits = [0u64, 1, 0, 1]; // MSB-first: 0101b = 5
    let sum = 13u64 + 5u64; // 18 = 0b10010

    let program = Arc::new(addbits_program(bitlen));

    let all_bits: Vec<Fr> = a_bits
        .iter()
        .chain(b_bits.iter())
        .map(|&b| Fr::from(b))
        .collect();
    let mut rng = rand::thread_rng();
    let shares = rep3::share_field_elements(&all_bits, &mut rng);

    let body = |program: Arc<CompiledProgram<Fr>>, share: Vec<Rep3PrimeFieldShare<Fr>>| {
        move |net0: &LocalNetwork, net1: &LocalNetwork| -> Vec<Fr> {
            let wex = Rep3WitnessExtension::new_rep3(net0, net1, program, VMConfig::default())
                .expect("new_rep3");
            let inputs: Vec<Rep3VmType<Fr>> =
                share.into_iter().map(Rep3VmType::Arithmetic).collect();
            let finalized = wex.run_with_flat(inputs, 0).expect("run_with_flat");
            finalized.get_output("out").expect("out")
        }
    };

    let results = run_3_parties(
        body(program.clone(), shares[0].clone()),
        body(program.clone(), shares[1].clone()),
        body(program, shares[2].clone()),
    );

    assert_eq!(results[0], results[1], "party 0/1 must agree");
    assert_eq!(results[1], results[2], "party 1/2 must agree");

    let expected: Vec<Fr> = (0..bitlen)
        .rev()
        .map(|i| Fr::from((sum >> i) & 1))
        .collect();
    assert_eq!(
        results[0], expected,
        "AddBits(13, 5), 4 bits, MSB first, wraps mod 16"
    );
}

/// Builds a program calling a zero-argument function `"multi_0"` whose (never
/// executed — the accelerator always intercepts it here) body just returns its own
/// `vars[0]`, with `ret_n` the callsite's arity and `out_count` output signals each
/// `Mov`'d from the corresponding return register.
///
/// Signal layout: `[0]=1`, `[1..1+out_count]` = outputs.
fn multi_return_program(ret_n: u32, out_count: u32) -> CompiledProgram<Fr> {
    let f = FunctionCode {
        instrs: vec![Instr::Ret {
            src: RetSrc::Reg(0),
            n: 1,
        }],
        num_field_regs: 1,
        num_int_regs: 0,
        num_vars: 1,
        num_params: 0,
        name_id: 1,
    };
    let num_regs = ret_n.max(out_count) as u16;
    let mut instrs = vec![Instr::CallFn {
        fn_id: FnId(0),
        args_start: 0,
        args_n: 0,
        ret: 0,
        ret_n,
    }];
    for i in 0..out_count {
        instrs.push(Instr::Mov {
            dst: Dst::Signal(Addr::Const(i)),
            src: Src::Reg(i as u16),
        });
    }
    instrs.push(Instr::Return);
    common::program_with_functions(
        instrs,
        num_regs,
        0,
        0,
        0,
        out_count,
        1 + out_count as usize,
        vec![f],
        vec!["multi_0"],
    )
}

/// (h) Multi-value function accelerator return, exact arity: a `multi_0` accelerator
/// returning 3 values, called with `ret_n = 3`, must land all 3 in the caller's output
/// signals — the spec obligation old-VM never met (it asserted `result.len() == 1`
/// and only supported single-return accelerators).
#[test]
fn multi_value_function_accelerator_returns_all_values() {
    let program = multi_return_program(3, 3);
    let mut accel: MpcAccelerator<Fr, PlainDriver<Fr>> = MpcAccelerator::empty();
    accel.register_function("multi_0", |driver, _args| {
        Ok(vec![
            driver.public_from(Fr::from(10u64)),
            driver.public_from(Fr::from(20u64)),
            driver.public_from(Fr::from(30u64)),
        ])
    });
    let mut driver = PlainDriver::default();
    let mut machine =
        Machine::new_with_accelerator(&program, &mut driver, VMConfig::default(), &accel)
            .expect("Machine::new_with_accelerator");
    machine.run_main().expect("run_main");

    assert_eq!(
        machine.signals[1..4],
        [Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)],
        "all 3 accelerator return values must land in the output signals"
    );
}

/// (i) Multi-value function accelerator return, callsite wants more than the
/// accelerator produced: a `multi_0` accelerator returning 3 values, called with
/// `ret_n = 4`, must zero-pad the 4th — the same callsite-arity `resize_ret` boundary
/// applied to a normal (non-accelerated) function return.
#[test]
fn multi_value_function_accelerator_zero_pads_when_callsite_wants_more() {
    let program = multi_return_program(4, 4);
    let mut accel: MpcAccelerator<Fr, PlainDriver<Fr>> = MpcAccelerator::empty();
    accel.register_function("multi_0", |driver, _args| {
        Ok(vec![
            driver.public_from(Fr::from(10u64)),
            driver.public_from(Fr::from(20u64)),
            driver.public_from(Fr::from(30u64)),
        ])
    });
    let mut driver = PlainDriver::default();
    let mut machine =
        Machine::new_with_accelerator(&program, &mut driver, VMConfig::default(), &accel)
            .expect("Machine::new_with_accelerator");
    machine.run_main().expect("run_main");

    assert_eq!(
        machine.signals[1..5],
        [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(0u64)
        ],
        "callsite ret_n=4 must zero-pad the accelerator's 3rd-index-and-beyond shortfall"
    );
}
