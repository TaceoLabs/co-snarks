//! Regression test for the function-accelerator binding bug: `CodeGen::lower_function`
//! used to populate `FunctionCode::name_id` with the *unmangled* circom function name
//! (e.g. `"sqrt"`), while the predefined `sqrt_0` accelerator registration (and old
//! `circom-mpc-vm::accelerator`'s `FunDecl` keying) is matched against the *mangled*
//! overload symbol (`"sqrt_0"`). The two never matched, so the accelerator silently
//! never bound and the interpreted (Tonelli-Shanks) function body ran instead —
//! mathematically equivalent, so the existing `sqrt_test_kat` KAT test passed either
//! way and never caught the regression. This file asserts both the static fact (the
//! compiled function names are mangled symbols) and the dynamic one (the accelerator
//! actually dispatches for a real compiled program).
mod common;

use ark_bn254::Fr;
use circom_mpc_compiler2::CompilerConfig;
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::driver::VmDriver;
use circom_mpc_vm2::program::VMConfig;
use circom_types::Witness;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// `sqrt_test.circom` calls the single-overload `sqrt` function, which the compiler
/// mangles to a `sqrt_N` symbol (`N` is the overload index circom assigns). The
/// predefined `sqrt_0` accelerator registration is keyed against exactly this mangled
/// form, so it must show up among `FunctionCode::name_id`'s resolved names verbatim —
/// not the unmangled `"sqrt"`.
#[test]
fn sqrt_test_function_names_are_mangled_symbols() {
    let program = common::compile("sqrt_test", CompilerConfig::default());
    let names: Vec<&str> = program
        .functions
        .iter()
        .map(|f| program.debug.names[f.name_id as usize].as_str())
        .collect();
    assert!(
        names.contains(&"sqrt_0"),
        "expected the mangled \"sqrt_0\" symbol among compiled function names (accelerator \
         binding is keyed against the mangled symbol, not the unmangled function name), got {names:?}"
    );
    assert!(
        !names.contains(&"sqrt"),
        "FunctionCode::name_id must hold the mangled symbol, not the unmangled function \
         name; got {names:?}"
    );
}

/// Behavioral proof that the `sqrt_0` accelerator actually binds and dispatches for a
/// compiled `sqrt_test` program (not just that a static name happens to match): the
/// predefined registration is replaced (`register_accelerator_function`'s documented
/// insert-replaces-by-name semantics) with a counting wrapper that delegates to the
/// same `VmDriver::sqrt` port, so the computed witness is unaffected — only the call
/// counter distinguishes "accelerator dispatched" from "interpreted body ran".
#[test]
fn sqrt_accelerator_binds_and_fires_for_compiled_sqrt_test() {
    let program = Arc::new(common::compile("sqrt_test", CompilerConfig::default()));

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let mut wex = PlainWitnessExtension::new_plain(program, VMConfig::default());
    wex.register_accelerator_function("sqrt_0", move |driver, args| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(vec![driver.sqrt(&args[0])?])
    });

    let finalized = wex
        .run_with_flat(vec![Fr::from(4u64)], 0)
        .expect("run_with_flat")
        .into_shared_witness();
    let mut full = finalized.public_inputs;
    full.extend(finalized.witness);

    let should = Witness::<Fr>::from_reader(
        File::open("../../test_vectors/WitnessExtension/kats/sqrt_test/witness0.wtns").unwrap(),
    )
    .unwrap();
    assert_eq!(
        full, should.values,
        "witness must still match ground truth with the counting wrapper installed"
    );

    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "sqrt_0 accelerator wrapper never fired: binding is broken. Before the fix, \
         FunctionCode::name_id held the unmangled \"sqrt\" name, which never matches the \
         mangled \"sqrt_0\" registration key, so the interpreted body silently ran instead \
         of the accelerator."
    );
}
