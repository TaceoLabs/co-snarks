use std::{path::PathBuf, thread};

use acir::{native_types::WitnessStack, FieldElement};

use ark_bn254::Bn254;
use co_acvm::solver::{PlainCoSolver, Rep3CoSolver};
use mpc_net::test::TestNetwork;
use noirc_artifacts::program::ProgramArtifact;
use tests::test_utils;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_line_number(false)
        .with_timer(());
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    install_tracing();
    let root = std::env!("CARGO_MANIFEST_DIR");
    println!("{root}");
    let test_case = "quantized";

    let program = std::fs::read_to_string(format!(
        "{root}/../test_vectors/noir/{test_case}/kat/{test_case}.json",
    ))
    .unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");

    let should_witness = std::fs::read(format!(
        "{root}/../test_vectors/noir/{test_case}/kat/{test_case}.gz",
    ))
    .unwrap();

    let should_witness = WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
    let input = PathBuf::from(format!(
        "{root}/../test_vectors/noir/{test_case}/Prover.toml",
    ));
    // read the input file
    let inputs = Rep3CoSolver::<_, ()>::partially_read_abi_bn254_fieldelement(
        &input,
        &program_artifact.abi,
        &program_artifact.bytecode,
    )?;

    // create input shares
    let mut rng = rand::thread_rng();
    let shares = test_utils::share_input_rep3::<Bn254, _>(inputs, &mut rng);
    let nets0 = TestNetwork::new_3_parties();
    let nets1 = TestNetwork::new_3_parties();
    let mut threads = vec![];
    for (net0, net1, program_artifact, share) in itertools::izip!(
        nets0,
        nets1,
        [
            program_artifact.clone(),
            program_artifact.clone(),
            program_artifact
        ],
        shares
    ) {
        threads.push(thread::spawn(move || {
            let input_share =
                test_utils::translate_witness_share_rep3(share, &program_artifact.abi);
            let solver =
                Rep3CoSolver::new_with_witness(&net0, &net1, program_artifact, input_share)
                    .unwrap();
            solver.solve().unwrap()
        }));
    }

    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    let is_witness = test_utils::combine_field_elements_for_acvm(result1, result2, result3);
    let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
    assert_eq!(should_witness, is_witness);
    Ok(())
}
