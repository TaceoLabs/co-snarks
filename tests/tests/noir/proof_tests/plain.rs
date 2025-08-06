use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use acir::native_types::{WitnessMap, WitnessStack};
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_acvm::{solver::PlainCoSolver, PlainAcvmSolver};
use co_builder::{flavours::ultra_flavour::UltraFlavour, TranscriptFieldType};
use co_noir::{Bn254G1, HonkRecursion};
use co_ultrahonk::prelude::{
    CoUltraHonk, CrsParser, PlainCoBuilder, ProvingKey, UltraHonk, Utils, ZeroKnowledge,
};
use common::{
    mpc::plain::PlainUltraHonkDriver,
    transcript::{Poseidon2Sponge, TranscriptHasher},
};
use sha3::Keccak256;

fn witness_map_to_witness_vector<F: PrimeField>(witness_map: WitnessMap<F>) -> Vec<F> {
    let mut wv = Vec::new();
    let mut index = 0;
    for (w, f) in witness_map.into_iter() {
        // ACIR uses a sparse format for WitnessMap where unused witness indices may be left unassigned.
        // To ensure that witnesses sit at the correct indices in the `WitnessVector`, we fill any indices
        // which do not exist within the `WitnessMap` with the dummy value of zero.
        while index < w.0 {
            wv.push(F::zero());
            index += 1;
        }
        wv.push(f);
        index += 1;
    }
    wv
}

fn convert_witness_plain<F: PrimeField>(mut witness_stack: WitnessStack<F>) -> Vec<F> {
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;
    witness_map_to_witness_vector(witness_map)
}

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(name: &str, has_zk: ZeroKnowledge) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let constraint_system = Utils::get_constraint_system_from_file(&circuit_file, true)
        .expect("failed to parse program artifact");
    let witness = Utils::get_witness_from_file(&witness_file).expect("failed to parse witness");

    let mut driver = PlainAcvmSolver::new();
    let builder = PlainCoBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        false, // We don't support recursive atm
        0,
        witness,
        HonkRecursion::UltraHonk,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) =
        CrsParser::<Bn254>::get_crs(CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk)
            .expect("failed to get crs")
            .split();
    let (proving_key, verifying_key) =
        ProvingKey::create_keys(0, builder, &prover_crs, verifier_crs, &mut driver).unwrap();

    let (proof, public_input) = CoUltraHonk::<PlainUltraHonkDriver, _, H, UltraFlavour>::prove(
        proving_key,
        &prover_crs,
        has_zk,
    )
    .unwrap();

    let is_valid = UltraHonk::<_, H, UltraFlavour>::verify::<Bn254>(
        proof,
        &public_input,
        &verifying_key,
        has_zk,
    )
    .unwrap();
    assert!(is_valid);
}

fn witness_and_proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);

    let solver = PlainCoSolver::init_plain_driver(program_artifact, prover_toml).unwrap();
    let witness = solver.solve().unwrap();
    let witness = convert_witness_plain(witness);

    let mut driver = PlainAcvmSolver::new();
    let builder = PlainCoBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        false, // We don't support recursive atm
        0,
        witness,
        HonkRecursion::UltraHonk,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) =
        CrsParser::<Bn254>::get_crs(CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk)
            .expect("failed to get crs")
            .split();
    let (proving_key, verifying_key) =
        ProvingKey::create_keys(0, builder, &prover_crs, verifier_crs, &mut driver).unwrap();

    let (proof, public_input) = CoUltraHonk::<PlainUltraHonkDriver, _, H, UltraFlavour>::prove(
        proving_key,
        &prover_crs,
        has_zk,
    )
    .unwrap();

    let is_valid = UltraHonk::<_, H, UltraFlavour>::verify::<Bn254>(
        proof,
        &public_input,
        &verifying_key,
        has_zk,
    )
    .unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No);
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes);
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No);
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes);
}

#[test]
fn poseidon_witness_and_proof_test_keccak256() {
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::No);
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes);
}

#[test]
fn poseidon_proof_test_keccak256() {
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::No);
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes);
}
