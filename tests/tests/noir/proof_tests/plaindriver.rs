use std::fs::File;

use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use acir::native_types::{WitnessMap, WitnessStack};
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_acvm::{solver::PlainCoSolver, PlainAcvmSolver};
use co_builder::prelude::HonkRecursion;
use co_builder::{keys::proving_key::ProvingKeyTrait, prelude::UltraCircuitBuilder};
use co_noir::{Bn254G1, HonkProof};
use co_noir_common::{
    crs::{parse::CrsParser, ProverCrs},
    honk_proof::TranscriptFieldType,
    keys::proving_key::ProvingKey,
    mpc::plain::PlainUltraHonkDriver,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_ultrahonk::prelude::{CoUltraHonk, UltraHonk};
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

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let constraint_system =
        co_noir::constraint_system_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse constraint system");
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    let mut driver = PlainAcvmSolver::new();
    //TODO FLORIN Streamline this
    let recursion_crs_size = constraint_system.get_honk_recursion_public_inputs_size();
    let recursion_crs = if recursion_crs_size > 0 {
        CrsParser::<<ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1>::get_crs_g1(
                CRS_PATH_G1,
                recursion_crs_size,
                has_zk,
            )
            .unwrap()
    } else {
        ProverCrs::default()
    };
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &recursion_crs,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) = CrsParser::<
        <ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1,
    >::get_crs::<Bn254>(
        CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk
    )
    .expect("failed to get crs")
    .split();
    let (proving_key, verifying_key) =
        ProvingKey::create_keys(0, builder, &prover_crs, verifier_crs, &mut driver).unwrap();

    let (proof, public_input) = CoUltraHonk::<PlainUltraHonkDriver, _, H>::prove(
        proving_key,
        &prover_crs,
        has_zk,
        &verifying_key.inner_vk,
    )
    .unwrap();

    if has_zk == ZeroKnowledge::No && name != "recursion" {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid =
        UltraHonk::<_, H>::verify::<Bn254>(proof, &public_input, &verifying_key, has_zk).unwrap();
    assert!(is_valid);
}

fn witness_and_proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);

    let solver = PlainCoSolver::init_plain_driver(program_artifact, prover_toml).unwrap();
    let witness = solver.solve().unwrap();
    let witness = convert_witness_plain(witness);

    let mut driver = PlainAcvmSolver::new();
    //TODO FLORIN Streamline this
    let recursion_crs_size = constraint_system.get_honk_recursion_public_inputs_size();
    let recursion_crs = if recursion_crs_size > 0 {
        CrsParser::<<ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1>::get_crs_g1(
                CRS_PATH_G1,
                recursion_crs_size,
                has_zk,
            )
            .unwrap()
    } else {
        ProverCrs::default()
    };
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &recursion_crs,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) = CrsParser::<
        <ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1,
    >::get_crs::<Bn254>(
        CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk
    )
    .expect("failed to get crs")
    .split();
    let (proving_key, verifying_key) =
        ProvingKey::create_keys(0, builder, &prover_crs, verifier_crs, &mut driver).unwrap();

    let (proof, public_input) = CoUltraHonk::<PlainUltraHonkDriver, _, H>::prove(
        proving_key,
        &prover_crs,
        has_zk,
        &verifying_key.inner_vk,
    )
    .unwrap();

    if has_zk == ZeroKnowledge::No && name != "recursion" {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid =
        UltraHonk::<_, H>::verify::<Bn254>(proof, &public_input, &verifying_key, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_witness_and_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_witness_and_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    witness_and_proof_test::<Keccak256>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    proof_test::<Keccak256>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}

#[test]
fn recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}
