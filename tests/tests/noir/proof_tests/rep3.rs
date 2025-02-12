use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use acir::native_types::{WitnessMap, WitnessStack};
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_acvm::{solver::Rep3CoSolver, Rep3AcvmType};
use co_ultrahonk::prelude::{
    CrsParser, Poseidon2Sponge, Rep3CoUltraHonk, TranscriptFieldType, TranscriptHasher, UltraHonk,
    Utils,
};
use sha3::Keccak256;
use std::{sync::Arc, thread};
use tests::rep3_network::Rep3TestNetwork;

fn witness_map_to_witness_vector<F: PrimeField>(
    witness_map: WitnessMap<Rep3AcvmType<F>>,
) -> Vec<Rep3AcvmType<F>> {
    let mut wv = Vec::new();
    let mut index = 0;
    for (w, f) in witness_map.into_iter() {
        // ACIR uses a sparse format for WitnessMap where unused witness indices may be left unassigned.
        // To ensure that witnesses sit at the correct indices in the `WitnessVector`, we fill any indices
        // which do not exist within the `WitnessMap` with the dummy value of zero.
        while index < w.0 {
            wv.push(Rep3AcvmType::from(F::zero()));
            index += 1;
        }

        wv.push(f);
        index += 1;
    }
    wv
}

fn convert_witness_rep3<F: PrimeField>(
    mut witness_stack: WitnessStack<Rep3AcvmType<F>>,
) -> Vec<Rep3AcvmType<F>> {
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;
    witness_map_to_witness_vector(witness_map)
}

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(name: &str) {
    let circuit_file = format!("../test_vectors/noir/{}/kat/{}.json", name, name);
    let witness_file = format!("../test_vectors/noir/{}/kat/{}.gz", name, name);
    let has_zk = false;

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");
    let witness = Utils::get_witness_from_file(&witness_file).expect("failed to parse witness");

    // Will be trivially shared anyways
    let witness = witness
        .into_iter()
        .map(Rep3AcvmType::from)
        .collect::<Vec<_>>();

    let test_network = Rep3TestNetwork::default();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
    let crs_size = co_noir::compute_circuit_size::<Bn254>(&constraint_system, false).unwrap();
    let prover_crs = Arc::new(CrsParser::<Bn254>::get_crs_g1(CRS_PATH_G1, crs_size).unwrap());
    for net in test_network.get_party_networks() {
        let witness = witness.clone();
        let prover_crs = prover_crs.clone();
        let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
        threads.push(thread::spawn(move || {
            // generate proving key and vk
            let (pk, net) =
                co_noir::generate_proving_key_rep3(net, &constraint_system, witness, false)
                    .unwrap();
            let (proof, _) = Rep3CoUltraHonk::<_, _, H>::prove(net, pk, &prover_crs).unwrap();
            proof
        }));
    }

    let mut proofs = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    // Get vk
    let verifier_crs = CrsParser::<Bn254>::get_crs_g2(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk(&constraint_system, prover_crs, verifier_crs, false).unwrap();

    let is_valid = UltraHonk::<_, H>::verify(proof, vk, has_zk).unwrap();
    assert!(is_valid);
}

fn witness_and_proof_test<H: TranscriptHasher<TranscriptFieldType>>(name: &str) {
    let circuit_file = format!("../test_vectors/noir/{}/kat/{}.json", name, name);
    let prover_toml = format!("../test_vectors/noir/{}/Prover.toml", name);
    let has_zk = false;

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");

    let test_network = Rep3TestNetwork::default();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
    let crs_size = co_noir::compute_circuit_size::<Bn254>(&constraint_system, false).unwrap();
    let prover_crs = Arc::new(CrsParser::<Bn254>::get_crs_g1(CRS_PATH_G1, crs_size).unwrap());
    for net in test_network.get_party_networks() {
        let prover_crs = prover_crs.clone();
        let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(thread::spawn(move || {
            let solver = Rep3CoSolver::from_network(net, artifact, prover_toml).unwrap();
            let (witness, driver) = solver.solve().unwrap();
            let witness = convert_witness_rep3(witness);
            // generate proving key and vk
            let (pk, net) = co_noir::generate_proving_key_rep3(
                driver.into_network(),
                &constraint_system,
                witness,
                false,
            )
            .unwrap();
            let (proof, _) = Rep3CoUltraHonk::<_, _, H>::prove(net, pk, &prover_crs).unwrap();
            proof
        }));
    }

    let mut proofs = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    // Get vk
    let verifier_crs = CrsParser::<Bn254>::get_crs_g2(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk(&constraint_system, prover_crs, verifier_crs, false).unwrap();

    let is_valid = UltraHonk::<_, H>::verify(proof, vk, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("poseidon");
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("poseidon");
}

#[test]
fn poseidon_witness_and_proof_test_keccak256() {
    witness_and_proof_test::<Keccak256>("poseidon");
}

#[test]
fn poseidon_proof_test_keccak256() {
    proof_test::<Keccak256>("poseidon");
}
