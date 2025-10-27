use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use co_acvm::solver::Rep3CoSolver;
use co_noir::Bn254G1;
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_noir_types::Rep3Type;
use co_ultrahonk::prelude::{Rep3CoUltraHonk, UltraHonk};
use mpc_net::local::LocalNetwork;
use sha3::Keccak256;
use std::{fs::File, sync::Arc};

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(name: &str, has_zk: ZeroKnowledge) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    // Will be trivially shared anyways
    let witness = witness.into_iter().map(Rep3Type::from).collect::<Vec<_>>();

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact, true);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system, false).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g1(
            CRS_PATH_G1,
            crs_size,
            has_zk,
        )
        .unwrap(),
    );
    for (net0, net1) in nets0.into_iter().zip(nets1) {
        let witness = witness.clone();
        let prover_crs = prover_crs.clone();
        let constraint_system =
            co_noir::get_constraint_system_from_artifact(&program_artifact, true);
        threads.push(std::thread::spawn(move || {
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                false,
                &net0,
                &net1,
            )
            .unwrap();
            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net0, pk, &prover_crs, has_zk).unwrap();
            (proof, public_input)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    // Get vk
    let verifier_crs =
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g2::<
            Bn254,
        >(CRS_PATH_G2)
        .unwrap();
    let vk =
        co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs, verifier_crs, false).unwrap();

    let is_valid = UltraHonk::<_, H>::verify(proof, &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);
}

fn witness_and_proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact, true);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system, false).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g1(
            CRS_PATH_G1,
            crs_size,
            has_zk,
        )
        .unwrap(),
    );
    for (net0, net1) in nets0.into_iter().zip(nets1) {
        let prover_crs = prover_crs.clone();
        let constraint_system =
            co_noir::get_constraint_system_from_artifact(&program_artifact, true);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = Rep3CoSolver::new(&net0, &net1, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                false,
                &net0,
                &net1,
            )
            .unwrap();
            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net0, pk, &prover_crs, has_zk).unwrap();
            (proof, public_input)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    // Get vk
    let verifier_crs =
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g2::<
            Bn254,
        >(CRS_PATH_G2)
        .unwrap();
    let vk =
        co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs, verifier_crs, false).unwrap();

    let is_valid = UltraHonk::<_, H>::verify(proof, &public_input, &vk, has_zk).unwrap();
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
