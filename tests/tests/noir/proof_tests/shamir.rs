use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use co_acvm::ShamirAcvmType;
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_builder::TranscriptFieldType;
use co_noir::Bn254G1;
use co_ultrahonk::prelude::{CrsParser, ShamirCoUltraHonk, UltraHonk, Utils, ZeroKnowledge};
use common::transcript::{Poseidon2Sponge, TranscriptHasher};
use mpc_net::local::LocalNetwork;
use sha3::Keccak256;
use std::sync::Arc;

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    num_parties: usize,
    threshold: usize,
    has_zk: ZeroKnowledge,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");
    let witness = Utils::get_witness_from_file(&witness_file).expect("failed to parse witness");

    // Will be trivially shared anyways
    let witness = witness
        .into_iter()
        .map(ShamirAcvmType::from)
        .collect::<Vec<_>>();

    let nets = LocalNetwork::new(num_parties);
    let mut threads = Vec::with_capacity(num_parties);
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system, false).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    for net in nets {
        let witness = witness.clone();
        let prover_crs = prover_crs.clone();
        let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
        threads.push(std::thread::spawn(move || {
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_shamir(
                num_parties,
                threshold,
                &constraint_system,
                witness,
                false,
                &net,
            )
            .unwrap();
            let (proof, public_inputs) = ShamirCoUltraHonk::<_, H, UltraFlavour>::prove(
                &net,
                num_parties,
                threshold,
                pk,
                &prover_crs,
                has_zk,
            )
            .unwrap();
            (proof, public_inputs)
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
    let verifier_crs = CrsParser::<Bn254>::get_crs_g2(CRS_PATH_G2).unwrap();
    let vk =
        co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs, verifier_crs, false).unwrap();

    let is_valid =
        UltraHonk::<_, H, UltraFlavour>::verify(proof, &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("poseidon", 3, 1, ZeroKnowledge::No);
    proof_test::<Poseidon2Sponge>("poseidon", 3, 1, ZeroKnowledge::Yes);
}

#[test]
fn poseidon_proof_test_keccak256() {
    proof_test::<Keccak256>("poseidon", 3, 1, ZeroKnowledge::No);
    proof_test::<Keccak256>("poseidon", 3, 1, ZeroKnowledge::Yes);
}
