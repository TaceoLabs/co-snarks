use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use co_acvm::ShamirAcvmType;
use co_ultrahonk::prelude::{
    CrsParser, Poseidon2Sponge, ShamirCoUltraHonk, TranscriptFieldType, TranscriptHasher,
    UltraHonk, Utils, ZeroKnowledge,
};
use sha3::Keccak256;
use std::{sync::Arc, thread};
use tests::shamir_network::ShamirTestNetwork;

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    num_parties: usize,
    threshold: usize,
) {
    let circuit_file = format!("../test_vectors/noir/{}/kat/{}.json", name, name);
    let witness_file = format!("../test_vectors/noir/{}/kat/{}.gz", name, name);
    let has_zk = ZeroKnowledge::No;

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");
    let witness = Utils::get_witness_from_file(&witness_file).expect("failed to parse witness");

    // Will be trivially shared anyways
    let witness = witness
        .into_iter()
        .map(ShamirAcvmType::from)
        .collect::<Vec<_>>();

    let test_network = ShamirTestNetwork::new(num_parties);
    let mut threads = Vec::with_capacity(num_parties);
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
    let crs_size = co_noir::compute_circuit_size::<Bn254>(&constraint_system, false).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    for net in test_network.get_party_networks() {
        let witness = witness.clone();
        let prover_crs = prover_crs.clone();
        let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
        threads.push(thread::spawn(move || {
            // generate proving key and vk
            let (pk, net) = co_noir::generate_proving_key_shamir(
                net,
                threshold,
                &constraint_system,
                witness,
                false,
            )
            .unwrap();
            let (proof, _) =
                ShamirCoUltraHonk::<_, _, H>::prove(net, threshold, pk, &prover_crs, has_zk)
                    .unwrap();
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
fn poseidon_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("poseidon", 3, 1);
}

#[test]
fn poseidon_proof_test_keccak256() {
    proof_test::<Keccak256>("poseidon", 3, 1);
}
