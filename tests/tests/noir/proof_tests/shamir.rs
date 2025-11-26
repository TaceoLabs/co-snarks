use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use co_noir::Bn254G1;
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_noir_types::ShamirType;
use co_ultrahonk::prelude::{ShamirCoUltraHonk, UltraHonk};
use mpc_net::local::LocalNetwork;
use noir_types::HonkProof;
use sha3::Keccak256;
use std::{fs::File, sync::Arc};

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    num_parties: usize,
    threshold: usize,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    // Will be trivially shared anyways
    let witness = witness
        .into_iter()
        .map(ShamirType::from)
        .collect::<Vec<_>>();

    let nets = LocalNetwork::new(num_parties);
    let mut threads = Vec::with_capacity(num_parties);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();
    for net in nets {
        let witness = witness.clone();
        let prover_crs = prover_crs.clone();
        let vk = vk.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_shamir(
                num_parties,
                threshold,
                &constraint_system,
                witness,
                &net,
                &prover_crs,
            )
            .unwrap();
            let (proof, public_inputs) = ShamirCoUltraHonk::<_, H>::prove(
                &net,
                num_parties,
                threshold,
                pk,
                &prover_crs,
                has_zk,
                &vk.inner_vk,
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

    if has_zk == ZeroKnowledge::No {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid = UltraHonk::<_, H>::verify(proof, &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    proof_test::<Poseidon2Sponge>("poseidon", 3, 1, ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("poseidon", 3, 1, ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    proof_test::<Keccak256>("poseidon", 3, 1, ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("poseidon", 3, 1, ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    proof_test::<Poseidon2Sponge>("add3u64", 3, 1, ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("add3u64", 3, 1, ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    proof_test::<Keccak256>("add3u64", 3, 1, ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("add3u64", 3, 1, ZeroKnowledge::Yes, PROOF_FILE);
}
