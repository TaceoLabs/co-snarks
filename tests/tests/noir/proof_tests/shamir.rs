use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use co_acvm::{PlainAcvmSolver, ShamirAcvmSolver, ShamirAcvmType};
use co_ultrahonk::prelude::{
    CoUltraHonk, Poseidon2Sponge, ProvingKey, ShamirCoBuilder, ShamirUltraHonkDriver,
    TranscriptFieldType, TranscriptHasher, UltraCircuitBuilder, UltraHonk, Utils, VerifyingKey,
};
use mpc_core::protocols::shamir::{ShamirPreprocessing, ShamirProtocol};
use sha3::Keccak256;
use std::thread;
use tests::shamir_network::{PartyTestNetwork, ShamirTestNetwork};

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    num_parties: usize,
    threshold: usize,
) {
    let circuit_file = format!("../test_vectors/noir/{}/kat/{}.json", name, name);
    let witness_file = format!("../test_vectors/noir/{}/kat/{}.gz", name, name);

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
    for net in test_network.get_party_networks() {
        let artifact = program_artifact.clone();
        let witness = witness.clone();
        threads.push(thread::spawn(move || {
            let constraint_system = Utils::get_constraint_system_from_artifact(&artifact, true);

            let id = net.id;
            let preprocessing = ShamirPreprocessing::new(threshold, net, 0).unwrap();
            let protocol = ShamirProtocol::from(preprocessing);
            let mut driver = ShamirAcvmSolver::new(protocol);

            let builder = ShamirCoBuilder::<Bn254, PartyTestNetwork>::create_circuit(
                constraint_system,
                false, // We don't support recursive atm
                0,
                witness,
                true,
                false,
                &mut driver,
            )
            .unwrap();

            let prover_crs =
                ProvingKey::<ShamirUltraHonkDriver<_, PartyTestNetwork>, _>::get_prover_crs(
                    &builder,
                    CRS_PATH_G1,
                )
                .expect("failed to get prover crs");

            let proving_key = ProvingKey::create(id, builder, prover_crs, &mut driver).unwrap();

            let net = driver.into_network();
            let num_pairs = if num_parties == 3 {
                0 // Precomputation is done on the fly since it requires no comminication
            } else {
                proving_key.ultrahonk_num_randomness()
            };
            let preprocessing = ShamirPreprocessing::new(threshold, net, num_pairs).unwrap();
            let mut io_context0 = ShamirProtocol::from(preprocessing);
            let io_context1 = io_context0.fork_with_pairs(0).unwrap();
            let driver = ShamirUltraHonkDriver::new(io_context0, io_context1);

            let prover = CoUltraHonk::<_, _, H>::new(driver);
            prover.prove(proving_key).unwrap()
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
    let mut driver = PlainAcvmSolver::new();
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);
    let builder = UltraCircuitBuilder::<Bn254>::create_circuit(
        constraint_system,
        false, // We don't support recursive atm
        0,
        vec![],
        true,
        false,
        &mut driver,
    )
    .unwrap();
    let crs = VerifyingKey::get_crs(&builder, CRS_PATH_G1, CRS_PATH_G2).unwrap();
    let verifying_key = VerifyingKey::create(builder, crs, &mut driver).unwrap();

    let is_valid = UltraHonk::<_, H>::verify(proof, verifying_key).unwrap();
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
