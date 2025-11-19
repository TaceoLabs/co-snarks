use crate::proof_tests::CRS_PATH_G1;
use crate::proof_tests::CRS_PATH_G2;
use ark_bn254::Bn254;
use co_acvm::PlainAcvmSolver;
use co_builder::prelude::constraint_system_from_reader;
use co_builder::prelude::HonkRecursion;
use co_builder::prelude::UltraCircuitBuilder;
use co_noir::UltraHonk;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::transcript::{Poseidon2Sponge, TranscriptHasher};
use co_noir_common::types::ZeroKnowledge;
use noir_types::HonkProof;
use sha3::Keccak256;
use std::fs::File;

fn plain_test<H: TranscriptHasher<TranscriptFieldType>>(
    proof_file: &str,
    circuit_file: &str,
    witness_file: &str,
    has_zk: ZeroKnowledge,
) {
    let constraint_system =
        constraint_system_from_reader(File::open(circuit_file).unwrap()).unwrap();
    let witness = noir_types::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let mut driver = PlainAcvmSolver::new();

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
    let builder = UltraCircuitBuilder::<
        <ark_ec::models::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1,
    >::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &recursion_crs,
        &mut driver,
    )
    .unwrap();
    let crs_size = builder.compute_dyadic_size();
    let crs =
        CrsParser::<<ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1>::get_crs::<Bn254>(
            CRS_PATH_G1,
            CRS_PATH_G2,
            crs_size,
            has_zk,
        )
        .unwrap();
    let (prover_crs, verifier_crs) = crs.split();

    let (proving_key, verifying_key) = builder
        .create_keys::<Bn254>(prover_crs.into(), verifier_crs, &mut driver)
        .unwrap();

    let (proof, public_inputs) =
        UltraHonk::<_, H>::prove(proving_key, has_zk, &verifying_key.inner_vk).unwrap();
    if has_zk == ZeroKnowledge::No {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid =
        UltraHonk::<_, H>::verify(proof, &public_inputs, &verifying_key, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    const CIRCUIT_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.gz";

    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn poseidon_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    const CIRCUIT_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.gz";

    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn add3_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    const CIRCUIT_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64.json";
    const WITNESS_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64.gz";

    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn add3_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    const CIRCUIT_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64.json";
    const WITNESS_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64.gz";

    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}
