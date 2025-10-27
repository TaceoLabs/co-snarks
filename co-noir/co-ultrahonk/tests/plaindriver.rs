use std::fs::File;

use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_acvm::{PlainAcvmSolver, mpc::NoirWitnessExtensionProtocol};
use co_builder::prelude::HonkRecursion;
use co_builder::prelude::constraint_system_from_reader;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::transcript::{Poseidon2Sponge, TranscriptHasher};
use co_noir_common::types::ZeroKnowledge;
use co_ultrahonk::prelude::{CoUltraHonk, PlainCoBuilder, ProvingKey};
use noir_types::HonkProof;
use sha3::Keccak256;
use ultrahonk::prelude::UltraHonk;

fn promote_public_witness_vector<F: PrimeField, T: NoirWitnessExtensionProtocol<F>>(
    witness: Vec<F>,
) -> Vec<T::AcvmType> {
    witness.into_iter().map(|w| T::AcvmType::from(w)).collect()
}

fn plaindriver_test<H: TranscriptHasher<TranscriptFieldType>>(
    proof_file: &str,
    circuit_file: &str,
    witness_file: &str,
    has_zk: ZeroKnowledge,
) {
    const CRS_PATH_G1: &str = "../co-noir-common/src/crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "../co-noir-common/src/crs/bn254_g2.dat";

    let constraint_system =
        constraint_system_from_reader(File::open(circuit_file).unwrap(), true).unwrap();
    let witness = noir_types::witness_from_reader(File::open(witness_file).unwrap()).unwrap();

    let witness = promote_public_witness_vector::<_, PlainAcvmSolver<ark_bn254::Fr>>(witness);
    let mut driver = PlainAcvmSolver::new();
    let builder = PlainCoBuilder::<ark_bn254::G1Projective>::create_circuit(
        &constraint_system,
        false, // We don't support recursive atm
        0,
        witness,
        HonkRecursion::UltraHonk,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) = CrsParser::<ark_bn254::G1Projective>::get_crs::<Bn254>(
        CRS_PATH_G1,
        CRS_PATH_G2,
        crs_size,
        has_zk,
    )
    .unwrap()
    .split();
    let (proving_key, verifying_key) =
        ProvingKey::create_keys(0, builder, &prover_crs, verifier_crs, &mut driver).unwrap();

    let (proof, public_inputs) =
        CoUltraHonk::<PlainUltraHonkDriver, ark_bn254::G1Projective, H>::prove(
            proving_key,
            &prover_crs,
            has_zk,
        )
        .unwrap();

    if has_zk == ZeroKnowledge::No {
        let proof_u8 = proof.to_buffer();
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
        assert_eq!(proof, read_proof);
    }

    let is_valid =
        UltraHonk::<_, H>::verify::<Bn254>(proof, &public_inputs, &verifying_key, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_plaindriver_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";
    plaindriver_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plaindriver_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn poseidon_plaindriver_test_keccak256() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";
    plaindriver_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plaindriver_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn add3_plaindriver_test_keccak256() {
    const PROOF_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.gz";
    plaindriver_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plaindriver_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn add3_plaindriver_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.gz";
    plaindriver_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plaindriver_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}
