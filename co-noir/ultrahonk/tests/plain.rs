use std::fs::File;

use ark_bn254::Bn254;
use co_builder::TranscriptFieldType;
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_builder::prelude::CrsParser;
use co_builder::prelude::HonkRecursion;
use co_builder::prelude::ZeroKnowledge;
use co_builder::prelude::constraint_system_from_reader;
use common::HonkProof;
use common::transcript::{Poseidon2Sponge, TranscriptHasher};
use sha3::Keccak256;
use ultrahonk::prelude::{PlainAcvmSolver, UltraCircuitBuilder, UltraHonk};

fn plain_test<H: TranscriptHasher<TranscriptFieldType>>(
    proof_file: &str,
    circuit_file: &str,
    witness_file: &str,
    has_zk: ZeroKnowledge,
) {
    const CRS_PATH_G1: &str = "../co-builder/src/crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "../co-builder/src/crs/bn254_g2.dat";

    let constraint_system =
        constraint_system_from_reader(File::open(circuit_file).unwrap(), true).unwrap();
    let witness = noir_types::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let mut driver = PlainAcvmSolver::new();
    let builder = UltraCircuitBuilder::<
        <ark_ec::models::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1,
    >::create_circuit(
        &constraint_system,
        false, // We don't support recursive atm
        0,
        witness,
        HonkRecursion::UltraHonk,
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
        UltraHonk::<_, H, UltraFlavour>::prove(proving_key, has_zk).unwrap();
    if has_zk == ZeroKnowledge::No {
        let proof_u8 = proof.to_buffer();
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
        assert_eq!(proof, read_proof);
    }

    let is_valid =
        UltraHonk::<_, H, UltraFlavour>::verify(proof, &public_inputs, &verifying_key, has_zk)
            .unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";

    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn poseidon_test_keccak256() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";

    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn add3_test_keccak256() {
    const PROOF_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.gz";

    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}

#[test]
fn add3_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/add3u64/kat/add3u64.gz";

    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::No);
    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE, ZeroKnowledge::Yes);
}
