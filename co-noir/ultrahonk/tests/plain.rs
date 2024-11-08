use ark_bn254::Bn254;
use sha3::Keccak256;
use ultrahonk::{
    prelude::{
        HonkProof, PlainAcvmSolver, Poseidon2Sponge, ProvingKey, TranscriptFieldType,
        TranscriptHasher, UltraCircuitBuilder, UltraHonk,
    },
    Utils,
};

fn plain_test<H: TranscriptHasher<TranscriptFieldType>>(
    proof_file: &str,
    circuit_file: &str,
    witness_file: &str,
) {
    const CRS_PATH_G1: &str = "../co-builder/src/crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "../co-builder/src/crs/bn254_g2.dat";

    let constraint_system = Utils::get_constraint_system_from_file(circuit_file, true).unwrap();
    let witness = Utils::get_witness_from_file(witness_file).unwrap();
    let mut driver = PlainAcvmSolver::new();
    let builder = UltraCircuitBuilder::<Bn254>::create_circuit(
        constraint_system,
        0,
        witness,
        true,
        false,
        &mut driver,
    );

    let crs = ProvingKey::get_crs(&builder, CRS_PATH_G1, CRS_PATH_G2).unwrap();

    let (proving_key, verifying_key) = builder.create_keys(crs, &mut driver).unwrap();

    let proof = UltraHonk::<_, H>::prove(proving_key).unwrap();

    let proof_u8 = proof.to_buffer();

    let read_proof_u8 = std::fs::read(proof_file).unwrap();
    assert_eq!(proof_u8, read_proof_u8);

    let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
    assert_eq!(proof, read_proof);

    let is_valid = UltraHonk::<_, H>::verify(proof, verifying_key).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/pos_proof";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";

    plain_test::<Poseidon2Sponge>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE);
}

#[test]
fn poseidon_test_keccak256() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/keccak_proof";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";

    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE);
}

#[test]
fn add3_test_keccak256() {
    const PROOF_FILE: &str = "../../test_vectors/noir/add3u64/add3proof";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/add3u64/add3u64.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/add3u64/add3u64.gz";
    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE);
}

#[test]
fn add3_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/add3u64/add3proof";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/add3u64/add3u64.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/add3u64/add3u64.gz";
    plain_test::<Keccak256>(PROOF_FILE, CIRCUIT_FILE, WITNESS_FILE);
}
