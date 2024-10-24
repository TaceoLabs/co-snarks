use ark_bn254::Bn254;
use sha3::Keccak256;
use ultrahonk::{
    prelude::{
        HonkProof, Poseidon2Sponge, ProvingKey, TranscriptFieldType, TranscriptHasher,
        UltraCircuitBuilder, UltraHonk, VerifyingKeyBarretenberg,
    },
    Utils,
};

fn poseidon_test<H: TranscriptHasher<TranscriptFieldType>>(proof_file: &str) {
    const CRS_PATH_G1: &str = "crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "crs/bn254_g2.dat";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";

    let constraint_system = Utils::get_constraint_system_from_file(CIRCUIT_FILE, true).unwrap();
    let witness = Utils::get_witness_from_file(WITNESS_FILE).unwrap();

    let builder =
        UltraCircuitBuilder::<Bn254>::create_circuit(constraint_system, 0, witness, true, false);

    let crs = ProvingKey::get_crs(&builder, CRS_PATH_G1, CRS_PATH_G2).unwrap();

    let (proving_key, verifying_key) = builder.create_keys(crs).unwrap();

    let proof = UltraHonk::<_, H>::prove(proving_key).unwrap();

    // TODO Keccak flavour is currently not compatible with Barretenberg since it has a different order for the relations
    if !proof_file.is_empty() {
        let proof_u8 = proof.to_buffer();

        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
        assert_eq!(proof, read_proof);
    }

    let is_valid = UltraHonk::<_, H>::verify(proof, verifying_key).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.proof";
    poseidon_test::<Poseidon2Sponge>(PROOF_FILE);
}

#[test]
fn poseidon_test_keccak256() {
    // const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon_keccaktranscript.proof";
    poseidon_test::<Keccak256>("");
}

#[test]
fn print_vkey() {
    const CRS_PATH_G1: &str = "crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "crs/bn254_g2.dat";
    const WITNESS_FILE: &str = "/home/fabsits/collaborative-circom/co-noir/co-noir/examples/test_vectors/add3u64/target/Prover.gz";
    const CIRCUIT_FILE: &str = "/home/fabsits/collaborative-circom/co-noir/co-noir/examples/test_vectors/add3u64/add3u64.json";
    let constraint_system = Utils::get_constraint_system_from_file(CIRCUIT_FILE, true).unwrap();
    let witness = Utils::get_witness_from_file(WITNESS_FILE).unwrap();

    let builder =
        UltraCircuitBuilder::<Bn254>::create_circuit(constraint_system, 0, witness, true, false);

    let crs = ProvingKey::get_crs(&builder, CRS_PATH_G1, CRS_PATH_G2).unwrap();

    let (proving_key, verifying_key) = builder.create_keys(crs).unwrap();

    const VKTHEM: &str =
        "/home/fabsits/collaborative-circom/co-noir/co-noir/examples/test_vectors/add3u64/bb_vkey";
    const VKUS: &str = "/home/fabsits/collaborative-circom/co-noir/co-noir/examples/test_vectors/add3u64/verification_key";
    // const VKTHEM: &str =
    //     "/home/fabsits/collaborative-circom/co-noir/co-noir/examples/test_vectors/add3field/bb_vkey";
    // const VKUS: &str =
    //     "/home/fabsits/collaborative-circom/co-noir/co-noir/examples/test_vectors/add3/bb_vkey";

    let vk_u8us = std::fs::read(VKUS).unwrap();
    let vkus = VerifyingKeyBarretenberg::<Bn254>::from_buffer(&vk_u8us).unwrap();

    let vk_u8them = std::fs::read(VKTHEM).unwrap();
    let vkthem = VerifyingKeyBarretenberg::<Bn254>::from_buffer(&vk_u8them).unwrap();

    // println!("this is our vk: \n");
    // vkus.print();

    // println!("\n this is their vk: \n");
    // vkthem.print();
}
