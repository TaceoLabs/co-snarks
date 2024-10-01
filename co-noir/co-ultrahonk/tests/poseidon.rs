use ark_bn254::Bn254;
use co_ultrahonk::prelude::{CoUltraHonk, PlainCoBuilder, ProvingKey, SharedBuilderVariable};
use mpc_core::protocols::plain::PlainDriver;
use ultrahonk::{prelude::HonkProof, Utils};

#[test]
fn poseidon_plaindriver_test() {
    const CRS_PATH_G1: &str = "../ultrahonk/crs/bn254_g1.dat";
    // const CRS_PATH_G2: &str = "crs/bn254_g2.dat";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";
    const PROOF_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.proof";

    let constraint_system = Utils::get_constraint_system_from_file(CIRCUIT_FILE, true).unwrap();
    let witness = Utils::get_witness_from_file(WITNESS_FILE).unwrap();

    let witness = SharedBuilderVariable::promote_public_witness_vector(witness);

    let builder =
        PlainCoBuilder::<Bn254>::create_circuit(constraint_system, 0, witness, true, false);

    let driver = PlainDriver::default();

    let prover_crs = ProvingKey::get_prover_crs(&builder, CRS_PATH_G1).unwrap();
    let proving_key = ProvingKey::create(&driver, builder, prover_crs);

    let prover = CoUltraHonk::new(driver);
    let proof = prover.prove(proving_key).unwrap();
    let proof_u8 = proof.to_buffer();

    let read_proof_u8 = std::fs::read(PROOF_FILE).unwrap();
    assert_eq!(proof_u8, read_proof_u8);

    let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
    assert_eq!(proof, read_proof);
}
