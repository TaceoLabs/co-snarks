//! Correctness tests for 2-party SPDZ collaborative proving.
//!
//! 1. Shared x shared multiplication works through the circuit (Beaver triples)
//! 2. Genuinely secret-shared inputs (each party holds different shares)
//! 3. Both parties produce identical proofs

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use co_noir::Bn254G1;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::keys::verification_key::VerifyingKey;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::types::ZeroKnowledge;
use co_spdz_acvm::types::SpdzAcvmType;
use co_ultrahonk::prelude::UltraHonk;
use mpc_net::local::LocalNetwork;
use mpc_net::Network;
use noir_types::HonkProof;
use rand::SeedableRng;
use sha3::Keccak256;
use spdz_core::preprocessing::{
    generate_dummy_preprocessing, generate_dummy_preprocessing_with_rng, SpdzPreprocessing,
};
use spdz_core::types::{share_field_element, SpdzPrimeFieldShare};
use std::fs::File;
use std::sync::Arc;

const CRS_PATH_G1: &str = "../../co-noir/co-noir-common/src/crs/bn254_g1.dat";
const CRS_PATH_G2: &str = "../../co-noir/co-noir-common/src/crs/bn254_g2.dat";

fn load_circuit(
    circuit_file: &str,
    has_zk: ZeroKnowledge,
) -> (
    noirc_artifacts::program::ProgramArtifact,
    Arc<ProverCrs<Bn254G1>>,
    VerifyingKey<Bn254>,
) {
    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk =
        co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
            .unwrap();
    (program_artifact, prover_crs, vk)
}

fn run_spdz_prove_with_prep<H: TranscriptHasher<TranscriptFieldType>>(
    program_artifact: &noirc_artifacts::program::ProgramArtifact,
    witness_0: Vec<SpdzAcvmType<Fr>>,
    witness_1: Vec<SpdzAcvmType<Fr>>,
    pk_prep_0: Box<dyn SpdzPreprocessing<Fr>>,
    pk_prep_1: Box<dyn SpdzPreprocessing<Fr>>,
    prove_prep_0: Box<dyn SpdzPreprocessing<Fr>>,
    prove_prep_1: Box<dyn SpdzPreprocessing<Fr>>,
    prover_crs: &Arc<ProverCrs<Bn254G1>>,
    vk: &VerifyingKey<Bn254>,
    has_zk: ZeroKnowledge,
) -> (HonkProof<H::DataType>, Vec<H::DataType>) {
    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();
    let cs_0 = co_noir::get_constraint_system_from_artifact(program_artifact);
    let cs_1 = co_noir::get_constraint_system_from_artifact(program_artifact);
    let crs_0 = prover_crs.clone();
    let crs_1 = prover_crs.clone();
    let vk_0 = vk.clone();
    let vk_1 = vk.clone();

    let t0 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            pk_prep_0, &cs_0, witness_0, &net0, &crs_0,
        )
        .unwrap();
        co_spdz_noir::prove_spdz::<_, H, _>(
            &net0, prove_prep_0, pk, &crs_0, has_zk, &vk_0.inner_vk,
        )
        .unwrap()
    });

    let t1 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            pk_prep_1, &cs_1, witness_1, &net1, &crs_1,
        )
        .unwrap();
        co_spdz_noir::prove_spdz::<_, H, _>(
            &net1, prove_prep_1, pk, &crs_1, has_zk, &vk_1.inner_vk,
        )
        .unwrap()
    });

    let (proof_0, pi_0) = t0.join().expect("P0 panicked");
    let (proof_1, pi_1) = t1.join().expect("P1 panicked");

    assert_eq!(proof_0, proof_1, "Both parties must produce identical proofs");
    assert_eq!(pi_0, pi_1, "Both parties must produce identical public inputs");

    (proof_0, pi_0)
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1: Shared x shared multiplication (trivially shared)
//
// Circuit: fn main(x: Field, y: Field) { assert(x * y != 0); }
// Both inputs are private. x*y exercises Beaver triple multiplication.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_shared_x_shared_multiplication() {
    let circuit_file = "../../test_vectors/noir/mul_shared/kat/mul_shared.json";
    let witness_file = "../../test_vectors/noir/mul_shared/kat/mul_shared.gz";
    let (program_artifact, prover_crs, vk) = load_circuit(circuit_file, ZeroKnowledge::No);

    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let w: Vec<SpdzAcvmType<Fr>> = witness.into_iter().map(SpdzAcvmType::Public).collect();

    let (pk_p0, pk_p1) = generate_dummy_preprocessing::<Fr>(50_000);
    let (pr_p0, pr_p1) = generate_dummy_preprocessing::<Fr>(50_000);

    let (proof, pi) = run_spdz_prove_with_prep::<Keccak256>(
        &program_artifact,
        w.clone(),
        w,
        Box::new(pk_p0),
        Box::new(pk_p1),
        Box::new(pr_p0),
        Box::new(pr_p1),
        &prover_crs,
        &vk,
        ZeroKnowledge::No,
    );

    assert!(
        UltraHonk::<_, Keccak256>::verify(proof, &pi, &vk, ZeroKnowledge::No).unwrap(),
        "shared*shared multiplication proof must verify"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2: Genuinely secret-shared inputs
//
// Same mul_shared circuit, but we SPDZ-share the witness so each party
// holds DIFFERENT shares. This tests that MPC arithmetic produces correct
// results with genuinely different data per party.
//
// All witness entries are private (no pub outputs), so we can share everything.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_secret_shared_inputs() {
    let circuit_file = "../../test_vectors/noir/mul_shared/kat/mul_shared.json";
    let witness_file = "../../test_vectors/noir/mul_shared/kat/mul_shared.gz";
    let (program_artifact, prover_crs, vk) = load_circuit(circuit_file, ZeroKnowledge::No);

    let witness_plain = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();

    // Generate preprocessing first to get the MAC key
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
    let (pk_prep_0, pk_prep_1) = generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let (prove_prep_0, prove_prep_1) =
        generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);

    let mac_key = pk_prep_0.mac_key_share() + pk_prep_1.mac_key_share();

    // Secret-share each witness element with the correct MAC key
    let mut witness_0 = Vec::with_capacity(witness_plain.len());
    let mut witness_1 = Vec::with_capacity(witness_plain.len());
    for val in &witness_plain {
        let [s0, s1] = share_field_element(*val, mac_key, &mut rng);
        witness_0.push(SpdzAcvmType::Shared(s0));
        witness_1.push(SpdzAcvmType::Shared(s1));
    }

    // Sanity: verify shares reconstruct correctly
    for (i, val) in witness_plain.iter().enumerate() {
        let s0 = match &witness_0[i] {
            SpdzAcvmType::Shared(s) => s,
            _ => unreachable!(),
        };
        let s1 = match &witness_1[i] {
            SpdzAcvmType::Shared(s) => s,
            _ => unreachable!(),
        };
        assert_eq!(s0.share + s1.share, *val, "witness[{i}] must reconstruct");
        assert_eq!(
            s0.mac + s1.mac,
            mac_key * val,
            "MAC[{i}] must be correct"
        );
    }

    let (proof, pi) = run_spdz_prove_with_prep::<Keccak256>(
        &program_artifact,
        witness_0,
        witness_1,
        Box::new(pk_prep_0),
        Box::new(pk_prep_1),
        Box::new(prove_prep_0),
        Box::new(prove_prep_1),
        &prover_crs,
        &vk,
        ZeroKnowledge::No,
    );

    assert!(
        UltraHonk::<_, Keccak256>::verify(proof, &pi, &vk, ZeroKnowledge::No).unwrap(),
        "Proof from genuinely secret-shared inputs must verify"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3: Poseidon2 hash on shared values
//
// Circuit: fn main(input: [Field; 4]) -> pub Field { poseidon2_permutation(input, 4)[0] }
// Tests that Poseidon2 S-boxes work correctly with SPDZ shared values.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_poseidon2_shared() {
    let circuit_file =
        "../../test_vectors/noir/blackbox_poseidon2/kat/blackbox_poseidon2.json";
    let witness_file =
        "../../test_vectors/noir/blackbox_poseidon2/kat/blackbox_poseidon2.gz";
    let (program_artifact, prover_crs, vk) = load_circuit(circuit_file, ZeroKnowledge::No);

    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();

    // Trivially shared — but the circuit uses poseidon2_permutation on private inputs,
    // so the MPC S-box protocol is exercised.
    let w: Vec<SpdzAcvmType<Fr>> = witness.into_iter().map(SpdzAcvmType::Public).collect();

    let (pk_p0, pk_p1) = generate_dummy_preprocessing::<Fr>(100_000);
    let (pr_p0, pr_p1) = generate_dummy_preprocessing::<Fr>(100_000);

    let (proof, pi) = run_spdz_prove_with_prep::<Keccak256>(
        &program_artifact,
        w.clone(),
        w,
        Box::new(pk_p0),
        Box::new(pk_p1),
        Box::new(pr_p0),
        Box::new(pr_p1),
        &prover_crs,
        &vk,
        ZeroKnowledge::No,
    );

    assert!(
        UltraHonk::<_, Keccak256>::verify(proof, &pi, &vk, ZeroKnowledge::No).unwrap(),
        "Poseidon2 circuit proof must verify"
    );
}
