//! Test that MAC verification works during the ACVM witness extension phase.
//!
//! The ACVM solver's open_many respects state.verify_macs. We test that
//! proving succeeds with MAC checks enabled (the default).

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use co_noir::Bn254G1;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::types::ZeroKnowledge;
use co_spdz_acvm::types::SpdzAcvmType;
use co_ultrahonk::prelude::UltraHonk;
use mpc_net::local::LocalNetwork;
use mpc_net::Network;
use rand::SeedableRng;
use sha3::Keccak256;
use spdz_core::preprocessing::{
    generate_dummy_preprocessing, generate_dummy_preprocessing_with_rng, SpdzPreprocessing,
};
use spdz_core::types::share_field_element;
use std::fs::File;
use std::sync::Arc;

const CRS_PATH_G1: &str = "../../co-noir/co-noir-common/src/crs/bn254_g1.dat";
const CRS_PATH_G2: &str = "../../co-noir/co-noir-common/src/crs/bn254_g2.dat";

/// Prove with MAC verification enabled (default behavior).
/// This exercises the ACVM solver's open_many with MAC checking.
#[test]
fn test_proving_with_mac_verification_enabled() {
    let circuit_file = "../../test_vectors/noir/mul_shared/kat/mul_shared.json";
    let witness_file = "../../test_vectors/noir/mul_shared/kat/mul_shared.gz";

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap()).unwrap();
    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();

    // Secret-share the witness with correct MACs
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(777);
    let (pk_prep_0, pk_prep_1) = generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let (prove_prep_0, prove_prep_1) =
        generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let mac_key = pk_prep_0.mac_key_share() + pk_prep_1.mac_key_share();

    let mut w0 = Vec::new();
    let mut w1 = Vec::new();
    for val in &witness {
        let [s0, s1] = share_field_element(*val, mac_key, &mut rng);
        w0.push(SpdzAcvmType::Shared(s0));
        w1.push(SpdzAcvmType::Shared(s1));
    }

    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(
        &constraint_system,
        prover_crs.clone(),
        verifier_crs,
    )
    .unwrap();

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();
    let cs_0 = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let cs_1 = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_0 = prover_crs.clone();
    let crs_1 = prover_crs.clone();
    let vk_0 = vk.clone();
    let vk_1 = vk.clone();

    // Default: MAC verification ON (semi_honest = false)
    let t0 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk_prep_0),
            &cs_0,
            w0,
            &net0,
            &crs_0,
        )
        .unwrap();
        co_spdz_noir::prove_spdz::<_, Keccak256, _>(
            &net0,
            Box::new(prove_prep_0),
            pk,
            &crs_0,
            ZeroKnowledge::No,
            &vk_0.inner_vk,
        )
        .unwrap()
    });

    let t1 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk_prep_1),
            &cs_1,
            w1,
            &net1,
            &crs_1,
        )
        .unwrap();
        co_spdz_noir::prove_spdz::<_, Keccak256, _>(
            &net1,
            Box::new(prove_prep_1),
            pk,
            &crs_1,
            ZeroKnowledge::No,
            &vk_1.inner_vk,
        )
        .unwrap()
    });

    let (proof_0, pi_0) = t0.join().expect("P0 panicked");
    let (proof_1, pi_1) = t1.join().expect("P1 panicked");

    assert_eq!(proof_0, proof_1);
    assert_eq!(pi_0, pi_1);

    let valid = UltraHonk::<_, Keccak256>::verify(proof_0, &pi_0, &vk, ZeroKnowledge::No).unwrap();
    assert!(valid, "Proof with MAC verification must verify");
}

/// Prove the same circuit with semi-honest mode explicitly, verifying it also works.
#[test]
fn test_proving_with_mac_verification_disabled() {
    let circuit_file =
        "../../test_vectors/noir/addition_multiplication/kat/addition_multiplication.json";
    let witness_file =
        "../../test_vectors/noir/addition_multiplication/kat/addition_multiplication.gz";

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap()).unwrap();
    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let w: Vec<SpdzAcvmType<Fr>> = witness.into_iter().map(SpdzAcvmType::Public).collect();

    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(
        &constraint_system,
        prover_crs.clone(),
        verifier_crs,
    )
    .unwrap();

    let (pk_p0, pk_p1) = generate_dummy_preprocessing::<Fr>(50_000);
    let (pr_p0, pr_p1) = generate_dummy_preprocessing::<Fr>(50_000);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();
    let cs_0 = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let cs_1 = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_0 = prover_crs.clone();
    let crs_1 = prover_crs.clone();
    let vk_0 = vk.clone();
    let vk_1 = vk.clone();
    let w0 = w.clone();
    let w1 = w;

    // Explicit semi-honest mode
    let t0 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz_with_options(
            Box::new(pk_p0), &cs_0, w0, &net0, &crs_0, true, // semi_honest = true
        ).unwrap();
        co_spdz_noir::prove_spdz_with_options::<_, Keccak256, _>(
            &net0, Box::new(pr_p0), pk, &crs_0, ZeroKnowledge::No, &vk_0.inner_vk, true,
        ).unwrap()
    });

    let t1 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz_with_options(
            Box::new(pk_p1), &cs_1, w1, &net1, &crs_1, true,
        ).unwrap();
        co_spdz_noir::prove_spdz_with_options::<_, Keccak256, _>(
            &net1, Box::new(pr_p1), pk, &crs_1, ZeroKnowledge::No, &vk_1.inner_vk, true,
        ).unwrap()
    });

    let (proof_0, pi_0) = t0.join().expect("P0 panicked");
    let (proof_1, pi_1) = t1.join().expect("P1 panicked");

    assert_eq!(proof_0, proof_1);

    let valid = UltraHonk::<_, Keccak256>::verify(proof_0, &pi_0, &vk, ZeroKnowledge::No).unwrap();
    assert!(valid, "Semi-honest proof must also verify");
}
