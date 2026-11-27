use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::{Bn254, Fr};
use co_acvm::solver::Rep3CoSolver;
use co_noir::{Bn254G1, HonkProof, OpenRecursionData, ProgramArtifact};
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_noir_types::Rep3Type;
use co_ultrahonk::prelude::{Rep3CoUltraHonk, ShamirCoUltraHonk, UltraHonk};
use itertools::izip;
use mpc_core::protocols::rep3::{id::PartyID, share_field_element};
use mpc_net::{local::LocalNetwork, Network};
use sha3::Keccak256;
use std::{fs::File, sync::Arc};

/// Reads the circuit and the witness of the test vector `name` and shares the witness. Public inputs stay public.
fn load_shared_witness(name: &str) -> (ProgramArtifact, [Vec<Rep3Type<Fr>>; 3]) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let public_inputs = &constraint_system.public_inputs;

    let witnesses = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            if public_inputs.contains(&(index as u32)) {
                std::array::from_fn(|_| Rep3Type::from(value))
            } else {
                share_field_element(value, &mut rand::thread_rng()).map(Rep3Type::from)
            }
        });
    let witnesses: [Vec<Rep3Type<Fr>>; 3] =
        witnesses
            .into_iter()
            .fold([Vec::new(), Vec::new(), Vec::new()], |mut acc, share| {
                for (i, s) in share.into_iter().enumerate() {
                    acc[i].push(s);
                }
                acc
            });
    (program_artifact, witnesses)
}

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    // The verifier of a ZK proof is not implemented for shared values, so its recursion data has to be opened
    let open_recursion_data = OpenRecursionData::from(name == "recursion_zk");
    let (program_artifact, witnesses) = load_shared_witness(name);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                open_recursion_data,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();
            (proof, public_input, vk)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input, _)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    let vk = results[0].2.clone();
    if has_zk == ZeroKnowledge::No && !proof_file.is_empty() {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid = UltraHonk::<Bn254G1, H>::verify(proof, &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);
}

fn witness_and_proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    // The verifier of a ZK proof is not implemented for shared values, so its recursion data has to be opened
    let open_recursion_data = OpenRecursionData::from(name == "recursion_zk");
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();
    for net in nets {
        let prover_crs = prover_crs.clone();
        let vk = vk.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = Rep3CoSolver::new(&net, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                open_recursion_data,
            )
            .unwrap();
            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();
            (proof, public_input)
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

    if has_zk == ZeroKnowledge::No && !proof_file.is_empty() {
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
fn poseidon_witness_and_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_witness_and_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    witness_and_proof_test::<Keccak256>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    proof_test::<Keccak256>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn random_access_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("random_access", ZeroKnowledge::Yes, "");
}

#[test]
fn random_access_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("random_access", ZeroKnowledge::Yes, "");
}

// The xor of two shared values is proven with lookups with shared operands, so the lookup read tags are shared
#[test]
fn blackbox_xor_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("blackbox_xor", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("blackbox_xor", ZeroKnowledge::Yes, "");
}

/// Builds the proving key with REP3, translates it to Shamir shares and proves with Shamir.
fn translated_proving_key_proof_test(name: &str) {
    type H = Poseidon2Sponge;
    let has_zk = ZeroKnowledge::Yes;
    let (program_artifact, witnesses) = load_shared_witness(name);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();

    let mut threads = Vec::with_capacity(3);
    for (net, witness) in izip!(LocalNetwork::new_3_parties(), witnesses) {
        let prover_crs = prover_crs.clone();
        let vk = vk.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                OpenRecursionData::No,
            )
            .unwrap();
            let id = PartyID::try_from(net.id()).unwrap();
            let pk = co_noir::translate_proving_key(pk, id).unwrap();
            let (proof, public_input) =
                ShamirCoUltraHonk::<_, H>::prove(&net, 3, 1, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();
            (proof, public_input)
        }));
    }
    let mut results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let (proof, public_input) = results.pop().unwrap();
    for (other_proof, other_public_input) in results {
        assert_eq!(proof, other_proof);
        assert_eq!(public_input, other_public_input);
    }
    assert!(UltraHonk::<_, H>::verify(proof, &public_input, &vk, has_zk).unwrap());
}

#[test]
fn poseidon_translated_proving_key_proof_test() {
    translated_proving_key_proof_test("poseidon");
}

// A ROM that is read at a shared index
#[test]
fn random_access_translated_proving_key_proof_test() {
    translated_proving_key_proof_test("random_access");
}

#[test]
fn rom_shared_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::Yes, "");
}

#[test]
fn rom_shared_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "REP3 methods on shared values are not yet implemented"]
fn recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "REP3 methods on shared values are not yet implemented"]
fn recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}

// The proof, the verification key and the key hash of the inner ZK proof are shared, so they must not be opened unless this is explicitly allowed
#[test]
fn zk_recursion_is_rejected_without_opening_recursion_data() {
    let (program_artifact, witnesses) = load_shared_witness("recursion_zk");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::Yes).unwrap(),
    );

    let mut threads = Vec::with_capacity(3);
    for (net, witness) in izip!(LocalNetwork::new_3_parties(), witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                OpenRecursionData::No,
            )
            .map(|_| ())
        }));
    }
    for thread in threads {
        let err = thread.join().unwrap().expect_err("must be rejected");
        assert!(
            format!("{err:?}").contains("would have to be opened to all parties"),
            "unexpected error: {err:?}"
        );
    }
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn zk_recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn zk_recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::No, "");
    proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::Yes, "");
}

// The proving key of a circuit with a RAM that is accessed at a shared index contains the shared read/write types of the memory records. No test vector has such a RAM, so the translation is tested with a handmade key.
#[test]
fn translate_proving_key_keeps_shared_memory_records() {
    use co_noir_common::keys::proving_key::Rep3ProvingKey;
    use co_noir_common::polynomials::entities::Polynomials;
    use mpc_core::protocols::shamir;

    let mut rng = rand::thread_rng();
    let circuit_size = 4;
    let witness_value = Fr::from(42u64);
    let records = [
        (5u32, Fr::from(1u64)),
        (9, Fr::from(0u64)),
        (12, Fr::from(1u64)),
    ];

    let witness_shares = share_field_element(witness_value, &mut rng);
    let record_shares = records.map(|(_, value)| share_field_element(value, &mut rng));

    let translated = [PartyID::ID0, PartyID::ID1, PartyID::ID2].map(|id| {
        let i = usize::from(id);
        let mut pk = Rep3ProvingKey::<Bn254G1> {
            polynomials: Polynomials::new(circuit_size),
            circuit_size: circuit_size as u32,
            ..Default::default()
        };
        pk.polynomials.witness.elements[0][1] = witness_shares[i];
        for ((gate, _), shares) in records.iter().zip(record_shares.iter()) {
            pk.memory_records_shared.insert(*gate, shares[i]);
        }
        co_noir::translate_proving_key(pk, id).unwrap()
    });

    let open = |shares: [_; 3]| shamir::combine_field_element(&shares, &[1, 2, 3], 1).unwrap();
    assert_eq!(
        open(
            translated
                .each_ref()
                .map(|pk| pk.polynomials.witness.elements[0][1])
        ),
        witness_value
    );
    for (gate, value) in records {
        for pk in &translated {
            assert_eq!(pk.memory_records_shared.len(), records.len());
        }
        let shares = translated
            .each_ref()
            .map(|pk| pk.memory_records_shared[&gate]);
        assert_eq!(open(shares), value);
    }
}
