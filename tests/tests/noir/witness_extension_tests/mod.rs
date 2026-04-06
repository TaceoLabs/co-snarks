use acir::native_types::{WitnessMap, WitnessStack};
use ark_ff::PrimeField;
use co_acvm::Rep3AcvmType;
use co_spdz_acvm::types::SpdzAcvmType;
use itertools::izip;

mod plain_solver;
mod rep3;
mod spdz;

macro_rules! add_plain_acvm_test {
        ($name: expr) => {
            paste::item! {
                #[test]
                fn [< test_plain_ $name >]() {
                    let program = std::fs::read_to_string(format!(
                        "../test_vectors/noir/{}/kat/{}.json",
                    $name, $name))
                    .unwrap();
                    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                        .expect("failed to parse program artifact");
                    let should_witness =
                        std::fs::read(format!("../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();
                    let should_witness =
                      WitnessStack::deserialize(should_witness.as_slice()).unwrap();
                    let prover_toml = format!("../test_vectors/noir/{}/Prover.toml", $name);
                    let solver =
                        PlainCoSolver::init_plain_driver(program_artifact, prover_toml).unwrap();
                    let is_witness = solver.solve().unwrap();
                    let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
                    assert_eq!(is_witness, should_witness);
                }
            }
        };
    }

macro_rules! add_rep3_acvm_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_rep3_ $name >]() {
                let root = std::env!("CARGO_MANIFEST_DIR");
                let program = std::fs::read_to_string(format!(
                    "{root}/../test_vectors/noir/{}/kat/{}.json",
                    $name, $name
                ))
                .unwrap();
                let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                    .expect("failed to parse program artifact");

                let should_witness =
                    std::fs::read(format!("{root}/../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();

                let should_witness =
                   WitnessStack::deserialize(should_witness.as_slice()).unwrap();
                let input = PathBuf::from(format!(
                    "{root}/../test_vectors/noir/{}/Prover.toml",
                    $name
                ));
                // read the input file
                let inputs = noir_types::partially_read_abi_bn254(
                    std::fs::File::open(input).unwrap(),
                    &program_artifact.abi,
                    &program_artifact.bytecode.functions[0].public_inputs().indices(),
                ).expect("can share field elements for noir witness extension");

                // create input shares
                let shares = co_noir::split_input_rep3(inputs);
                let nets0 = LocalNetwork::new_3_parties();
                let nets1 = LocalNetwork::new_3_parties();
                let mut threads = vec![];
                for (net0, net1, program_artifact, share) in izip!(
                    nets0,
                    nets1,
                    [
                        program_artifact.clone(),
                        program_artifact.clone(),
                        program_artifact
                    ],
                    shares
                ) {
                    threads.push(std::thread::spawn(move || {
                        let input_share = co_noir::witness_map_from_string_map(share, &program_artifact.abi).expect("can translate witness for noir witness extension");
                        let solver =
                            Rep3CoSolver::new_with_witness(&net0, &net1, program_artifact, input_share).unwrap();
                        let proof = solver.solve().unwrap();
                        proof
                    }));
                }

                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();
                let is_witness = super::combine_field_elements_for_acvm(result1, result2, result3);
                let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
                assert_eq!(should_witness, is_witness)
            }
        }
    };
}

/// SPDZ 2PC prove+verify test parameterized by hasher and ZK mode.
pub(super) fn spdz_prove_verify_test<H: co_noir_common::transcript::TranscriptHasher<co_noir_common::honk_proof::TranscriptFieldType>>(
    name: &str,
    has_zk: co_noir_common::types::ZeroKnowledge,
) {
    use ark_bn254::{Bn254, Fr};
    use co_noir::Bn254G1;
    use co_noir_common::crs::parse::CrsParser;
    use co_noir_common::types::ZeroKnowledge;
    use co_spdz_acvm::types::SpdzAcvmType;
    use co_ultrahonk::prelude::UltraHonk;
    use mpc_net::local::LocalNetwork;
    use spdz_core::preprocessing::{create_lazy_preprocessing, SpdzPreprocessing};
    use spdz_core::types::share_field_element;
    use std::sync::Arc;

    let root = std::env!("CARGO_MANIFEST_DIR");
    let circuit_file = format!("{root}/../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("{root}/../test_vectors/noir/{name}/kat/{name}.gz");
    let crs_g1 = format!("{root}/../co-noir/co-noir-common/src/crs/bn254_g1.dat");
    let crs_g2 = format!("{root}/../co-noir/co-noir-common/src/crs/bn254_g2.dat");

    let artifact = co_noir::program_artifact_from_reader(
        std::fs::File::open(&circuit_file).unwrap()
    ).expect("failed to parse program artifact");
    let cs = co_noir::get_constraint_system_from_artifact(&artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&cs).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(&crs_g1, crs_size, has_zk).unwrap()
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(&crs_g2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&cs, prover_crs.clone(), verifier_crs).unwrap();

    let witness = co_noir::witness_from_reader(
        std::fs::File::open(&witness_file).unwrap()
    ).unwrap();

    // Random seeds per test to avoid interference when tests run in parallel
    let seed_pk: u64 = rand::random();
    let seed_pr: u64 = rand::random();
    let mut pk0 = create_lazy_preprocessing::<Fr>(seed_pk, 0);
    let mut pk1 = create_lazy_preprocessing::<Fr>(seed_pk, 1);
    let pr0 = create_lazy_preprocessing::<Fr>(seed_pr, 0);
    let pr1 = create_lazy_preprocessing::<Fr>(seed_pr, 1);
    let mac_key = pk0.mac_key_share() + pk1.mac_key_share();

    let public_inputs = &cs.public_inputs;
    let mut rng = rand::thread_rng();
    let mut w0 = Vec::with_capacity(witness.len());
    let mut w1 = Vec::with_capacity(witness.len());
    for (i, val) in witness.iter().enumerate() {
        if public_inputs.contains(&(i as u32)) {
            w0.push(SpdzAcvmType::Public(*val));
            w1.push(SpdzAcvmType::Public(*val));
        } else {
            let [s0, s1] = share_field_element(*val, mac_key, &mut rng);
            w0.push(SpdzAcvmType::Shared(s0));
            w1.push(SpdzAcvmType::Shared(s1));
        }
    }

    let mut nets = LocalNetwork::new(2).into_iter();
    let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());

    let cs0 = co_noir::get_constraint_system_from_artifact(&artifact);
    let cs1 = co_noir::get_constraint_system_from_artifact(&artifact);
    let (c0, c1) = (prover_crs.clone(), prover_crs.clone());
    let (v0, v1) = (vk.clone(), vk.clone());

    let t0 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk0) as Box<dyn SpdzPreprocessing<Fr>>,
            &cs0, w0, &net0, &c0,
        ).unwrap();
        co_spdz_noir::prove_spdz::<_, H, _>(
            &net0, Box::new(pr0) as Box<dyn SpdzPreprocessing<Fr>>,
            pk, &c0, has_zk, &v0.inner_vk,
        ).unwrap()
    });
    let t1 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk1) as Box<dyn SpdzPreprocessing<Fr>>,
            &cs1, w1, &net1, &c1,
        ).unwrap();
        co_spdz_noir::prove_spdz::<_, H, _>(
            &net1, Box::new(pr1) as Box<dyn SpdzPreprocessing<Fr>>,
            pk, &c1, has_zk, &v1.inner_vk,
        ).unwrap()
    });

    let (proof0, pi0) = t0.join().expect("Party 0 panicked");
    let (proof1, pi1) = t1.join().expect("Party 1 panicked");
    assert_eq!(proof0, proof1, "proofs differ between parties");
    assert_eq!(pi0, pi1, "public inputs differ between parties");

    let valid = UltraHonk::<_, H>::verify(proof0, &pi0, &vk, has_zk).unwrap();
    assert!(valid, "proof verification failed for {} (zk={:?})", name, has_zk);
}

/// SPDZ prove+verify: Keccak256 transcript, no ZK
macro_rules! add_spdz_acvm_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_spdz_ $name >]() {
                spdz_prove_verify_test::<sha3::Keccak256>(
                    $name, co_noir_common::types::ZeroKnowledge::No,
                );
            }
        }
    };
}

/// SPDZ prove+verify: Keccak256 transcript, WITH ZK
macro_rules! add_spdz_acvm_test_zk {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_spdz_zk_ $name >]() {
                spdz_prove_verify_test::<sha3::Keccak256>(
                    $name, co_noir_common::types::ZeroKnowledge::Yes,
                );
            }
        }
    };
}

/// SPDZ prove+verify: Poseidon2Sponge transcript, no ZK
macro_rules! add_spdz_acvm_test_poseidon2 {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_spdz_pos_ $name >]() {
                spdz_prove_verify_test::<co_noir_common::transcript::Poseidon2Sponge>(
                    $name, co_noir_common::types::ZeroKnowledge::No,
                );
            }
        }
    };
}

fn combine_field_elements_for_acvm<F: PrimeField>(
    mut a: WitnessStack<Rep3AcvmType<F>>,
    mut b: WitnessStack<Rep3AcvmType<F>>,
    mut c: WitnessStack<Rep3AcvmType<F>>,
) -> WitnessStack<F> {
    let mut res = WitnessStack::default();
    assert_eq!(a.length(), b.length());
    assert_eq!(b.length(), c.length());
    while let Some(stack_item_a) = a.pop() {
        let stack_item_b = b.pop().unwrap();
        let stack_item_c = c.pop().unwrap();
        assert_eq!(stack_item_a.index, stack_item_b.index);
        assert_eq!(stack_item_b.index, stack_item_c.index);
        let mut witness_map = WitnessMap::default();
        for ((witness_a, share_a), (witness_b, share_b), (witness_c, share_c)) in izip!(
            stack_item_a.witness.into_iter(),
            stack_item_b.witness.into_iter(),
            stack_item_c.witness.into_iter()
        ) {
            assert_eq!(witness_a, witness_b);
            assert_eq!(witness_b, witness_c);
            let reconstructed = match (share_a, share_b, share_c) {
                (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)) => {
                    if a == b && b == c {
                        a
                    } else {
                        panic!("must be all public")
                    }
                }
                (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)) => {
                    mpc_core::protocols::rep3::combine_field_element(a, b, c)
                }
                _ => unimplemented!(),
            };
            witness_map.insert(witness_a, reconstructed);
        }
        res.push(stack_item_a.index, witness_map);
    }
    res
}

use add_plain_acvm_test;
use add_rep3_acvm_test;
use add_spdz_acvm_test;
use add_spdz_acvm_test_zk;
use add_spdz_acvm_test_poseidon2;
