use acir::native_types::{WitnessMap, WitnessStack};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use co_acvm::solver::Rep3CoSolver;
use co_ultrahonk::prelude::{
    CoUltraHonk, HonkProof, ProvingKey, Rep3CoBuilder, SharedBuilderVariable, UltraCircuitVariable,
    Utils,
};
use mpc_core::protocols::rep3::{
    network::Rep3Network, witness_extension_impl::Rep3VmType, Rep3Protocol,
};
use serial_test::serial;
use std::thread;
use tests::rep3_network::Rep3TestNetwork;

fn witness_map_to_witness_vector<P: Pairing, N: Rep3Network>(
    witness_map: WitnessMap<Rep3VmType<P::ScalarField>>,
) -> Vec<SharedBuilderVariable<Rep3Protocol<P::ScalarField, N>, P>> {
    let mut wv = Vec::new();
    let mut index = 0;
    for (w, f) in witness_map.into_iter() {
        // ACIR uses a sparse format for WitnessMap where unused witness indices may be left unassigned.
        // To ensure that witnesses sit at the correct indices in the `WitnessVector`, we fill any indices
        // which do not exist within the `WitnessMap` with the dummy value of zero.
        while index < w.0 {
            wv.push(SharedBuilderVariable::from_public(P::ScalarField::zero()));
            index += 1;
        }
        match f {
            Rep3VmType::Public(f) => {
                wv.push(SharedBuilderVariable::from_public(f));
            }
            Rep3VmType::Shared(f) => {
                wv.push(SharedBuilderVariable::from_shared(f));
            }
            Rep3VmType::BitShared => panic!("BitShared not supported"),
        }
        index += 1;
    }
    wv
}

fn convert_witness_rep3<P: Pairing, N: Rep3Network>(
    mut witness_stack: WitnessStack<Rep3VmType<P::ScalarField>>,
) -> Vec<SharedBuilderVariable<Rep3Protocol<P::ScalarField, N>, P>> {
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;
    witness_map_to_witness_vector(witness_map)
}

fn proof_test(name: &str) {
    const CRS_PATH_G1: &str = "../co-noir/ultrahonk/crs/bn254_g1.dat";
    let circuit_file = format!("../test_vectors/noir/{}/kat/{}.json", name, name);
    let witness_file = format!("../test_vectors/noir/{}/kat/{}.gz", name, name);
    let proof_file = format!("../test_vectors/noir/{}/kat/{}.proof", name, name);

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");
    let witness = Utils::get_witness_from_file(&witness_file).expect("failed to parse witness");

    // Will be trivially shared anyways
    let witness = witness
        .into_iter()
        .map(SharedBuilderVariable::from_public)
        .collect::<Vec<_>>();

    let test_network = Rep3TestNetwork::default();
    let mut threads = Vec::with_capacity(3);
    for net in test_network.get_party_networks() {
        let artifact = program_artifact.clone();
        let witness = witness.clone();
        threads.push(thread::spawn(move || {
            let constraint_system = Utils::get_constraint_system_from_artifact(&artifact, true);

            let builder = Rep3CoBuilder::<Bn254, _>::create_circuit(
                constraint_system,
                0,
                witness,
                true,
                false,
            );

            let prover_crs = ProvingKey::get_prover_crs(&builder, CRS_PATH_G1)
                .expect("failed to get prover crs");

            let driver = Rep3Protocol::new(net).unwrap();
            let proving_key = ProvingKey::create(&driver, builder, prover_crs);

            let prover = CoUltraHonk::new(driver);
            prover.prove(proving_key).unwrap()
        }));
    }

    let mut proofs = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let proof_u8 = proof.to_buffer();

    let read_proof_u8 = std::fs::read(&proof_file).unwrap();
    assert_eq!(proof_u8, read_proof_u8);

    let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
    assert_eq!(proof, read_proof);
}

fn witness_and_proof_test(name: &str) {
    const CRS_PATH_G1: &str = "../co-noir/ultrahonk/crs/bn254_g1.dat";
    let circuit_file = format!("../test_vectors/noir/{}/kat/{}.json", name, name);
    let prover_toml = format!("../test_vectors/noir/{}/Prover.toml", name);
    let proof_file = format!("../test_vectors/noir/{}/kat/{}.proof", name, name);

    let program_artifact = Utils::get_program_artifact_from_file(&circuit_file)
        .expect("failed to parse program artifact");

    let test_network1 = Rep3TestNetwork::default();
    let test_network2 = Rep3TestNetwork::default();
    let mut threads = Vec::with_capacity(3);
    for (net1, net2) in test_network1
        .get_party_networks()
        .into_iter()
        .zip(test_network2.get_party_networks())
    {
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(thread::spawn(move || {
            let constraint_system = Utils::get_constraint_system_from_artifact(&artifact, true);
            let solver = Rep3CoSolver::from_network(net1, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = convert_witness_rep3(witness);

            let builder = Rep3CoBuilder::<Bn254, _>::create_circuit(
                constraint_system,
                0,
                witness,
                true,
                false,
            );

            let prover_crs = ProvingKey::get_prover_crs(&builder, CRS_PATH_G1)
                .expect("failed to get prover crs");

            let driver = Rep3Protocol::new(net2).unwrap();
            let proving_key = ProvingKey::create(&driver, builder, prover_crs);

            let prover = CoUltraHonk::new(driver);
            prover.prove(proving_key).unwrap()
        }));
    }

    let mut proofs = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let proof_u8 = proof.to_buffer();

    let read_proof_u8 = std::fs::read(&proof_file).unwrap();
    assert_eq!(proof_u8, read_proof_u8);

    let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
    assert_eq!(proof, read_proof);
}

#[test]
#[serial]
fn poseidon_witness_and_proof_test() {
    witness_and_proof_test("poseidon");
}

#[test]
#[serial]
fn poseidon_proof_test() {
    proof_test("poseidon");
}
