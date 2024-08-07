use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16};
use circom_types::{
    groth16::{proof::JsonProof, witness::Witness, zkey::ZKey},
    r1cs::R1CS,
};
use collaborative_groth16::{
    circuit::Circuit,
    groth16::{CollaborativeGroth16, SharedWitness},
};
use itertools::izip;
use mpc_core::protocols::shamir::ShamirProtocol;
use rand::thread_rng;
use std::{fs::File, thread};
use tests::shamir_network::{PartyTestNetwork, ShamirTestNetwork};

fn e2e_poseidon_bn254_inner(num_parties: usize, threshold: usize) {
    let zkey_file = File::open("../test_vectors/Groth16/bn254/poseidon/circuit_0000.zkey").unwrap();
    let r1cs_file = File::open("../test_vectors/Groth16/bn254/poseidon/poseidon.r1cs").unwrap();
    let witness_file = File::open("../test_vectors/Groth16/bn254/poseidon/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
    let (pk1, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
    let pk = vec![pk1.clone(); num_parties];
    let pvk = prepare_verifying_key(&pk1.vk);
    let r1cs1 = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
    let r1cs = vec![r1cs1.clone(); num_parties];
    let circuit = Circuit::new(r1cs1.clone(), witness);
    let (public_inputs1, witness) = circuit.get_wire_mapping();
    let inputs = circuit.public_inputs();
    let mut rng = thread_rng();
    let witness_share =
        SharedWitness::share_shamir(&witness, &public_inputs1, threshold, num_parties, &mut rng);

    let test_network = ShamirTestNetwork::new(num_parties);
    let mut threads = vec![];

    for (net, x, r1cs, pk) in izip!(test_network.get_party_networks(), witness_share, r1cs, pk,) {
        threads.push(thread::spawn(move || {
            let shamir =
                ShamirProtocol::<ark_bn254::Fr, PartyTestNetwork>::new(threshold, net).unwrap();
            let mut prover = CollaborativeGroth16::<
                ShamirProtocol<ark_bn254::Fr, PartyTestNetwork>,
                Bn254,
            >::new(shamir);
            prover.prove(&pk, &r1cs, x).unwrap()
        }));
    }
    let mut results = Vec::with_capacity(num_parties);
    for r in threads {
        results.push(r.join().unwrap());
    }
    let result1 = results.pop().unwrap();
    for r in results {
        assert_eq!(result1, r);
    }
    let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
    let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
    let verified =
        Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
    assert!(verified);
}

fn e2e_poseidon_bn254_with_zkey_matrices_inner(num_parties: usize, threshold: usize) {
    let zkey_file = File::open("../test_vectors/bn254/poseidon/circuit_0000.zkey").unwrap();
    let witness_file = File::open("../test_vectors/bn254/poseidon/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
    let (pk1, matrices) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
    let pk = vec![pk1.clone(); num_parties];
    let num_inputs = matrices.num_instance_variables;
    let pvk = prepare_verifying_key(&pk1.vk);
    let mut rng = thread_rng();

    let witness_share = SharedWitness::share_shamir(
        &witness.values[num_inputs..],
        &witness.values[..num_inputs],
        threshold,
        num_parties,
        &mut rng,
    );

    let test_network = ShamirTestNetwork::new(num_parties);
    let mut threads = vec![];

    for (net, x, pk) in izip!(test_network.get_party_networks(), witness_share, pk) {
        let matrices = matrices.clone();
        threads.push(thread::spawn(move || {
            let shamir =
                ShamirProtocol::<ark_bn254::Fr, PartyTestNetwork>::new(threshold, net).unwrap();
            let mut prover = CollaborativeGroth16::<
                ShamirProtocol<ark_bn254::Fr, PartyTestNetwork>,
                Bn254,
            >::new(shamir);
            prover.prove_with_matrices(&pk, &matrices, x).unwrap()
        }));
    }
    let mut results = Vec::with_capacity(num_parties);
    for r in threads {
        results.push(r.join().unwrap());
    }
    let result1 = results.pop().unwrap();
    for r in results {
        assert_eq!(result1, r);
    }
    let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
    let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
    let inputs = witness.values[1..num_inputs].to_vec();
    let verified =
        Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
    assert!(verified);
}

#[test]
fn e2e_poseidon_bn254() {
    e2e_poseidon_bn254_inner(3, 1);
    e2e_poseidon_bn254_inner(10, 4);
}

#[test]
fn e2e_poseidon_bn254_with_zkey_matrices() {
    e2e_poseidon_bn254_with_zkey_matrices_inner(3, 1);
    e2e_poseidon_bn254_with_zkey_matrices_inner(10, 4);
}
