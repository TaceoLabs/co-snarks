use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16};
use circom_types::{
    groth16::{proof::JsonProof, witness::Witness, zkey::ZKey},
    r1cs::R1CS,
};
use collaborative_groth16::groth16::{CollaborativeGroth16, SharedWitness};
use mpc_core::protocols::rep3::Rep3Protocol;
use rand::thread_rng;
use std::{fs::File, thread};
use tests::rep3_network::{PartyTestNetwork, Rep3TestNetwork};

#[test]
fn e2e_proof_poseidon_bn254() {
    let zkey_file = File::open("../test_vectors/Groth16/bn254/poseidon/circuit_0000.zkey").unwrap();
    let r1cs_file = File::open("../test_vectors/Groth16/bn254/poseidon/poseidon.r1cs").unwrap();
    let witness_file = File::open("../test_vectors/Groth16/bn254/poseidon/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
    let (pk1, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
    let pk2 = pk1.clone();
    let pk3 = pk1.clone();
    let pvk = prepare_verifying_key(&pk1.vk);
    let r1cs1 = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
    let r1cs2 = r1cs1.clone();
    let r1cs3 = r1cs1.clone();
    //ignore leading 1 for verification
    let public_input = witness.values[1..r1cs1.num_inputs].to_vec();
    let mut rng = thread_rng();
    let [witness_share1, witness_share2, witness_share3] =
        SharedWitness::share_rep3(witness, r1cs1.num_inputs, &mut rng);
    let test_network = Rep3TestNetwork::default();
    let mut threads = vec![];
    for (((net, x), r1cs), pk) in test_network
        .get_party_networks()
        .into_iter()
        .zip([witness_share1, witness_share2, witness_share3].into_iter())
        .zip([r1cs1, r1cs2, r1cs3].into_iter())
        .zip([pk1, pk2, pk3].into_iter())
    {
        threads.push(thread::spawn(move || {
            let rep3 = Rep3Protocol::<ark_bn254::Fr, PartyTestNetwork>::new(net).unwrap();
            let mut prover = CollaborativeGroth16::<
                Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>,
                Bn254,
            >::new(rep3);
            prover.prove(&pk, &r1cs, x).unwrap()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
    let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof)
        .unwrap()
        .into();
    assert_eq!(der_proof, result2);
    let verified =
        Groth16::<Bn254>::verify_proof(&pvk, &der_proof, &public_input).expect("can verify");
    assert!(verified);
}

#[test]
fn e2e_proof_poseidon_bn254_with_zkey_matrices() {
    let zkey_file = File::open("../test_vectors/Groth16/bn254/poseidon/circuit_0000.zkey").unwrap();
    let witness_file = File::open("../test_vectors/Groth16/bn254/poseidon/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
    let (pk1, matrices) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
    let pk2 = pk1.clone();
    let pk3 = pk1.clone();
    let num_inputs = matrices.num_instance_variables;
    let pvk = prepare_verifying_key(&pk1.vk);
    let mut rng = thread_rng();
    let [witness_share1, witness_share2, witness_share3] =
        SharedWitness::share_rep3(witness.clone(), num_inputs, &mut rng);
    let test_network = Rep3TestNetwork::default();
    let mut threads = vec![];
    for (((net, x), mat), pk) in test_network
        .get_party_networks()
        .into_iter()
        .zip([witness_share1, witness_share2, witness_share3].into_iter())
        .zip([matrices.clone(), matrices.clone(), matrices].into_iter())
        .zip([pk1, pk2, pk3].into_iter())
    {
        threads.push(thread::spawn(move || {
            let rep3 = Rep3Protocol::<ark_bn254::Fr, PartyTestNetwork>::new(net).unwrap();
            let mut prover = CollaborativeGroth16::<
                Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>,
                Bn254,
            >::new(rep3);
            prover.prove_with_matrices(&pk, &mat, x).unwrap()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
    let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof)
        .unwrap()
        .into();
    assert_eq!(der_proof, result2);
    let inputs = witness.values[1..num_inputs].to_vec();
    let verified = Groth16::<Bn254>::verify_proof(&pvk, &der_proof, &inputs).expect("can verify");
    assert!(verified);
}
