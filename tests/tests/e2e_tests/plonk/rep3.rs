use ark_bn254::Bn254;
use circom_types::{
    plonk::{JsonVerificationKey, PlonkProof, ZKey},
    Witness, R1CS,
};
use co_circom_snarks::SharedWitness;
use collaborative_plonk::{plonk::Plonk, CollaborativePlonk};
use mpc_core::protocols::rep3::Rep3Protocol;
use rand::thread_rng;
use std::{fs::File, thread};
use tests::rep3_network::{PartyTestNetwork, Rep3TestNetwork};

#[test]
fn e2e_proof_poseidon_bn254() {
    let zkey_file = File::open("../test_vectors/Plonk/bn254/poseidon/poseidon.zkey").unwrap();
    let r1cs_file = File::open("../test_vectors/Plonk/bn254/poseidon/poseidon.r1cs").unwrap();
    let witness_file = File::open("../test_vectors/Plonk/bn254/poseidon/witness.wtns").unwrap();
    let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(
        File::open("../test_vectors/Plonk/bn254/poseidon/verification_key.json").unwrap(),
    )
    .unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
    let pk1 = ZKey::<Bn254>::from_reader(zkey_file).unwrap();
    let pk2 = pk1.clone();
    let pk3 = pk1.clone();
    let r1cs1 = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
    let mut rng = thread_rng();
    let public_input = witness.values[1..r1cs1.num_inputs].to_vec();
    let [witness_share1, witness_share2, witness_share3] =
        SharedWitness::share_rep3(witness, r1cs1.num_inputs, &mut rng);
    let test_network = Rep3TestNetwork::default();
    let mut threads = vec![];
    for ((net, x), pk) in test_network
        .get_party_networks()
        .into_iter()
        .zip([witness_share1, witness_share2, witness_share3].into_iter())
        .zip([pk1, pk2, pk3].into_iter())
    {
        threads.push(thread::spawn(move || {
            let rep3 = Rep3Protocol::<ark_bn254::Fr, PartyTestNetwork>::new(net).unwrap();
            let prover =
                CollaborativePlonk::<Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>, Bn254>::new(
                    rep3,
                );
            prover.prove(&pk, x).unwrap()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);

    let ser_proof = serde_json::to_string(&result1).unwrap();
    let der_proof = serde_json::from_str::<PlonkProof<Bn254>>(&ser_proof).unwrap();
    assert_eq!(der_proof, result1);
    let verified = Plonk::<Bn254>::verify(&vk, &der_proof, &public_input).expect("can verify");
    assert!(verified);
}
