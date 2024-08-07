use ark_bn254::Bn254;
use circom_types::{groth16::witness::Witness, plonk::ZKey, r1cs::R1CS};
use collaborative_groth16::{circuit::Circuit, groth16::SharedWitness};
use collaborative_plonk::CollaborativePlonk;
use mpc_core::protocols::rep3::Rep3Protocol;
use rand::thread_rng;
use std::{fs::File, thread};
use tests::rep3_network::{PartyTestNetwork, Rep3TestNetwork};

#[test]
fn e2e_proof_poseidon_bn254() {
    let zkey_file = File::open("../test_vectors/Plonk/bn254/poseidon/poseidon.zkey").unwrap();
    let r1cs_file = File::open("../test_vectors/Plonk/bn254/poseidon/poseidon.r1cs").unwrap();
    let witness_file = File::open("../test_vectors/Plonk/bn254/poseidon/witness.wtns").unwrap();
    let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
    let pk1 = ZKey::<Bn254>::from_reader(zkey_file).unwrap();
    let pk2 = pk1.clone();
    let pk3 = pk1.clone();
    let r1cs1 = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
    let circuit = Circuit::new(r1cs1.clone(), witness);
    let (public_inputs1, witness) = circuit.get_wire_mapping();
    let mut rng = thread_rng();
    let [witness_share1, witness_share2, witness_share3] =
        SharedWitness::share_rep3(&witness, &public_inputs1, &mut rng);
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
            prover.prove(pk, x).unwrap()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);

    // TODO rewrite for plonk
    // let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
    // let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
    // let verified =
    //     Plonk::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
    // assert!(verified);
}
