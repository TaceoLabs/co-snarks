use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use circom_types::plonk::PlonkProof;
use circom_types::Witness;
use circom_types::{
    groth16::{Groth16Proof, JsonPublicInput, JsonVerificationKey as Groth16VK, ZKey as Groth16ZK},
    plonk::{JsonVerificationKey as PlonkVK, ZKey as PlonkZK},
    R1CS,
};
use std::sync::Arc;

use circom_types::traits::CheckElement;
use co_circom_snarks::SharedWitness;
use co_groth16::Groth16;
use co_groth16::Rep3CoGroth16;
use co_plonk::Plonk;
use co_plonk::Rep3CoPlonk;
use itertools::izip;
use rand::thread_rng;
use std::{fs::File, thread};
use tests::rep3_network::{PartyTestNetwork, Rep3TestNetwork};

macro_rules! e2e_test {
    ($name: expr) => {
        add_test_impl!(Groth16, Bn254, $name);
        add_test_impl!(Groth16, Bls12_381, $name);
        add_test_impl!(Plonk, Bn254, $name);
        add_test_impl!(Plonk, Bls12_381, $name);
    };
}

macro_rules! add_test_impl {
    ($proof_system: ident, $curve: ident, $name: expr) => {
        paste::item! {
            #[test]
            fn [< e2e_proof_ $name _ $curve:lower _ $proof_system:lower>] () {
                let zkey_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circuit.zkey", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap();
                let r1cs_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circuit.r1cs", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap();
                let witness_file =
                    File::open(format!("../test_vectors/{}/{}/{}/witness.wtns", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap();
                let witness = Witness::<[< ark_ $curve:lower >]::Fr>::from_reader(witness_file).unwrap();
                let zkey1 = Arc::new([< $proof_system ZK >]::<$curve>::from_reader(zkey_file, CheckElement::No).unwrap());
                let zkey2 = Arc::clone(&zkey1);
                let zkey3 = Arc::clone(&zkey1);
                let r1cs = R1CS::<$curve>::from_reader(r1cs_file).unwrap();
                //ignore leading 1 for verification
                let public_input = witness.values[1..r1cs.num_inputs].to_vec();
                let mut rng = thread_rng();
                let [witness_share1, witness_share2, witness_share3] =
                    SharedWitness::share_rep3(witness, r1cs.num_inputs, &mut rng);
                let test_network = Rep3TestNetwork::default();
                let mut threads = vec![];
                for (net, x, zkey) in izip!(
                    test_network.get_party_networks(),
                    [witness_share1, witness_share2, witness_share3].into_iter(),
                    [zkey1, zkey2, zkey3].into_iter()
                ) {
                    threads.push(thread::spawn(move || {
                        [< Rep3Co $proof_system>]::<$curve, PartyTestNetwork>::prove(net, zkey, x).unwrap().0
                    }));
                }
                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();
                assert_eq!(result1, result2);
                assert_eq!(result2, result3);
                let ser_proof = serde_json::to_string(&result1).unwrap();
                let der_proof = serde_json::from_str::<[< $proof_system Proof >]<$curve>>(&ser_proof).unwrap();
                let vk: [ < $proof_system VK > ]<$curve> = serde_json::from_reader(
                    File::open(format!("../test_vectors/{}/{}/{}/verification_key.json", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap(),
                )
                .unwrap();
                assert_eq!(der_proof, result2);
                    $proof_system::<$curve>::verify(&vk, &der_proof, &public_input).expect("can verify");
            }

            #[test]
            fn [< e2e_proof_verify_snarkjs_proof_ $name _ $curve:lower _ $proof_system:lower>] () {
                let snarkjs_proof_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circom.proof", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap();
                let public_input_file =
                    File::open(format!("../test_vectors/{}/{}/{}/public.json", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap();
                let vk_file =
                    File::open(format!("../test_vectors/{}/{}/{}/verification_key.json", stringify!($proof_system), stringify!([< $curve:lower >]), $name)).unwrap();
                let vk: [ < $proof_system VK > ]<$curve> = serde_json::from_reader(
                    vk_file,
                )
                .unwrap();
                let public_input: JsonPublicInput::<[< ark_ $curve:lower >]::Fr> = serde_json::from_reader(public_input_file).unwrap();
                let snarkjs_proof: [< $proof_system Proof >]<$curve> = serde_json::from_reader(&snarkjs_proof_file).unwrap();
                    $proof_system::<$curve>::verify(&vk, &snarkjs_proof, &public_input.values).expect("can verify");
            }
        }
    };
}
e2e_test!("multiplier2");
e2e_test!("poseidon");
