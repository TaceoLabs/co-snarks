use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use circom_types::Witness;
use circom_types::{
    groth16::{
        CircomGroth16Proof, JsonPublicInput, JsonVerificationKey as Groth16VK, ZKey as Groth16ZK,
    },
    plonk::{JsonVerificationKey as PlonkVK, PlonkProof, ZKey as PlonkZK},
    R1CS,
};
use std::sync::Arc;

use circom_types::traits::CheckElement;
use co_circom_types::SharedWitness;
use co_groth16::ShamirCoGroth16;
use co_groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey};
use co_plonk::Plonk;
use co_plonk::ShamirCoPlonk;
use itertools::izip;
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use std::fs::File;

macro_rules! e2e_test {
    ($name: expr) => {
        add_test_impl_g16!(Bn254, $name);
        add_test_impl_g16!(Bls12_381, $name);
        add_test_impl_plonk!(Bn254, $name);
        add_test_impl_plonk!(Bls12_381, $name);
    };
}

macro_rules! add_test_impl_g16 {
    ($curve: ident, $name: expr) => {
        paste::item! {
            #[test]
            fn [< e2e_proof_ $name _ $curve:lower _ groth16>] () {
                let zkey_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circuit.zkey", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap();
                let r1cs_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circuit.r1cs", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap();
                let witness_file =
                    File::open(format!("../test_vectors/{}/{}/{}/witness.wtns", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap();
                let witness = Witness::<[< ark_ $curve:lower >]::Fr>::from_reader(witness_file).unwrap();
                let zkey1 = Groth16ZK::<$curve>::from_reader(zkey_file, CheckElement::No).unwrap();
                let zkey1: (ConstraintMatrices<_>, ProvingKey<_>) = zkey1.into();
                let zkey1 = Arc::new(zkey1);
                let zkey2 = Arc::clone(&zkey1);
                let zkey3 = Arc::clone(&zkey1);
                let r1cs = R1CS::<$curve>::from_reader(r1cs_file).unwrap();
                //ignore leading 1 for verification
                let public_input = witness.values[1..r1cs.num_inputs].to_vec();
                let mut rng = thread_rng();
                let witness_shares =
                    SharedWitness::share_shamir(witness, r1cs.num_inputs, 1, 3, &mut rng);
                let nets0 = LocalNetwork::new_3_parties();
                let nets1 = LocalNetwork::new_3_parties();
                let mut threads = vec![];
                for (net0, net1, x, zkey) in izip!(
                    nets0,
                    nets1,
                    witness_shares.into_iter(),
                    [zkey1, zkey2, zkey3].into_iter()
                ) {
                    threads.push(std::thread::spawn(move || {
                        ShamirCoGroth16::<$curve>::prove::<_, CircomReduction>(&net0, &net1, 3, 1, &zkey.1, &zkey.0, x).unwrap()
                    }));
                }
                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();
                assert_eq!(result1, result2);
                assert_eq!(result2, result3);
                let proof = CircomGroth16Proof::from(result1);
                let ser_proof = serde_json::to_string(&proof).unwrap();
                let der_proof = serde_json::from_str::<CircomGroth16Proof<$curve>>(&ser_proof).unwrap();
                let vk: Groth16VK<$curve> = serde_json::from_reader(
                    File::open(format!("../test_vectors/{}/{}/{}/verification_key.json", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap(),
                )
                .unwrap();
                let vk = vk.into();
                let der_proof = der_proof.into();
                assert_eq!(der_proof, result2);
                Groth16::<$curve>::verify(&vk, &der_proof, &public_input).expect("can verify");
            }

            #[test]
            fn [< e2e_proof_verify_snarkjs_proof_ $name _ $curve:lower _ groth16>] () {
                let snarkjs_proof_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circom.proof", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap();
                let public_input_file =
                    File::open(format!("../test_vectors/{}/{}/{}/public.json", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap();
                let vk_file =
                    File::open(format!("../test_vectors/{}/{}/{}/verification_key.json", "Groth16", stringify!([< $curve:lower >]), $name)).unwrap();
                let vk: Groth16VK<$curve> = serde_json::from_reader(
                    vk_file,
                )
                .unwrap();
                let vk = vk.into();
                let public_input: JsonPublicInput::<[< ark_ $curve:lower >]::Fr> = serde_json::from_reader(public_input_file).unwrap();
                let snarkjs_proof: CircomGroth16Proof<$curve> = serde_json::from_reader(&snarkjs_proof_file).unwrap();
                let proof = snarkjs_proof.into();
                Groth16::<$curve>::verify(&vk, &proof, &public_input.values).expect("can verify");
            }
        }
    };
}

macro_rules! add_test_impl_plonk {
    ($curve: ident, $name: expr) => {
        paste::item! {
            #[test]
            fn [< e2e_proof_ $name _ $curve:lower _ plonk>] () {
                let zkey_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circuit.zkey", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap();
                let r1cs_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circuit.r1cs", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap();
                let witness_file =
                    File::open(format!("../test_vectors/{}/{}/{}/witness.wtns", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap();
                let witness = Witness::<[< ark_ $curve:lower >]::Fr>::from_reader(witness_file).unwrap();
                let zkey1 = PlonkZK::<$curve>::from_reader(zkey_file, CheckElement::No).unwrap();
                let zkey1 = Arc::new(zkey1);
                let zkey2 = Arc::clone(&zkey1);
                let zkey3 = Arc::clone(&zkey1);
                let r1cs = R1CS::<$curve>::from_reader(r1cs_file).unwrap();
                //ignore leading 1 for verification
                let public_input = witness.values[1..r1cs.num_inputs].to_vec();
                let mut rng = thread_rng();
                let witness_shares =
                    SharedWitness::share_shamir(witness, r1cs.num_inputs, 1, 3, &mut rng);
                let mut nets = vec![Vec::with_capacity(8), Vec::with_capacity(8), Vec::with_capacity(8)];
                for _ in 0..8 {
                    let [n0, n1, n2] = LocalNetwork::new_3_parties();
                    nets[0].push(n0);
                    nets[1].push(n1);
                    nets[2].push(n2);
                }
                let mut threads = vec![];
                for (nets, x, zkey) in izip!(
                    nets,
                    witness_shares.into_iter(),
                    [zkey1, zkey2, zkey3].into_iter()
                ) {
                    threads.push(std::thread::spawn(move || {
                        ShamirCoPlonk::<$curve>::prove(&nets.try_into().unwrap(), 3, 1, zkey, x).unwrap()
                    }));
                }
                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();
                assert_eq!(result1, result2);
                assert_eq!(result2, result3);
                let proof = PlonkProof::from(result1);
                let ser_proof = serde_json::to_string(&proof).unwrap();
                let der_proof = serde_json::from_str::<PlonkProof<$curve>>(&ser_proof).unwrap();
                let vk: PlonkVK<$curve> = serde_json::from_reader(
                    File::open(format!("../test_vectors/{}/{}/{}/verification_key.json", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap(),
                )
                .unwrap();
                assert_eq!(der_proof, result2);
                Plonk::<$curve>::verify(&vk, &der_proof, &public_input).expect("can verify");
            }

            #[test]
            fn [< e2e_proof_verify_snarkjs_proof_ $name _ $curve:lower _ plonk>] () {
                let snarkjs_proof_file =
                    File::open(format!("../test_vectors/{}/{}/{}/circom.proof", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap();
                let public_input_file =
                    File::open(format!("../test_vectors/{}/{}/{}/public.json", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap();
                let vk_file =
                    File::open(format!("../test_vectors/{}/{}/{}/verification_key.json", "Plonk", stringify!([< $curve:lower >]), $name)).unwrap();
                let vk: PlonkVK<$curve> = serde_json::from_reader(
                    vk_file,
                )
                .unwrap();
                let public_input: JsonPublicInput::<[< ark_ $curve:lower >]::Fr> = serde_json::from_reader(public_input_file).unwrap();
                let snarkjs_proof: PlonkProof<$curve> = serde_json::from_reader(&snarkjs_proof_file).unwrap();
                Plonk::<$curve>::verify(&vk, &snarkjs_proof, &public_input.values).expect("can verify");
            }
        }
    };
}

e2e_test!("multiplier2");
e2e_test!("poseidon");
