//! A library for creating and verifying Groth16 proofs in a collaborative fashion using MPC.
#![warn(missing_docs)]
mod groth16_gpu;

pub mod bridges;
mod gpu_utils;
/// This module contains the Groth16 prover trait
pub mod mpc;
mod verifier;

pub use groth16_gpu::{CircomReduction, Groth16, R1CSToQAP};

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};
pub use ark_relations::r1cs::ConstraintMatrices;

#[cfg(test)]
mod tests {

    use ark_bn254::Bn254;

    use circom_types::{
        CheckElement, Witness,
        groth16::{Proof as CircomGroth16Proof, VerificationKey as JsonVerificationKey, Zkey},
    };
    use co_circom_types::SharedWitness;

    use icicle_snark::CacheManager;
    use std::fs::File;

    use crate::{CircomReduction, groth16_gpu::Groth16};

    #[test]
    fn create_proof_and_verify_bn254() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let zkey_file =
                File::open("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey").unwrap();
            let witness_file =
                File::open("../../test_vectors/Groth16/bn254/multiplier2/witness.wtns").unwrap();
            let vk_file =
                File::open("../../test_vectors/Groth16/bn254/multiplier2/verification_key.json")
                    .unwrap();

            let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
            let zkey = Zkey::<Bn254>::from_reader(zkey_file, check).unwrap();
            let (matrices, pkey) = zkey.into();
            let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(vk_file).unwrap();
            let vk = vk.into();
            let public_input = witness.values[..matrices.num_instance_variables].to_vec();
            let witness = SharedWitness {
                public_inputs: public_input.clone(),
                witness: witness.values[matrices.num_instance_variables..].to_vec(),
            };
            let proof: ark_groth16::Proof<ark_ec::bn::Bn<ark_bn254::Config>> =
                Groth16::<Bn254>::plain_prove::<CircomReduction>(&pkey, &matrices, witness)
                    .expect("proof generation works");
            let proof = CircomGroth16Proof::from(proof);
            let ser_proof = serde_json::to_string(&proof).unwrap();
            let der_proof = serde_json::from_str::<CircomGroth16Proof<Bn254>>(&ser_proof).unwrap();
            let der_proof = der_proof.into();
            Groth16::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        }
    }

    #[test]
    fn create_proof_and_verify_poseidon_hash_bn254() {
        for check in [CheckElement::Yes; 10000] {
            let zkey_file =
                File::open("../../test_vectors/Groth16/bn254/poseidon/circuit.zkey").unwrap();
            let witness_file =
                File::open("../../test_vectors/Groth16/bn254/poseidon/witness.wtns").unwrap();
            let vk_file =
                File::open("../../test_vectors/Groth16/bn254/poseidon/verification_key.json")
                    .unwrap();

            let timer_start = std::time::Instant::now();
            icicle_snark::groth16_prove(
                "../../test_vectors/Groth16/bn254/poseidon/witness.wtns",
                "../../test_vectors/Groth16/bn254/poseidon/circuit.zkey",
                "proof.proof",
                "../../test_vectors/Groth16/bn254/poseidon/public.json",
                "CUDA",
                &mut CacheManager::default(),
            )
            .unwrap();
            println!(
                "GPU proof generation with icicle took: {:?}",
                timer_start.elapsed()
            );

            let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
            let zkey = Zkey::<Bn254>::from_reader(zkey_file, check).unwrap();
            let (matrices, pkey) = zkey.into();
            let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(vk_file).unwrap();
            let vk = vk.into();
            let public_input = witness.values[..matrices.num_instance_variables].to_vec();
            let witness = SharedWitness {
                public_inputs: public_input.clone(),
                witness: witness.values[matrices.num_instance_variables..].to_vec(),
            };
            let proof = Groth16::<Bn254>::plain_prove::<CircomReduction>(&pkey, &matrices, witness)
                .expect("proof generation works");
            let proof = CircomGroth16Proof::from(proof);
            let ser_proof = serde_json::to_string(&proof).unwrap();
            let der_proof = serde_json::from_str::<CircomGroth16Proof<Bn254>>(&ser_proof).unwrap();
            let der_proof = der_proof.into();
            Groth16::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        }
    }
}
