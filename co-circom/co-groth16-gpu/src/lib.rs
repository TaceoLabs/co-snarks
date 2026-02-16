//! A library for creating and verifying Groth16 proofs in a collaborative fashion using MPC.
#![warn(missing_docs)]
mod groth16_gpu;

/// This module contains the Groth16 prover trait
pub mod mpc;
mod gpu_utils;
pub mod bridges;
mod verifier;

pub use groth16_gpu::{
    Groth16, CircomReduction, R1CSToQAP,
};

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};
pub use ark_relations::r1cs::ConstraintMatrices;

#[cfg(test)]
mod tests {
    use ark_bls12_377::{Bls12_377, G1Affine};
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_groth16::{ProvingKey, VerifyingKey};
    use ark_relations::r1cs::{ConstraintMatrices, Matrix};
    use ark_serialize::CanonicalDeserialize;
    use circom_types::{
        CheckElement, Witness,
        groth16::{
            Proof as CircomGroth16Proof, PublicInput as JsonPublicInput,
            VerificationKey as JsonVerificationKey, Zkey,
        },
    };
    use icicle_bn254::curve::ScalarField;
    use icicle_core::{bignum::BigNum, ecntt::Projective, negacyclic_ntt::{self, NegacyclicNttConfig}, ntt::{self, NTTConfig, initialize_domain}};
    use icicle_runtime::{Device, memory::HostSlice, runtime};
    use co_circom_types::SharedWitness;
    use std::fs::{self, File};

    use icicle_bn254::curve::{ G1Projective};
    use icicle_core::{msm, msm::MSMConfig, traits::GenerateRandom};

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
            let proof: ark_groth16::Proof<ark_ec::bn::Bn<ark_bn254::Config>> = Groth16::<Bn254>::plain_prove::<CircomReduction>(&pkey, &matrices, witness)
                .expect("proof generation works");
            let proof = CircomGroth16Proof::from(proof);
            let ser_proof = serde_json::to_string(&proof).unwrap();
            let der_proof = serde_json::from_str::<CircomGroth16Proof<Bn254>>(&ser_proof).unwrap();
            let der_proof = der_proof.into();
            Groth16::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        }
    }

    #[test]
    fn verify_circom_proof_bn254() {
        let vk_string = fs::read_to_string(
            "../../test_vectors/Groth16/bn254/multiplier2/verification_key.json",
        )
        .unwrap();
        let public_string = "[\"33\"]";
        let proof_string =
            fs::read_to_string("../../test_vectors/Groth16/bn254/multiplier2/circom.proof")
                .unwrap();

        let vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&vk_string).unwrap();
        let vk = vk.into();
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<CircomGroth16Proof<Bn254>>(&proof_string).unwrap();
        let proof = proof.into();

        Groth16::<Bn254>::verify(&vk, &proof, &public_input.0).expect("can verify");
    }

    #[test]
    fn verify_circom_proof_poseidon_bn254() {
        let vk_string =
            fs::read_to_string("../../test_vectors/Groth16/bn254/poseidon/verification_key.json")
                .unwrap();
        let public_string = "[
            \"17853941289740592551682164141790101668489478619664963356488634739728685875777\"
           ]";
        let proof_string =
            fs::read_to_string("../../test_vectors/Groth16/bn254/poseidon/circom.proof").unwrap();

        let vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&vk_string).unwrap();
        let vk = vk.into();
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<CircomGroth16Proof<Bn254>>(&proof_string).unwrap();
        let proof = proof.into();
        Groth16::verify(&vk, &proof, &public_input.0).expect("can verify");
    }
}
