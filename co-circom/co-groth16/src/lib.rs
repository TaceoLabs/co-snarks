//! A library for creating and verifying Groth16 proofs in a collaborative fashion using MPC.
#![warn(missing_docs)]
mod groth16;
/// This module contains the Groth16 prover trait
pub mod mpc;
#[cfg(feature = "verifier")]
mod verifier;

pub use groth16::{
    CircomReduction, CoGroth16, Groth16, LibSnarkReduction, R1CSToQAP, Rep3CoGroth16,
    ShamirCoGroth16,
};

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};
pub use ark_relations::r1cs::ConstraintMatrices;

#[cfg(test)]
#[cfg(feature = "verifier")]
mod tests {
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_groth16::{ProvingKey, VerifyingKey};
    use ark_relations::r1cs::{ConstraintMatrices, Matrix};
    use ark_serialize::CanonicalDeserialize;
    use circom_types::{
        groth16::{CircomGroth16Proof, JsonPublicInput, JsonVerificationKey, ZKey},
        traits::CheckElement,
        Witness,
    };
    use co_circom_snarks::SharedWitness;
    use std::fs::{self, File};

    use crate::{groth16::Groth16, CircomReduction, LibSnarkReduction};

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
            let zkey = ZKey::<Bn254>::from_reader(zkey_file, check).unwrap();
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

        Groth16::<Bn254>::verify(&vk, &proof, &public_input.values).expect("can verify");
    }

    #[test]
    fn create_proof_and_verify_poseidon_hash_bn254() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let zkey_file =
                File::open("../../test_vectors/Groth16/bn254/poseidon/circuit.zkey").unwrap();
            let witness_file =
                File::open("../../test_vectors/Groth16/bn254/poseidon/witness.wtns").unwrap();
            let vk_file =
                File::open("../../test_vectors/Groth16/bn254/poseidon/verification_key.json")
                    .unwrap();
            let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
            let zkey = ZKey::<Bn254>::from_reader(zkey_file, check).unwrap();
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
        Groth16::verify(&vk, &proof, &public_input.values).expect("can verify");
    }

    #[test]
    fn verify_circom_proof_bls12_381() {
        let vk_string = fs::read_to_string(
            "../../test_vectors/Groth16/bls12_381/multiplier2/verification_key.json",
        )
        .unwrap();
        let public_string = "[\"33\"]";
        let proof_string =
            fs::read_to_string("../../test_vectors/Groth16/bls12_381/multiplier2/circom.proof")
                .unwrap();

        let vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&vk_string).unwrap();
        let vk = vk.into();
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bls12_381::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<CircomGroth16Proof<Bls12_381>>(&proof_string).unwrap();
        let proof = proof.into();
        Groth16::<Bls12_381>::verify(&vk, &proof, &public_input.values).expect("can verify");
    }

    #[test]
    fn proof_circom_proof_bls12_381() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let zkey_file =
                File::open("../../test_vectors/Groth16/bls12_381/multiplier2/circuit.zkey")
                    .unwrap();
            let witness_file =
                File::open("../../test_vectors/Groth16/bls12_381/multiplier2/witness.wtns")
                    .unwrap();
            let vk_file = File::open(
                "../../test_vectors/Groth16/bls12_381/multiplier2/verification_key.json",
            )
            .unwrap();
            let witness = Witness::<ark_bls12_381::Fr>::from_reader(witness_file).unwrap();
            let zkey = ZKey::<Bls12_381>::from_reader(zkey_file, check).unwrap();
            let (matrices, pkey) = zkey.into();
            let vk: JsonVerificationKey<Bls12_381> = serde_json::from_reader(vk_file).unwrap();
            let vk = vk.into();
            let public_input = witness.values[..matrices.num_instance_variables].to_vec();
            let witness = SharedWitness {
                public_inputs: public_input.clone(),
                witness: witness.values[matrices.num_instance_variables..].to_vec(),
            };

            let proof =
                Groth16::<Bls12_381>::plain_prove::<CircomReduction>(&pkey, &matrices, witness)
                    .expect("proof generation works");
            Groth16::<Bls12_381>::verify(&vk, &proof, &public_input[1..]).expect("can verify");
            let proof = CircomGroth16Proof::from(proof);
            let ser_proof = serde_json::to_string(&proof).unwrap();
            let der_proof =
                serde_json::from_str::<CircomGroth16Proof<Bls12_381>>(&ser_proof).unwrap();
            let der_proof = der_proof.into();
            Groth16::<Bls12_381>::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        }
    }

    #[test]
    fn proof_circom_proof_bn254() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let zkey_file =
                File::open("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey").unwrap();
            let witness_file =
                File::open("../../test_vectors/Groth16/bn254/multiplier2/witness.wtns").unwrap();
            let vk_file =
                File::open("../../test_vectors/Groth16/bn254/multiplier2/verification_key.json")
                    .unwrap();
            let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
            let zkey = ZKey::<Bn254>::from_reader(zkey_file, check).unwrap();
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
            Groth16::<Bn254>::verify(&vk, &proof, &public_input[1..]).expect("can verify");
            let proof = CircomGroth16Proof::from(proof);
            let ser_proof = serde_json::to_string(&proof).unwrap();
            let der_proof = serde_json::from_str::<CircomGroth16Proof<Bn254>>(&ser_proof).unwrap();
            let der_proof = der_proof.into();
            Groth16::<Bn254>::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        }
    }

    fn proof_libsnark_penumbra_bls12_377(circuit: &str) {
        let pkey_file = File::open(format!(
            "../../test_vectors/Groth16/bls12_377/{circuit}/circuit.pk"
        ))
        .unwrap();
        let a_file = File::open(format!(
            "../../test_vectors/Groth16/bls12_377/{circuit}/a.bin"
        ))
        .unwrap();
        let b_file = File::open(format!(
            "../../test_vectors/Groth16/bls12_377/{circuit}/b.bin"
        ))
        .unwrap();
        let c_file = File::open(format!(
            "../../test_vectors/Groth16/bls12_377/{circuit}/c.bin"
        ))
        .unwrap();
        let witness_file = File::open(format!(
            "../../test_vectors/Groth16/bls12_377/{circuit}/witness.wtns"
        ))
        .unwrap();
        let vk_file = File::open(format!(
            "../../test_vectors/Groth16/bls12_377/{circuit}/circuit.vk"
        ))
        .unwrap();
        let witness = Witness::<ark_bls12_377::Fr>::from_reader(witness_file).unwrap();
        let pkey = ProvingKey::<Bls12_377>::deserialize_uncompressed_unchecked(pkey_file).unwrap();
        // TODO once we can serde ConstraintMatrices, we dont need to do this anymore
        let a = Matrix::<ark_bls12_377::Fr>::deserialize_uncompressed(a_file).unwrap();
        let b = Matrix::<ark_bls12_377::Fr>::deserialize_uncompressed(b_file).unwrap();
        let c = Matrix::<ark_bls12_377::Fr>::deserialize_uncompressed(c_file).unwrap();
        let matrices = ConstraintMatrices {
            num_instance_variables: pkey.b_g1_query.len() - pkey.l_query.len(),
            num_witness_variables: pkey.a_query.len(),
            num_constraints: a.len(),
            a_num_non_zero: a.len(),
            b_num_non_zero: b.len(),
            c_num_non_zero: c.len(),
            a,
            b,
            c,
        };

        let vk = VerifyingKey::<Bls12_377>::deserialize_uncompressed_unchecked(vk_file).unwrap();
        let public_input = witness.values[..matrices.num_instance_variables].to_vec();
        let witness = SharedWitness {
            public_inputs: public_input.clone(),
            witness: witness.values[matrices.num_instance_variables..].to_vec(),
        };

        let proof =
            Groth16::<Bls12_377>::plain_prove::<LibSnarkReduction>(&pkey, &matrices, witness)
                .expect("proof generation works");
        Groth16::<Bls12_377>::verify(&vk, &proof, &public_input[1..]).expect("can verify");
    }

    #[test]
    fn proof_libsnark_penumbra_spend_bls12_377() {
        proof_libsnark_penumbra_bls12_377("penumbra_spend");
    }

    #[test]
    fn proof_libsnark_penumbra_output_bls12_377() {
        proof_libsnark_penumbra_bls12_377("penumbra_output");
    }

    #[test]
    fn proof_libsnark_penumbra_delegator_vote_bls12_377() {
        proof_libsnark_penumbra_bls12_377("penumbra_delegator_vote");
    }
}
