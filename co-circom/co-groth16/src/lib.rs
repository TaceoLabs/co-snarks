//! A library for creating and verifying Groth16 proofs in a collaborative fashion using MPC.
#![warn(missing_docs)]
mod groth16;
mod mpc;
#[cfg(feature = "verifier")]
mod verifier;

pub use groth16::CoGroth16;
pub use groth16::Groth16;
pub use groth16::Rep3CoGroth16;

#[cfg(test)]
#[cfg(feature = "verifier")]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use circom_types::{
        groth16::{Groth16Proof, JsonPublicInput, JsonVerificationKey, ZKey},
        Witness,
    };
    use co_circom_snarks::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;
    use std::fs::{self, File};

    use crate::groth16::Groth16;

    #[test]
    fn create_proof_and_verify_bn254() {
        let zkey_file =
            File::open("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey").unwrap();
        let witness_file =
            File::open("../../test_vectors/Groth16/bn254/multiplier2/witness.wtns").unwrap();
        let vk_file =
            File::open("../../test_vectors/Groth16/bn254/multiplier2/verification_key.json")
                .unwrap();

        let driver = PlainDriver::<ark_bn254::Fr>::default();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let zkey = ZKey::<Bn254>::from_reader(zkey_file).unwrap();
        let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(vk_file).unwrap();
        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };
        let mut groth16 = Groth16::<Bn254>::new(driver);
        let proof = groth16
            .prove(&zkey, witness)
            .expect("proof generation works");
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<Groth16Proof<Bn254>>(&ser_proof).unwrap();
        let verified = Groth16::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        assert!(verified);
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
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<Groth16Proof<Bn254>>(&proof_string).unwrap();
        let verified =
            Groth16::<Bn254>::verify(&vk, &proof, &public_input.values).expect("can verify");
        assert!(verified)
    }

    #[test]
    fn create_proof_and_verify_poseidon_hash_bn254() {
        let zkey_file =
            File::open("../../test_vectors/Groth16/bn254/poseidon/circuit.zkey").unwrap();
        let witness_file =
            File::open("../../test_vectors/Groth16/bn254/poseidon/witness.wtns").unwrap();
        let driver = PlainDriver::<ark_bn254::Fr>::default();
        let vk_file =
            File::open("../../test_vectors/Groth16/bn254/poseidon/verification_key.json").unwrap();

        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let zkey = ZKey::<Bn254>::from_reader(zkey_file).unwrap();
        let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(vk_file).unwrap();
        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };
        let mut groth16 = Groth16::<Bn254>::new(driver);
        let proof = groth16
            .prove(&zkey, witness)
            .expect("proof generation works");
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<Groth16Proof<Bn254>>(&ser_proof).unwrap();
        let verified = Groth16::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        assert!(verified);
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
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<Groth16Proof<Bn254>>(&proof_string).unwrap();
        let verified = Groth16::verify(&vk, &proof, &public_input.values).expect("can verify");
        assert!(verified)
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
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bls12_381::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<Groth16Proof<Bls12_381>>(&proof_string).unwrap();
        let verified =
            Groth16::<Bls12_381>::verify(&vk, &proof, &public_input.values).expect("can verify");
        assert!(verified)
    }

    #[test]
    fn proof_circom_proof_bls12_381() {
        let zkey_file =
            File::open("../../test_vectors/Groth16/bls12_381/multiplier2/circuit.zkey").unwrap();
        let witness_file =
            File::open("../../test_vectors/Groth16/bls12_381/multiplier2/witness.wtns").unwrap();
        let vk_file =
            File::open("../../test_vectors/Groth16/bls12_381/multiplier2/verification_key.json")
                .unwrap();
        let witness = Witness::<ark_bls12_381::Fr>::from_reader(witness_file).unwrap();
        let zkey = ZKey::<Bls12_381>::from_reader(zkey_file).unwrap();
        let vk: JsonVerificationKey<Bls12_381> = serde_json::from_reader(vk_file).unwrap();
        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bls12_381::Fr>, Bls12_381> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };

        let driver = PlainDriver::<ark_bls12_381::Fr>::default();
        let mut groth16 = Groth16::<Bls12_381>::new(driver);
        let proof = groth16
            .prove(&zkey, witness)
            .expect("proof generation works");
        let verified =
            Groth16::<Bls12_381>::verify(&vk, &proof, &public_input[1..]).expect("can verify");
        assert!(verified);
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<Groth16Proof<Bls12_381>>(&ser_proof).unwrap();
        let verified =
            Groth16::<Bls12_381>::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        assert!(verified)
    }

    #[test]
    fn proof_circom_proof_bn254() {
        let zkey_file =
            File::open("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey").unwrap();
        let witness_file =
            File::open("../../test_vectors/Groth16/bn254/multiplier2/witness.wtns").unwrap();
        let vk_file =
            File::open("../../test_vectors/Groth16/bn254/multiplier2/verification_key.json")
                .unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let zkey = ZKey::<Bn254>::from_reader(zkey_file).unwrap();
        let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(vk_file).unwrap();
        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };

        let driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut groth16 = Groth16::<Bn254>::new(driver);
        let proof = groth16
            .prove(&zkey, witness)
            .expect("proof generation works");
        let verified =
            Groth16::<Bn254>::verify(&vk, &proof, &public_input[1..]).expect("can verify");
        assert!(verified);
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<Groth16Proof<Bn254>>(&ser_proof).unwrap();
        let verified =
            Groth16::<Bn254>::verify(&vk, &der_proof, &public_input[1..]).expect("can verify");
        assert!(verified)
    }
}
