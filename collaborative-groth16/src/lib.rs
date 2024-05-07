mod circom_reduction;
pub mod circuit;
mod collab_reduction;
pub mod groth16;
pub mod groth16_proof_with_assignment;

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_ff::UniformRand;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use circom_types::{
        groth16::{
            proof::JsonProof, public_input::JsonPublicInput, verification_key::JsonVerificationKey,
            witness::Witness, zkey::ZKey,
        },
        r1cs::R1CS,
    };
    use rand::thread_rng;
    use std::fs::{self, File};

    use crate::{circom_reduction::CircomReduction, circuit::Circuit};

    #[test]
    fn create_proof_and_verify_bn254() {
        let zkey_file = File::open("../test_vectors/bn254/multiplier2.zkey").unwrap();
        let witness_file = File::open("../test_vectors/bn254/witness.wtns").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/multiplier2.r1cs").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let (pk, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
        let r1cs = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        let circuit = Circuit::new(r1cs, witness);
        let public_inputs = circuit.public_inputs();
        let mut rng = thread_rng();
        let r = <Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let s = <Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let proof =
            Groth16::<Bn254, CircomReduction>::create_proof_with_reduction(circuit, &pk, r, s)
                .expect("proof generation works");
        let pvk = prepare_verifying_key(&pk.vk);
        let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(proof)).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        let verified = Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &public_inputs)
            .expect("can verify");
        assert!(verified);
    }

    #[test]
    fn verify_circom_proof_bn254() {
        let vk_string = fs::read_to_string("../test_vectors/bn254/verification_key.json").unwrap();
        let public_string = "[\"33\"]";
        let proof_string = fs::read_to_string("../test_vectors/bn254/proof.json").unwrap();

        let vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&vk_string).unwrap();
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<JsonProof<Bn254>>(&proof_string).unwrap();
        let pvk = vk.prepare_verifying_key();
        let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof.into(), &public_input.values)
            .expect("can verify");
        assert!(verified)
    }

    #[test]
    fn verify_circom_proof_bls12_381() {
        let vk_string =
            fs::read_to_string("../test_vectors/bls12_381/verification_key.json").unwrap();
        let public_string = "[\"33\"]";
        let proof_string = fs::read_to_string("../test_vectors/bls12_381/proof.json").unwrap();

        let vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&vk_string).unwrap();
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bls12_381::Fr>>(public_string).unwrap();
        let proof = serde_json::from_str::<JsonProof<Bls12_381>>(&proof_string).unwrap();
        let pvk = vk.prepare_verifying_key();
        let verified =
            Groth16::<Bls12_381>::verify_proof(&pvk, &proof.into(), &public_input.values)
                .expect("can verify");
        assert!(verified)
    }

    //this does not work. See https://github.com/TaceoLabs/collaborative-circom/issues/10
    #[ignore]
    #[test]
    fn proof_circom_proof_bls12_381() {
        let zkey_file = File::open("../test_vectors/bls12_381/multiplier2.zkey").unwrap();
        let witness_file = File::open("../test_vectors/bls12_381/witness.wtns").unwrap();
        let r1cs_file = File::open("../test_vectors/bls12_381/multiplier2.r1cs").unwrap();
        let witness = Witness::<ark_bls12_381::Fr>::from_reader(witness_file).unwrap();
        let (pk, _) = ZKey::<Bls12_381>::from_reader(zkey_file).unwrap().split();
        let r1cs = R1CS::<Bls12_381>::from_reader(r1cs_file).unwrap();
        let circuit = Circuit::new(r1cs, witness);
        let public_inputs = circuit.public_inputs();
        let mut rng = thread_rng();
        let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let s = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let proof =
            Groth16::<Bls12_381, CircomReduction>::create_proof_with_reduction(circuit, &pk, r, s)
                .expect("proof generation works");
        let pvk = prepare_verifying_key(&pk.vk);
        let verified =
            Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &public_inputs).expect("can verify");
        assert!(verified);
        let ser_proof = serde_json::to_string(&JsonProof::<Bls12_381>::from(proof)).unwrap();
        //fs::write(Path::new("my_cool_proof1.json"), test.clone()).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bls12_381>>(&ser_proof).unwrap();
        let verified = Groth16::<Bls12_381>::verify_proof(&pvk, &der_proof.into(), &public_inputs)
            .expect("can verify");
        assert!(verified)
    }

    #[test]
    fn proof_circom_proof_bn254() {
        let zkey_file = File::open("../test_vectors/bn254/multiplier2.zkey").unwrap();
        let witness_file = File::open("../test_vectors/bn254/witness.wtns").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/multiplier2.r1cs").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let (pk, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
        let r1cs = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        let circuit = Circuit::new(r1cs, witness);
        let public_inputs = circuit.public_inputs();
        let mut rng = thread_rng();
        let r = <Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let s = <Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let proof =
            Groth16::<Bn254, CircomReduction>::create_proof_with_reduction(circuit, &pk, r, s)
                .expect("proof generation works");
        let pvk = prepare_verifying_key(&pk.vk);
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).expect("can verify");
        assert!(verified);
        let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(proof)).unwrap();
        //fs::write(Path::new("my_cool_proof1.json"), test.clone()).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        let verified = Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &public_inputs)
            .expect("can verify");
        assert!(verified);
    }
}
