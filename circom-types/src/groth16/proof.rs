//! This module defines the [`Groth16Proof`] struct that implements de/serialization using [`serde`].
use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use ark_ec::pairing::Pairing;
use serde::{Deserialize, Serialize};

/// Represents a Groth16 proof in JSON format that was created by circom. Supports de/serialization using [`serde`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16Proof<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Proof element A (or 1) in G1
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub pi_a: P::G1Affine,
    /// Proof element B (or 2) in G2
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    pub pi_b: P::G2Affine,
    /// Proof element C (or 3) in G1
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub pi_c: P::G1Affine,
    /// The protocol used to generate the proof (always `"groth16"`)
    pub protocol: String,
    /// The curve used to generate the proof
    pub curve: String,
}
#[cfg(test)]
mod tests {
    use crate::groth16::test_utils;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    use std::{fs, str::FromStr};

    #[test]
    pub fn deserialize_bn254_proof() {
        let proof_string =
            fs::read_to_string("../test_vectors/Groth16/bn254/multiplier2/proof.json").unwrap();
        let proof = serde_json::from_str::<Groth16Proof<Bn254>>(&proof_string).unwrap();

        let pi_a = test_utils::to_g1_bn254!(
            "5969123522090814361171588228229368332719697989145919311329989202301051796912",
            "18906266273883421538550545870389760028232642993789046435548759958047513826466"
        );
        let pi_b = test_utils::to_g2_bn254!(
            { "13732822754685216699494313130307949314358351264391615026657641877459312805921", "15242155868134051061519617910834758681213622395767565233201715494163382082631"},
            { "6040988303910179137905227500476692522731546381459192177262195830159275686930", "6102931310051425482112222546940021723264293724138375749141717027794878004116"}
        );
        let pi_c = test_utils::to_g1_bn254!(
            "8027438340805100823503975850514290391260085605647857333256305214246713987397",
            "17368354082387796246978493062684369586080079518888794624836970993708830684295"
        );
        assert_eq!(pi_a, proof.pi_a);
        assert_eq!(pi_b, proof.pi_b);
        assert_eq!(pi_c, proof.pi_c);
        assert_eq!("groth16", proof.protocol);
        assert_eq!("bn128", proof.curve);
        //serialize and deserialize and check for equality
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<Groth16Proof<Bn254>>(&ser_proof).unwrap();
        assert_eq!(der_proof, proof);
    }

    #[test]
    pub fn deserialize_bls12_381_proof() {
        let proof_string =
            fs::read_to_string("../test_vectors/Groth16/bls12_381/proof.json").unwrap();
        let proof = serde_json::from_str::<Groth16Proof<Bls12_381>>(&proof_string).unwrap();

        let pi_a = test_utils::to_g1_bls12_381!(
            "2813585902014243229521635712428097947930461922931227160162435763779471002056411796676626370855763256659769027518815",
            "1075249136892464767280670101672294034222581368912584908444034334165470693799208384000038312705129339274385058946941"
        );
        let pi_b = test_utils::to_g2_bls12_381!(
            { "2069575146125513370719986136489769805947797918358013181795267531051218058674271318822695530256502887287951592324356", "3416333842890244671922490626591621420038219774941802756286778773629437562082374100069865625099021273446902242714759"},
            { "1438442598849687110102191433682477593951892217267878213959340014574382987971877787036275175997065538230648149315373", "32085737806097963437306341712668191804836047643955771093081629310654488326260359800432950017960150507741895184109"}
        );
        let pi_c = test_utils::to_g1_bls12_381!(
            "3952408895266918207190055696713595108319034555321205066315435460571191392383205902562242862428705903108447944687220",
            "3201619144773405291669320922230950128989560123172104039158720835089705716439047007883166824402803608411295437206929"
        );
        assert_eq!(pi_a, proof.pi_a);
        assert_eq!(pi_b, proof.pi_b);
        assert_eq!(pi_c, proof.pi_c);
        assert_eq!("groth16", proof.protocol);
        assert_eq!("bls12381", proof.curve);
        //serialize and deserialize and check for equality
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<Groth16Proof<Bls12_381>>(&ser_proof).unwrap();
        assert_eq!(der_proof, proof);
    }
}
