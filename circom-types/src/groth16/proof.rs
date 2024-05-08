use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_groth16::Proof;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonProof<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub pi_a: P::G1Affine,
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    pub pi_b: P::G2Affine,
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub pi_c: P::G1Affine,
    pub protocol: String,
    pub curve: String,
}

impl From<Proof<Bn254>> for JsonProof<Bn254> {
    fn from(proof: Proof<Bn254>) -> Self {
        Self {
            pi_a: proof.a,
            pi_b: proof.b,
            pi_c: proof.c,
            protocol: "groth16".to_owned(),
            //name for bn254 in circom
            curve: "bn128".to_owned(),
        }
    }
}

impl From<Proof<Bls12_381>> for JsonProof<Bls12_381> {
    fn from(proof: Proof<Bls12_381>) -> Self {
        Self {
            pi_a: proof.a,
            pi_b: proof.b,
            pi_c: proof.c,
            protocol: "groth16".to_owned(),
            //name for bn254 in circom
            curve: "bls12381".to_owned(),
        }
    }
}

impl From<JsonProof<Bn254>> for Proof<Bn254> {
    fn from(proof: JsonProof<Bn254>) -> Self {
        Self {
            a: proof.pi_a,
            b: proof.pi_b,
            c: proof.pi_c,
        }
    }
}
impl From<JsonProof<Bls12_381>> for Proof<Bls12_381> {
    fn from(proof: JsonProof<Bls12_381>) -> Self {
        Self {
            a: proof.pi_a,
            b: proof.pi_b,
            c: proof.pi_c,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::groth16::test_utils;

    use super::*;
    use ark_bn254::Bn254;

    use std::{fs, str::FromStr};

    #[test]
    pub fn deserialize_bn254_proof() {
        let proof_string =
            fs::read_to_string("../test_vectors/bn254/multiplier2/proof.json").unwrap();
        let proof = serde_json::from_str::<JsonProof<Bn254>>(&proof_string).unwrap();

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
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        assert_eq!(der_proof, proof);
    }

    #[test]
    pub fn deserialize_bls12_381_proof() {
        let proof_string = fs::read_to_string("../test_vectors/bls12_381/proof.json").unwrap();
        let proof = serde_json::from_str::<JsonProof<Bls12_381>>(&proof_string).unwrap();

        let pi_a = test_utils::to_g1_bls12_381!(
            "3161908979679926775128680944679071538745668002759034646131533136353064954005207254318668644456284173469805968760274",
            "943532593826252599737807200249476533359927971490538961858149123202081401871540707106656046130958338623945663626186"
        );
        let pi_b = test_utils::to_g2_bls12_381!(
            { "85742549345889893344331842994640794112074584516319753815005105901943370689030168831914548108571635575039924477416", "2063309714137674670006939489787775864259991675287387397189721335446383640772638846295890366681817369960896191805235"},
            { "3053148004559350767943052136550141887203994601729754546425724209793793539928689518983148456450556212804554999358511", "1581626384968579936893743628431111753581369267581383758121072848336003852123314656974102655036991831468665961439542"}
        );
        let pi_c = test_utils::to_g1_bls12_381!(
            "2811305345295781817348529691522124392970009024849953436593888697060068799640479394087216974900674885681117393183827",
            "397872111509223241450298082121548199971453357182782398995856142185115769297556208956572080598498776953969788363251"
        );
        assert_eq!(pi_a, proof.pi_a);
        assert_eq!(pi_b, proof.pi_b);
        assert_eq!(pi_c, proof.pi_c);
        assert_eq!("groth16", proof.protocol);
        assert_eq!("bls12381", proof.curve);
        //serialize and deserialize and check for equality
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bls12_381>>(&ser_proof).unwrap();
        assert_eq!(der_proof, proof);
    }
}
