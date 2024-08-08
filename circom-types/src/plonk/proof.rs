//! This module defines the [`PlonkProof`] in circom's format. It implements de/serialization using [`serde`].

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use ark_ec::pairing::Pairing;
use ark_serialize::{SerializationError, Valid};
use serde::{Deserialize, Serialize};

/// Represents a Plonk proof that was created by circom. Supports de/serialization using [`serde`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlonkProof<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Proof element A (or 1)
    #[serde(rename = "A")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub a: P::G1Affine,
    /// Proof element B (or 2)
    #[serde(rename = "B")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub b: P::G1Affine,
    /// Proof element C (or 3)
    #[serde(rename = "C")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub c: P::G1Affine,
    #[serde(rename = "Z")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    /// Proof element Z
    pub z: P::G1Affine,
    #[serde(rename = "T1")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    /// Proof element T1
    pub t1: P::G1Affine,
    #[serde(rename = "T2")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    /// Proof element T2
    pub t2: P::G1Affine,
    #[serde(rename = "T3")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    /// Proof element T3
    pub t3: P::G1Affine,
    #[serde(rename = "Wxi")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    /// Proof element Wxi
    pub wxi: P::G1Affine,
    #[serde(rename = "Wxiw")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    /// Proof element Wxiw
    pub wxiw: P::G1Affine,
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    /// Proof element eval_a
    pub eval_a: P::ScalarField,
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    /// Proof element eval_b
    pub eval_b: P::ScalarField,
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    /// Proof element eval_c
    pub eval_c: P::ScalarField,
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    /// Proof element eval_s1
    pub eval_s1: P::ScalarField,
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    /// Proof element eval_s2
    pub eval_s2: P::ScalarField,
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    /// Proof element eval_zw
    pub eval_zw: P::ScalarField,
    /// The protocol used to generate the proof
    pub protocol: String,
    /// The curve used to generate the proof
    pub curve: String,
}

impl<P: Pairing + CircomArkworksPairingBridge> PlonkProof<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// This function checks whether the group elements are valid.
    pub fn is_well_constructed(&self) -> Result<(), SerializationError> {
        self.a.check()?;
        self.b.check()?;
        self.c.check()?;
        self.z.check()?;
        self.t1.check()?;
        self.t2.check()?;
        self.t3.check()?;
        self.wxi.check()?;
        self.wxiw.check()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::plonk::test_utils;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    use std::{fs, str::FromStr};

    #[test]
    pub fn deserialize_bn254_proof() {
        let proof_string =
            fs::read_to_string("../test_vectors/Plonk/bn254/multiplierAdd2/proof.json").unwrap();
        let proof = serde_json::from_str::<PlonkProof<Bn254>>(&proof_string).unwrap();

        let a = test_utils::to_g1_bn254!(
            "3576296322454829680846124704164634815293912035423112807141710436614198319140",
            "17434686986782480093322770867959193198226159550136733752733700031714311381305"
        );
        let b = test_utils::to_g1_bn254!(
            "18681003315242488778015178023205075467745501164417519811291335381746413168240",
            "21724502338114049274860973172806666184189142261450605616562439878100471397115"
        );
        let c = test_utils::to_g1_bn254!(
            "19839679564920734609871127025893899164579396067537932515462659795441949359137",
            "20356466467530210483192208580170627320431819547178386368589483870555207074476"
        );
        let z = test_utils::to_g1_bn254!(
            "9065488517106626395974600404380072232252816099596599554572758113056303502095",
            "17675933016697661003787037227814114299197006219978205486530480704684143567421"
        );
        let t1 = test_utils::to_g1_bn254!(
            "20673756723461688791221037459431236042712084290214566201576915061603065988397",
            "8953493347095476791740335881608041032928302882802131619696215025427300411175"
        );
        let t2 = test_utils::to_g1_bn254!(
            "10361510634877369565862233442709639089958128050987044821769626126846879122372",
            "8410846959805368239144340824600345927867136851099382053575951345240574004073"
        );
        let t3 = test_utils::to_g1_bn254!(
            "11857255209265365878724958529066724833751405148371565225625051698797774223393",
            "13470927903414485497487066467032911822952913088313568198938558381718014554719"
        );
        let wxi = test_utils::to_g1_bn254!(
            "13011387037827226410856017535976866635959597395948712742484719951679072776306",
            "19097020865394571201925707379727666282006694736686406474550074716624155667701"
        );
        let wxiw = test_utils::to_g1_bn254!(
            "7538438606542139971896241028375221414522763891135594182272062973403990501037",
            "5788189548822339379779485439690155515956662814351848253698188435203316528671"
        );

        assert_eq!(a, proof.a);
        assert_eq!(b, proof.b);
        assert_eq!(c, proof.c);
        assert_eq!(z, proof.z);
        assert_eq!(t1, proof.t1);
        assert_eq!(t2, proof.t2);
        assert_eq!(t3, proof.t3);
        assert_eq!(wxi, proof.wxi);
        assert_eq!(wxiw, proof.wxiw);

        assert_eq!("plonk", proof.protocol);
        assert_eq!("bn128", proof.curve);
        //serialize and deserialize and check for equality
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<PlonkProof<Bn254>>(&ser_proof).unwrap();
        assert_eq!(der_proof, proof);
    }
}
