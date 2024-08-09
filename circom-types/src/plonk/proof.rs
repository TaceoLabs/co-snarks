//! This module defines the [`PlonkProof`] in circom's format. It implements de/serialization using [`serde`].

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use ark_ec::pairing::Pairing;
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

    #[test]
    pub fn deserialize_bls12_381_proof() {
        let proof_string =
            fs::read_to_string("../test_vectors/Plonk/bls12_381/proof.json").unwrap();
        let proof = serde_json::from_str::<PlonkProof<Bls12_381>>(&proof_string).unwrap();

        let a = test_utils::to_g1_bls12_381!(
            "360821804645872796888044667200991021453493777251305346796504289496467907752766833900643658028444845629156216393324",
  "1743833438735965327743874287593339060012631123850205250984765614039475912106506714327784229942272632136619917250486"
        );
        let b = test_utils::to_g1_bls12_381!(
            "647529654280197842116942175362955462972603633810968680634758618373070555550190755943096375411475072327869662324547",
  "1093542557185967570791812822161311787424425885056129440768098377962299197710704662181885014324076698823963377336025"
        );
        let c = test_utils::to_g1_bls12_381!(
             "909065706427639143941621188169426799311204387473973167470397653201272491896707757799302349773200819358242532949185",
  "2342084890936029731104809553395305460649583485769471523125620703383004673901025847900483202675992343335455079276122"
        );
        let z = test_utils::to_g1_bls12_381!(
              "3330213652503959540097089971048139705457039578801875067459333665725028517313831248403121726563014904856404091593211",
  "642923594788217344287176854506355032041668478150968605086400129141978866365207797951968991667700550596700600275543"
        );
        let t1 = test_utils::to_g1_bls12_381!(
            "1955645041815280133198409574040758270369812816186088574200594797427020200837830035419152552897677457164567111746761",
  "2350378048728508202952340493307724320685360179319386854298760316761252877568396364257536365821132124720840653298847"
        );
        let t2 = test_utils::to_g1_bls12_381!(
             "3130519755724128287700196351122201905148891330457612247249586899668401317742539323164255175937783698914119951036117",
  "935806497503352973151912427576385676028502497206324550975185303470364374727244004875897015762455356967563520448170");
        let t3 = test_utils::to_g1_bls12_381!(
              "1805763374451871470516963364031152993904442181471289524234654735654044104349646069969148335720368703471958234925263",
  "973376007912103842832178017452470209380019653586447501491489823928562392242750048689673801542590333423123640492376"
        );
        let wxi = test_utils::to_g1_bls12_381!(
          "647238908803044918723860250202195809450833670544051273237357046570641511679371238662795653090702795861867914119025",
  "1932770882500884280542258068758169138249147152624178066950186305513148290829541809325301574481529686778630594560305"
        );
        let wxiw = test_utils::to_g1_bls12_381!(
              "747548878247014563886506404345988167312428123956992027735386597434624360089477921786249002577949057260820126725128",
  "3195628342178391338503474224605941324690328455886237192727799844469083957271228571965282249145363879340949447470958"
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
        assert_eq!("bls12381", proof.curve);
        //serialize and deserialize and check for equality
        let ser_proof = serde_json::to_string(&proof).unwrap();
        let der_proof = serde_json::from_str::<PlonkProof<Bls12_381>>(&ser_proof).unwrap();
        assert_eq!(der_proof, proof);
    }
}
