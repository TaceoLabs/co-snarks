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
        let proof_string = fs::read_to_string("../test_vectors/Plonk/bn254/proof.json").unwrap();
        let proof = serde_json::from_str::<PlonkProof<Bn254>>(&proof_string).unwrap();

        let a = test_utils::to_g1_bn254!(
            "4504319521196248702424241689113086747083246292055350385986501020926102518542",
            "6624669162716562589232059886787621308146570032902956902836114719213619143185"
        );
        let b = test_utils::to_g1_bn254!(
            "3241992792190028833617931880162692509788594912496246919731609465694141307201",
            "18910984292971472318755650746803983804533002031862391944579042894508998225348"
        );
        let c = test_utils::to_g1_bn254!(
            "17172488745748655891280405659397918840900334071602786979817684295459889806640",
            "9460303090791167118292468484255364794427299083619187746915014245289420778201"
        );
        let z = test_utils::to_g1_bn254!(
            "9773693617949119563662227871839602380690238921118958421089744717873368585536",
            "11324176037248355750632021743777563617208674355873111697869220156056198662136"
        );
        let t1 = test_utils::to_g1_bn254!(
            "14564055116559704570587905172722480236337267676471119840425894354250403169816",
            "9822352311469764878307659464852540679581510275847620081553817049058693809774"
        );
        let t2 = test_utils::to_g1_bn254!(
            "20018965586080343478397346040050173531638741453272800766491865412099000812334",
            "5789754625553642260023133205071680863364314823973349265193469910909447755094"
        );
        let t3 = test_utils::to_g1_bn254!(
            "486073402326735481056319530220520664524127573843374860694131243353156863283",
            "14960997512301924339959160695834199595054941074994293533857887948111571933843"
        );
        let wxi = test_utils::to_g1_bn254!(
            "12394470832707851068390023647355799901711918631367966079560296880065901394627",
            "2350920226105450648946738249632874739742518515206927838829601987759189813579"
        );
        let wxiw = test_utils::to_g1_bn254!(
            "9006680527049575132726802280128514057947891949259564617340923953382095408968",
            "10115041197761203375104085613343864426816108492413524742101251862401233667621"
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
