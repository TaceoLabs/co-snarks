use std::marker::PhantomData;

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_groth16::Proof;
use serde::de::{self};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(bound = "P: Pairing")]
pub struct JsonProof<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    #[serde(deserialize_with = "deserialize_g1_element::<_,P>")]
    pub pi_a: P::G1Affine,
    #[serde(deserialize_with = "deserialize_g2_element::<_,P>")]
    pub pi_b: P::G2Affine,
    #[serde(deserialize_with = "deserialize_g1_element::<_,P>")]
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

fn deserialize_g1_element<'de, D, P: Pairing + CircomArkworksPairingBridge>(
    deserializer: D,
) -> Result<P::G1Affine, D::Error>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(G1Visitor::<P>::new())
}

fn deserialize_g2_element<'de, D, P: Pairing + CircomArkworksPairingBridge>(
    deserializer: D,
) -> Result<P::G2Affine, D::Error>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(G2Visitor::<P>::new())
}

struct G1Visitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> G1Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, P: Pairing + CircomArkworksPairingBridge> de::Visitor<'de> for G1Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    type Value = P::G1Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 3 strings, representing a projective point on G1")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else {
            P::g1_from_strings_projective(&x, &y, &z)
                .map_err(|_| de::Error::custom("Invalid projective point on G1.".to_owned()))
        }
    }
}

struct G2Visitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> G2Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, P: Pairing + CircomArkworksPairingBridge> de::Visitor<'de> for G2Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    type Value = P::G2Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .write_str("a sequence of 3 seqeunces, representing a projective point on G2. The 3 sequences each consist of two strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else if x.len() != 2 {
            Err(de::Error::custom(format!(
                "x coordinates need two field elements for G2, but got {}",
                x.len()
            )))
        } else if y.len() != 2 {
            Err(de::Error::custom(format!(
                "y coordinates need two field elements for G2, but got {}",
                y.len()
            )))
        } else if z.len() != 2 {
            Err(de::Error::custom(format!(
                "z coordinates need two field elements for G2, but got {}",
                z.len()
            )))
        } else {
            Ok(P::g2_from_strings_projective(&x[0], &x[1], &y[0], &y[1], &z[0], &z[1]).unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::groth16::test_utils;

    use super::*;
    use ark_bn254::Bn254;
    use hex_literal::hex;

    use std::str::FromStr;

    #[test]
    pub fn deserialize_bn254_proof() {
        let proof_bytes = hex!("7b0a202270695f61223a205b0a20202235393639313233353232303930383134333631313731353838323238323239333638333332373139363937393839313435393139333131333239393839323032333031303531373936393132222c0a2020223138393036323636323733383833343231353338353530353435383730333839373630303238323332363432393933373839303436343335353438373539393538303437353133383236343636222c0a20202231220a205d2c0a202270695f62223a205b0a20205b0a202020223133373332383232373534363835323136363939343934333133313330333037393439333134333538333531323634333931363135303236363537363431383737343539333132383035393231222c0a202020223135323432313535383638313334303531303631353139363137393130383334373538363831323133363232333935373637353635323333323031373135343934313633333832303832363331220a20205d2c0a20205b0a2020202236303430393838333033393130313739313337393035323237353030343736363932353232373331353436333831343539313932313737323632313935383330313539323735363836393330222c0a2020202236313032393331333130303531343235343832313132323232353436393430303231373233323634323933373234313338333735373439313431373137303237373934383738303034313136220a20205d2c0a20205b0a2020202231222c0a2020202230220a20205d0a205d2c0a202270695f63223a205b0a20202238303237343338333430383035313030383233353033393735383530353134323930333931323630303835363035363437383537333333323536333035323134323436373133393837333937222c0a2020223137333638333534303832333837373936323436393738343933303632363834333639353836303830303739353138383838373934363234383336393730393933373038383330363834323935222c0a20202231220a205d2c0a202270726f746f636f6c223a202267726f74683136222c0a20226375727665223a2022626e313238220a7d");
        let proof_string = String::from_utf8(proof_bytes.to_vec()).unwrap();
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
    }

    #[test]
    pub fn deserialize_bls12_381_proof() {
        let proof_bytes = hex!("7b0a202270695f61223a205b0a20202233313631393038393739363739393236373735313238363830393434363739303731353338373435363638303032373539303334363436313331353333313336333533303634393534303035323037323534333138363638363434343536323834313733343639383035393638373630323734222c0a202022393433353332353933383236323532353939373337383037323030323439343736353333333539393237393731343930353338393631383538313439313233323032303831343031383731353430373037313036363536303436313330393538333338363233393435363633363236313836222c0a20202231220a205d2c0a202270695f62223a205b0a20205b0a202020223835373432353439333435383839383933333434333331383432393934363430373934313132303734353834353136333139373533383135303035313035393031393433333730363839303330313638383331393134353438313038353731363335353735303339393234343737343136222c0a2020202232303633333039373134313337363734363730303036393339343839373837373735383634323539393931363735323837333837333937313839373231333335343436333833363430373732363338383436323935383930333636363831383137333639393630383936313931383035323335220a20205d2c0a20205b0a2020202233303533313438303034353539333530373637393433303532313336353530313431383837323033393934363031373239373534353436343235373234323039373933373933353339393238363839353138393833313438343536343530353536323132383034353534393939333538353131222c0a2020202231353831363236333834393638353739393336383933373433363238343331313131373533353831333639323637353831333833373538313231303732383438333336303033383532313233333134363536393734313032363535303336393931383331343638363635393631343339353432220a20205d2c0a20205b0a2020202231222c0a2020202230220a20205d0a205d2c0a202270695f63223a205b0a20202232383131333035333435323935373831383137333438353239363931353232313234333932393730303039303234383439393533343336353933383838363937303630303638373939363430343739333934303837323136393734393030363734383835363831313137333933313833383237222c0a202022333937383732313131353039323233323431343530323938303832313231353438313939393731343533333537313832373832333938393935383536313432313835313135373639323937353536323038393536353732303830353938343938373736393533393639373838333633323531222c0a20202231220a205d2c0a202270726f746f636f6c223a202267726f74683136222c0a20226375727665223a2022626c733132333831220a7d");
        let proof_string = String::from_utf8(proof_bytes.to_vec()).unwrap();
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
    }
}
