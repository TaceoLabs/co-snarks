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
            fs::read_to_string("../../test_vectors/Plonk/bn254/multiplier2/circom.proof").unwrap();
        let proof = serde_json::from_str::<PlonkProof<Bn254>>(&proof_string).unwrap();

        let a = test_utils::to_g1_bn254!(
            "19185397279453135687907629215618377331052614639062297861977006623699765902669",
            "14076670419431094877766141946219186382960374658248679166656125419187757611992"
        );
        let b = test_utils::to_g1_bn254!(
            "2507612843658598262175159725156716601527310419851022894398961190172406420716",
            "9507866817343785656125038284260215111734090591370736917675930458700211123375"
        );
        let c = test_utils::to_g1_bn254!(
            "21337538251891423253170113243675521236652082898886356406347527538451722251600",
            "4601841665804129088932258527878495938386324658596718537385781766564373982184"
        );
        let z = test_utils::to_g1_bn254!(
            "1315294690899812926536846063602562610991364125345434605970401401169419766156",
            "12400277297505514557892162657921825641804975244957202931983352886142624549048"
        );
        let t1 = test_utils::to_g1_bn254!(
            "8249530393556784329337015813862161518800073858733417144402849313890116399774",
            "21834170048352726103969592707454634815468994580819464027446591372045577083420"
        );
        let t2 = test_utils::to_g1_bn254!(
            "11258310379602927457171792998761697495732357295394944737859140992406908320927",
            "1182394090262501396517594656643195962372088382418665816316617215485999908311"
        );
        let t3 = test_utils::to_g1_bn254!(
            "8632722195148815273807999249905534249844876531646352159949740282008747021660",
            "4035528332906249218339151047390105315812479578866368594429110701648781726590"
        );
        let wxi = test_utils::to_g1_bn254!(
            "20085668208463684447802888422259904090562924652546934519848712289147934166401",
            "5973678760424951893319519221560971321644322562928997291096069736378998603487"
        );
        let wxiw = test_utils::to_g1_bn254!(
            "16665635097679564151940247079921673579718911401169267483832368229346767284794",
            "3815209636412039073728878062777320266584051459762556106938153466506942387618"
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
            fs::read_to_string("../../test_vectors/Plonk/bls12_381/multiplier2/circom.proof")
                .unwrap();
        let proof = serde_json::from_str::<PlonkProof<Bls12_381>>(&proof_string).unwrap();

        let a = test_utils::to_g1_bls12_381!(
            "7079055545652892091172049996016877083471582793270458041561649002604067773928367787208369525483719669846458141997",
  "2385186405166306137907214704002622350849790162202152204552416874190641596408350541886341533337726336868720684727066"
        );
        let b = test_utils::to_g1_bls12_381!(
            "590249539122723124353604259335629308078973055877458869785883862370628244396988230204028146292193783953602836331665",
  "447921499967089104752537697505537716374302591749643198063997854121658041103907595801321026524795379979836902480620"
        );
        let c = test_utils::to_g1_bls12_381!(
             "536697836123521027996718000252000694218319641513936269898259478945773126994691294394840316800882887961924631798554",
  "2558193015818325045493869208337709034019021186074225683301085416156282063789442232173435380007151339465265762078558"
        );
        let z = test_utils::to_g1_bls12_381!(
              "545339640641609353878118828797588634689096460893937756839279437284154392082474116059257976627553775629974958115164",
  "2575327766129512737532577155583077606893133888302092876011514742085778703963598152879993680042314273833110441814745"
        );
        let t1 = test_utils::to_g1_bls12_381!(
            "3880669295926578946355050852841786205134696960626010987853957047339524263897589976196635522590267712165586236976006",
  "375484972025168887860121156977788238878679914151273543500647141403326644827145044438275098888822905390379512791494"
        );
        let t2 = test_utils::to_g1_bls12_381!(
             "2407336075877409041687950280882062675240623554226520134309032574299607578007253677739380728087742021492057409306265",
  "2224749196745899613436064622755321820625835969540722701935776638540715376682382218585341599311599688702135588745893");
        let t3 = test_utils::to_g1_bls12_381!(
              "1983818938618488107072797139829776452760247610479299680681933492365445446066813231393476816942990680770995719769502",
  "914979824011470736801319448162340780281912438271009988162309331575787788172518963661761714979514387237104840364145"
        );
        let wxi = test_utils::to_g1_bls12_381!(
          "882776873652953848060114812615449965462950131693140077696219356688810350977734352922880411781027793200492951183293",
  "2192991963752116122093119009907566567385839008456599371293766481323809550032553099581622684563538952146114833780784"
        );
        let wxiw = test_utils::to_g1_bls12_381!(
              "2319111274733089875544652730864276961796743944692465902097271930365866041091301573795259451740956855830885488414124",
  "1376770408130253154878489850239497399183687449893033641655894971676195517967584323754110282421595525974596250445652"
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
