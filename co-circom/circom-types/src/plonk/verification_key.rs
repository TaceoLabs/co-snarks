//! This module defines the [`JsonVerificationKey`] struct that implements de/serialization using [`serde`].

use ark_ec::pairing::Pairing;

use serde::{Deserialize, Serialize};

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};

/// Represents a verification key in JSON format that was created by circom. Supports de/serialization using [`serde`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonVerificationKey<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// The protocol (Plonk in this case)
    pub protocol: String,
    /// The curve
    pub curve: String,
    /// The number of public inputs
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    /// The size of the fft domain
    pub power: usize,
    /// Proof element k1
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    pub k1: P::ScalarField,
    /// Proof element k2
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    pub k2: P::ScalarField,
    /// Proof element Qm
    #[serde(rename = "Qm")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub qm: P::G1Affine,
    /// Proof element Ql
    #[serde(rename = "Ql")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub ql: P::G1Affine,
    /// Proof element Qr
    #[serde(rename = "Qr")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub qr: P::G1Affine,
    /// Proof element Qo
    #[serde(rename = "Qo")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub qo: P::G1Affine,
    /// Proof element Qc
    #[serde(rename = "Qc")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub qc: P::G1Affine,
    /// Proof element s1
    #[serde(rename = "S1")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub s1: P::G1Affine,
    /// Proof element s2
    #[serde(rename = "S2")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub s2: P::G1Affine,
    /// Proof element s3
    #[serde(rename = "S3")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub s3: P::G1Affine,
    /// Proof element x2
    #[serde(rename = "X_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    pub x2: P::G2Affine,
    // This is curve.Fr.toObject(curve.Fr.w[zkey.power]) so some root of unity (can be computed as in groth16.rs fn root_of_unity() I guess)
    #[serde(rename = "w")]
    #[serde(serialize_with = "P::serialize_fr::<_>")]
    #[serde(deserialize_with = "P::deserialize_fr_element::<_>")]
    w: P::ScalarField,
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;

    use crate::groth16::test_utils;

    use super::JsonVerificationKey;
    use std::{fs, str::FromStr};

    #[test]
    fn can_serde_vk_bn254() {
        let vk_string =
            fs::read_to_string("../../test_vectors/Plonk/bn254/multiplier2/verification_key.json")
                .unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&vk_string).unwrap();
        let qm = test_utils::to_g1_bn254!(
            "7677917713632822727920361992493844364860461207903462488868552343030933598587",
            "18785788385944964807498119744800331077684021375283066763155481595429754250127"
        );
        let ql = test_utils::to_g1_bn254!(
            "9912891307923343075276552724680741202359956696186743932656062593705983916855",
            "1090902058157320892752828520268588270304383995644052104036574185115443278231"
        );
        let qr = ark_bn254::G1Affine::identity();
        let qo = test_utils::to_g1_bn254!(
            "7677917713632822727920361992493844364860461207903462488868552343030933598587",
            "3102454485894310414748286000456944011012289782014756899533556299215471958456"
        );
        let qc = ark_bn254::G1Affine::identity();
        let s1 = test_utils::to_g1_bn254!(
            "1588013514669887852420520084622112203943081494537199508796624414557244544894",
            "6363016164871783624088344755278860796966968417834109644642757464101539174212"
        );
        let s2 = test_utils::to_g1_bn254!(
            "651048528780562970739559818377688095353475815543581634785970378249683232044",
            "1088822084192525369992366256765818710535493190476239776716882318272152929642"
        );
        let s3 = test_utils::to_g1_bn254!(
            "12232637047072170230083757137522484754457903918681512568058855373421867563625",
            "799799222532926464004015195662822376000121219776485581168192697719991323951"
        );
        let x2 = test_utils::to_g2_bn254!({
              "17107451015727890535405243583892630665905859553114023952625938566692070181697",
         "7296510080180284174700458208553594089290233382150687905659845846121677033283"
              },
        {
         "7655786405335547809725849483004638345920750254441453925457356777745907098389",
         "10385078733619740730589284844861152500078556978272946914506777105818518867878"
          });
        assert_eq!(vk.protocol, "plonk");
        assert_eq!(vk.n_public, 2);

        assert_eq!(vk.power, 3);
        assert_eq!(vk.k1, ark_bn254::Fr::from_str("2").unwrap());
        assert_eq!(vk.k2, ark_bn254::Fr::from_str("3").unwrap());
        assert_eq!(vk.qm, qm);
        assert_eq!(vk.ql, ql);
        assert_eq!(vk.qr, qr);
        assert_eq!(vk.qo, qo);
        assert_eq!(vk.qc, qc);
        assert_eq!(vk.s1, s1);
        assert_eq!(vk.s2, s2);
        assert_eq!(vk.s3, s3);
        assert_eq!(vk.x2, x2);
        assert_eq!(
            vk.w,
            ark_bn254::Fr::from_str(
                "19540430494807482326159819597004422086093766032135589407132600596362845576832"
            )
            .unwrap()
        );

        let ser_vk = serde_json::to_string(&vk).unwrap();
        let der_vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&ser_vk).unwrap();
        assert_eq!(der_vk, vk);
    }

    #[test]
    #[cfg(feature = "ark-bls12-381")]
    fn can_serde_vk_bls12_381() {
        use ark_bls12_381::Bls12_381;
        let vk_string = fs::read_to_string(
            "../../test_vectors/Plonk/bls12_381/multiplier2/verification_key.json",
        )
        .unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&vk_string).unwrap();
        let qm = test_utils::to_g1_bls12_381!(
            "1161934215332947887776770080672672736071220168419763784744984455867029974807069620136708593397374748473799982382355",
            "2475816809115390425448758399149658723861102823935625019162174879917945061566694894582346638789223177428431811949584"
        );
        let ql = test_utils::to_g1_bls12_381!(
            "231229530240189893077851306858492660111524752424199304190320688660020866328950437841232960702415871073726889567210",
            "419948876015099780046281058087716590665335676204622284917870410414457729327564575704316456539169469321608690887528"
        );
        let qr = ark_bls12_381::G1Affine::identity();
        let qo = test_utils::to_g1_bls12_381!(
            "1161934215332947887776770080672672736071220168419763784744984455867029974807069620136708593397374748473799982382355",
            "1526592746106276967969031426586245432695779996003382866169883256206086588924142969860340990339792486609462460610203"
        );
        let qc = ark_bls12_381::G1Affine::identity();
        let s1 = test_utils::to_g1_bls12_381!(
            "2006324325458522089157897373551924885871642595641341117148011529426301578867027886227286833073753567634342006781233",
            "14411238778653553095129208715185053150442950911775268340214412197951109236145625764796354200506134935915020308203"
        );
        let s2 = test_utils::to_g1_bls12_381!(
            "3045030373937613278290486945374979965828969680314983134373360690847330815179297069384764287289595867130719068429707",
            "110239115381824825762807943570538404768108009532879365104075815551576845712218745391529988189005379916663969472307"
        );
        let s3 = test_utils::to_g1_bls12_381!(
            "1205970244134791682394627743281420372372248875136100886846078435493251934206381326768624963319520272162244890871754",
            "568208207488514354567139159956547145900098066765870535628206863420405293046656704853363526547096830735710491545366"
        );
        let x2 = test_utils::to_g2_bls12_381!({
                  "3400914744496515007427032749951088582272903522533906041216887827784876366739537204517323627479720818587691128044356",
         "3136793432262573652132468205415338308973613937549376074382942196416643057333246782047817811618289191718376213530045"
              },
        {
         "3601128821143217109339263813029265705936318377953652004577678390117422133537231692691575263234731557178409614811184",
         "1578782236597603608670731344280717233017998234674616797175771378468572702130255650434128469455090530043220787958222"
                });
        assert_eq!(vk.protocol, "plonk");
        assert_eq!(vk.n_public, 2);
        assert_eq!(vk.curve, "bls12381");
        assert_eq!(vk.power, 3);
        assert_eq!(vk.k1, ark_bls12_381::Fr::from_str("2").unwrap());
        assert_eq!(vk.k2, ark_bls12_381::Fr::from_str("3").unwrap());
        assert_eq!(vk.qm, qm);
        assert_eq!(vk.ql, ql);
        assert_eq!(vk.qr, qr);
        assert_eq!(vk.qo, qo);
        assert_eq!(vk.qc, qc);
        assert_eq!(vk.s1, s1);
        assert_eq!(vk.s2, s2);
        assert_eq!(vk.s3, s3);
        assert_eq!(vk.x2, x2);
        assert_eq!(
            vk.w,
            ark_bls12_381::Fr::from_str(
                "28761180743467419819834788392525162889723178799021384024940474588120723734663"
            )
            .unwrap()
        );

        let ser_vk = serde_json::to_string(&vk).unwrap();
        let der_vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&ser_vk).unwrap();
        assert_eq!(der_vk, vk);
    }
}
