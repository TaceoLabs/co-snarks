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
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;

    use crate::groth16::test_utils;

    use super::JsonVerificationKey;
    use std::{fs, str::FromStr};

    #[test]
    fn can_serde_vk_bn254() {
        let vk_string =
            fs::read_to_string("../test_vectors/Plonk/bn254/multiplierAdd2/verification_key.json")
                .unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&vk_string).unwrap();
        let qm = test_utils::to_g1_bn254!(
            "20825949499069110345561489838956415747250622568151984013116057026259498945798",
            "4633888776580597789536778273539625207986785465104156818397550354894072332743"
        );
        let ql = test_utils::to_g1_bn254!(
            "13502414797941204782598195942532580786194839256223737894432362681935424485706",
            "18673738305240077401477088441313771484023070622513584695135539045403188608753"
        );
        let qr = ark_bn254::G1Affine::identity();
        let qo = test_utils::to_g1_bn254!(
            "20825949499069110345561489838956415747250622568151984013116057026259498945798",
            "17254354095258677432709627471717649880709525692193666844291487539751153875840"
        );
        let qc = test_utils::to_g1_bn254!(
            "7167169246583852617380903752531339238444147908961325897597949332988406042299",
            "12364583451238037929078977925246171915349841649656473564249433866303866084266"
        );
        let s1 = test_utils::to_g1_bn254!(
            "13202407937711313005642452333811609087464396353116695610303151252904167171620",
            "21731254820425051303723153463753634951117765441815246299664699876121073117502"
        );
        let s2 = test_utils::to_g1_bn254!(
            "16200325753055057451615309173506918000762869099648255035811864298892416060700",
            "4854549074137598879328057568476164349356796548999724306337465469884552778449"
        );
        let s3 = test_utils::to_g1_bn254!(
            "3207167574831090445347032248388699269604771547162446230552397142949469891087",
            "12507407042551102340888562297650509947996426934050931499910730860149104209330"
        );
        let x2 = test_utils::to_g2_bn254!({
              "10381638170874971121397996789967534475891885850310336883817213216996635408863",
         "2681851268301877279864787521790659176335414381552233253452818192215017003276"
              },
        {
         "19858983598518854908568324414020838266159771673617204257399035093494286994555",
         "569270094740415591600773137166848239653190938661445787168358059369199519813"
          });
        assert_eq!(vk.protocol, "plonk");
        assert_eq!(vk.n_public, 1);

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
    fn can_serde_vk_bls12_381() {
        let vk_string =
            fs::read_to_string("../test_vectors/Plonk/bls12_381/verification_key.json").unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&vk_string).unwrap();
        let qm = test_utils::to_g1_bls12_381!(
          "1723147748860828416711120144543696719412111761825303700112596551376351187620742212893274526748831681863858206231470",
  "2949018972034072043740206501764353634519550026620862305380322829903199190587508331471635344356183415843666976401698"
        );
        let ql = test_utils::to_g1_bls12_381!(
            "3836917296495756920179716205998206213357216686615320555801436880599102341913682173681313790253148307966578937769015",
  "287401979715570516415919566515906473641585537049013188619537234824606718133535321706070669392101973993347320311893"
        );
        let qr = test_utils::to_g1_bls12_381!(
           "2090618390196470119327210227188908173086441410206851642137521637225931432009316340040148689543557079904123056036812",
  "1614427045717856902928226937023608202596469061857201468812661304500361137288033196689748614324789374823638907201419"
        );
        let qo = test_utils::to_g1_bls12_381!(
              "212424632652769445500590033189575253920172379119689148781069953308238005190735544239420721400019017091996598322116",
  "3173095482931144378897089731669172940179057440246979478758607017788221611203356502898514800281479458409055942675359"
        );
        let qc = test_utils::to_g1_bls12_381!(
            "3613514779558094395787932385557249525856650035693742424949594438298333545270541624092080973224002109511316286350074",
  "1891770042479331211073204627597672521095148927702129901134944980343042707766453457435002283096533588302336491655236"
        );
        let s1 = test_utils::to_g1_bls12_381!(
              "927929153192021070631884049359833058456321442047292745670443464208275455505862107703488386277425646759192792198739",
  "688622098248959357920278536377976850412357227432736736266054280444660941866822927921789555295792305630885779170685"
        );
        let s2 = test_utils::to_g1_bls12_381!(
              "95270063593234332501896678317095767892583473794553368237686885354093930427625023374101094166815100345814218250329",
  "3802490423224918447737248020323450838304577295580744321910263675866465650400974680899245700740953244263410141773367");
        let s3 = test_utils::to_g1_bls12_381!(
              "3416496197193169849022401205249143545024447114211659121851027015642973335020224757645611950432601100806228119734467",
  "3387494238870189253069530118205554882464479427930063948404732410125166920969605229179748646331087309237715815672578"
        );
        let x2 = test_utils::to_g2_bls12_381!({
                  "2860053056104173544028575029336499762563668781131445523105796126289087661258945099800746281886380671479668146251588",
         "1390338754753874009273019648633275655165794518014047713032788004636409868272254989992393134429149660168465975047041"
              },
        {
         "1593225350270998129442252518445686172875774793870713060989614781941846267941879796967979194189797942108678900337905",
         "684036879284401121245453399582968744567428921440189521153229215944607164260296376796809206662207469687719394118671"
                });
        assert_eq!(vk.protocol, "plonk");
        assert_eq!(vk.n_public, 1);
        assert_eq!(vk.curve, "bls12381");
        assert_eq!(vk.power, 15);
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
                "30195699792882346185164345110260439085017223719129789169349923251189180189908"
            )
            .unwrap()
        );

        let ser_vk = serde_json::to_string(&vk).unwrap();
        let der_vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&ser_vk).unwrap();
        assert_eq!(der_vk, vk);
    }
}
