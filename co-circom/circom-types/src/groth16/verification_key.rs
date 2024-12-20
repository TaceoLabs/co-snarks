//! This module defines the [`JsonVerificationKey`] struct that implements de/serialization using [`serde`].
use std::io::Read;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use serde::ser::SerializeSeq;
use serde::{
    de::{self},
    Deserialize, Serialize, Serializer,
};

use crate::traits::{CheckElement, CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};

/// Represents a verification key in JSON format that was created by circom. Supports de/serialization using [`serde`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonVerificationKey<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// The protocol used to generate the proof (always `"groth16"`)
    pub protocol: String,
    /// The number of public inputs
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    /// The element α of the verification key ∈ G1
    #[serde(rename = "vk_alpha_1")]
    #[serde(serialize_with = "P::serialize_g1::<_>")]
    #[serde(deserialize_with = "P::deserialize_g1_element::<_>")]
    pub alpha_1: P::G1Affine,
    /// The element β of the verification key ∈ G2
    #[serde(rename = "vk_beta_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    pub beta_2: P::G2Affine,
    /// The γ of the verification key ∈ G2
    #[serde(rename = "vk_gamma_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    pub gamma_2: P::G2Affine,
    /// The element δ of the verification key ∈ G2
    #[serde(rename = "vk_delta_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    pub delta_2: P::G2Affine,
    /// The pairing of α and β of the verification key ∈ Gt
    #[serde(rename = "vk_alphabeta_12")]
    #[serde(serialize_with = "P::serialize_gt::<_>")]
    #[serde(deserialize_with = "P::deserialize_gt_element::<_>")]
    pub alpha_beta_gt: P::TargetField,
    /// Used to bind the public inputs to the proof
    #[serde(rename = "IC")]
    #[serde(serialize_with = "serialize_g1_sequence::<_,P>")]
    #[serde(deserialize_with = "deserialize_g1_sequence::<_,P>")]
    pub ic: Vec<P::G1Affine>,
}

impl<P: Pairing + CircomArkworksPairingBridge> JsonVerificationKey<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Deserializes a [`JsonVerificationKey`] from a reader.
    pub fn from_reader<R: Read>(rdr: R) -> Result<Self, serde_json::Error> {
        serde_json::from_reader(rdr)
    }
}

fn serialize_g1_sequence<S: Serializer, P: Pairing + CircomArkworksPairingBridge>(
    p: &[P::G1Affine],
    ser: S,
) -> Result<S::Ok, S::Error>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    let mut seq = ser.serialize_seq(Some(p.len())).unwrap();
    let maybe_error = p
        .iter()
        .map(|p| P::g1_to_strings_projective(p))
        .map(|strings| seq.serialize_element(&strings))
        .find(|r| r.is_err());
    if let Some(Err(err)) = maybe_error {
        Err(err)
    } else {
        seq.end()
    }
}

fn deserialize_g1_sequence<'de, D, P: Pairing + CircomArkworksPairingBridge>(
    deserializer: D,
) -> Result<Vec<P::G1Affine>, D::Error>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(G1SeqVisitor::<P>::new(CheckElement::Yes))
}
struct G1SeqVisitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    check: CheckElement,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> G1SeqVisitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new(check: CheckElement) -> Self {
        Self {
            check,
            phantom_data: PhantomData,
        }
    }
}

impl<'de, P: Pairing + CircomArkworksPairingBridge> de::Visitor<'de> for G1SeqVisitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    type Value = Vec<P::G1Affine>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(
            "a sequence of elements representing 
        projective points on G1, which in turn are seqeunces of three
         elements on the BaseField of the Curve.",
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(point) = seq.next_element::<Vec<String>>()? {
            //check if there are no more elements
            if point.len() != 3 {
                return Err(de::Error::invalid_length(point.len(), &self));
            } else {
                values.push(
                    P::g1_from_strings_projective(&point[0], &point[1], &point[2], self.check)
                        .map_err(|_| {
                            de::Error::custom("Invalid projective point on G1.".to_owned())
                        })?,
                );
            }
        }
        Ok(values)
    }
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
        let vk_string = fs::read_to_string(
            "../../test_vectors/Groth16/bn254/multiplier2/verification_key.json",
        )
        .unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&vk_string).unwrap();
        let alpha_1 = test_utils::to_g1_bn254!(
            "16899422092493380665487369855810985762968608626455123789954325961085508316984",
            "11126583514615198837401836505802377658281069969464374246623821884538475740573"
        );
        let beta_2 = test_utils::to_g2_bn254!(
            { "10507543441632391771444308193378912964353702039245296649929512844719350719061", "18201322790656668038537601329094316169506292175603805191741014817443184049262"},
            { "5970405197328671009015216309153477729292937823545171027250144292199028398006", "207690659672174295265842461226025308763643182574816306177651013602294932409"}
        );
        let gamma_2 = test_utils::to_g2_bn254!(
            { "10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"},
            { "8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"}
        );
        let delta_2 = test_utils::to_g2_bn254!(
            { "16155635570759079539128338844496116072647798864000233687303657902717776158999", "146722472349298011683444548694315820674090918095096001856936731325601586110"},
            { "7220557679759413200896918190625936046017159618724594116959480938714251928850", "3740741795440491235944811815904112252316619638122978144672498770442910025884"}
        );
        let ic = vec![
            test_utils::to_g1_bn254!(
                "17064056514210178269621297150176790945669784643731237949186503569701111845663",
                "5160771857172547017310246971961987180872028348077571247747329170768684330052"
            ),
            test_utils::to_g1_bn254!(
                "19547536507588365344778723326587455846790642159887261127893730469532513538882",
                "10737415594461993507153866894812637432840367562913937920244709428556226500845"
            ),
        ];
        //build the element in the target group
        let alpha_beta_gt = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_str("16538785791976368996028573001047494279971959674976400375908002449802111164210").unwrap(),
            ark_bn254::Fq::from_str("17311099400175814384162244991310888068564323701034150916749873601372080366545").unwrap(),
        ),
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_str("6190374261283519082602974907779713353906416008756241816830276080558497621488").unwrap(),
            ark_bn254::Fq::from_str("5946497939975323131559609840334502947229444050838397884136261522455069934142").unwrap(),
        ),
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_str("18660892217118600624251818120445899943943785636603359483071997396426302577570").unwrap(),
            ark_bn254::Fq::from_str("18531687330071011377875481700311081568396123435430215454992195853578365394388").unwrap(),
        )),
        ark_bn254::Fq6::new(
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_str("5476127288440774450864859467181646064764995969290605718134676080503271266731").unwrap(),
            ark_bn254::Fq::from_str("3399564724672231262367838805943403806290653366654941312613814022309517035043").unwrap(),
        ),
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_str("4672701693668323185944980624424920973243633836894733786127181806645734926322").unwrap(),
            ark_bn254::Fq::from_str("7402927066587580894909225234727377776130731489482028867669208914818027294939").unwrap(),
        ),
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_str("11345717037360228259307455612221550284384863263968564709545071871541242621150").unwrap(),
            ark_bn254::Fq::from_str("13027534640849390915265700715948188003828506929766238127775224004400946253786").unwrap(),
        )));

        assert_eq!(vk.protocol, "groth16");
        assert_eq!(vk.n_public, 1);
        assert_eq!(vk.alpha_1, alpha_1);
        assert_eq!(vk.beta_2, beta_2);
        assert_eq!(vk.gamma_2, gamma_2);
        assert_eq!(vk.delta_2, delta_2);
        assert_eq!(vk.alpha_beta_gt, alpha_beta_gt);
        assert_eq!(vk.ic, ic);

        let ser_vk = serde_json::to_string(&vk).unwrap();
        let der_vk = serde_json::from_str::<JsonVerificationKey<Bn254>>(&ser_vk).unwrap();
        assert_eq!(der_vk, vk);
    }

    #[test]
    fn can_serde_vk_bls12_381() {
        let vk_string = fs::read_to_string(
            "../../test_vectors/Groth16/bls12_381/multiplier2/verification_key.json",
        )
        .unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&vk_string).unwrap();
        let alpha_1 = test_utils::to_g1_bls12_381!(
            "573513743870798705896078935465463988747193691665514373553428213826028808426481266659437596949247877550493216010640",
            "3195692015363680281472407569911592878057544540747596023043039898101401350267601241530895953964131482377769738361054"
        );
        let beta_2 = test_utils::to_g2_bls12_381!(
            { "1213509159032791114787919253810063723698125343911375817823407964507894154588429618034348468252648939670896208579873", "1573371412929811557753878280884507253544333246060733954030366147593600651713802914366664802456680232238300886611563"},
            { "227372997676533734391726211114649274508389438640619116602997243907961458158899171192162581346407208971296972028627", "3173649281634920042594077931157174670855523098488107297282865037955359011267273317056899941445467620214571651786849"}
        );
        let gamma_2 = test_utils::to_g2_bls12_381!(
            { "352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160", "3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758"},
            { "1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905", "927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"}
        );
        let delta_2 = test_utils::to_g2_bls12_381!(
            { "1225439548733361287866553883695456824469134186836570397762131498241583159823035296217074111710636342557133382852358", "2605368487020759648403319793196297851010839805929073625099854787778388904778675959353258883417612421791844637077008"},
            { "1154742119857928659368603772369477002539216605293799365584478673152507602473688973931247635774944414206241097299617", "3083613843092389681361977317882198510817133309742782178582263450336527557948727917944434768179612190551923309894740"}
        );
        let ic = vec![
            test_utils::to_g1_bls12_381!("1496325678302426440401133733502043551289869837205655668080008848699551523921245028359850882036392240986058622892606", "1817947725837285375871533104780166089829860102882637736910105269739240593327578312097322455849119517519139026844600"),
            test_utils::to_g1_bls12_381!("1718008724910268123339696488143341961797261917931626884153637247409759465219924679458496161324559634841879674394994", "1374573688907712469603830822734104311026384172354584262904362700919219617284680686401889337872942140366529825919103"),

        ];
        //build the element in the target group
        let alpha_beta_gt = ark_bls12_381::Fq12::new(
        ark_bls12_381::Fq6::new(
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("3426206260164739717251301050836450446272788847665758859792043696763965142214765873633538485020729400216151666369916").unwrap(),
            ark_bls12_381::Fq::from_str("3302905821964069651826570399970992298757253274554755094428043026707855995911990478373290331459067497769869076804692").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("3341741925197178969628078584898626374239424719347918618051814256401232214624764228918336903295697250041874183026953").unwrap(),
            ark_bls12_381::Fq::from_str("3049530629856295411922538290278377288433683510160899068732135510374047492051320353748966405581434200795943001265698").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("119957832779228556734893577556894434260913253291862526433137528213961786701320640345096805403160954913056649513659").unwrap(),
            ark_bls12_381::Fq::from_str("3449648129239458233379559341036050782107226110618632498004835099130249815018931424285727567073991590904426359911010").unwrap(),
        )),
        ark_bls12_381::Fq6::new(
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("782679613215087138195107428934265275754328138002469766499180898383795360891987634262285201345126183624241376694383").unwrap(),
            ark_bls12_381::Fq::from_str("2292345180186296398615963393473076941560700467992311445603207795848142440522290136219412300965109286381992330148").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("960143589460992063893724434040957098401339018007122975228797469321024716444113662816346644525584332133943576279012").unwrap(),
            ark_bls12_381::Fq::from_str("3729324641017761386323645877587187523466589607676793132334511964903429670740473430270328545717478877434534869350645").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("1870388516961111788736169836636048611100105041008953211013579724636674061079883646738605250003717737291366865842426").unwrap(),
            ark_bls12_381::Fq::from_str("3988361102892232342629689285346924532881936157425416548691446154501639146823564430648915954890776187454089346713099").unwrap(),
        )));

        assert_eq!(vk.protocol, "groth16");
        assert_eq!(vk.n_public, 1);
        assert_eq!(vk.alpha_1, alpha_1);
        assert_eq!(vk.beta_2, beta_2);
        assert_eq!(vk.gamma_2, gamma_2);
        assert_eq!(vk.delta_2, delta_2);
        assert_eq!(vk.alpha_beta_gt, alpha_beta_gt);
        assert_eq!(vk.ic, ic);

        let ser_vk = serde_json::to_string(&vk).unwrap();
        let der_vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&ser_vk).unwrap();
        assert_eq!(der_vk, vk);
    }
}
