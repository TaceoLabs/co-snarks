//! This module defines the [`JsonVerificationKey`] struct that implements de/serialization using [`serde`] and the [`From`] trait for the [`ark_groth16::PreparedVerifyingKey`] type.
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use serde::ser::SerializeSeq;
use serde::{
    de::{self},
    Deserialize, Serialize, Serializer,
};

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use core::ops::Neg;

/// Represents a verification key in JSON format that was created by circom. Supports de/serialization using [`serde`] and the [`From`] trait for the [`ark_groth16::PreparedVerifyingKey`] type.
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
    alpha_1: P::G1Affine,
    /// The element β of the verification key ∈ G2
    #[serde(rename = "vk_beta_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    beta_2: P::G2Affine,
    /// The γ of the verification key ∈ G2
    #[serde(rename = "vk_gamma_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    gamma_2: P::G2Affine,
    /// The element δ of the verification key ∈ G2
    #[serde(rename = "vk_delta_2")]
    #[serde(serialize_with = "P::serialize_g2::<_>")]
    #[serde(deserialize_with = "P::deserialize_g2_element::<_>")]
    delta_2: P::G2Affine,
    /// The pairing of α and β of the verification key ∈ Gt
    #[serde(rename = "vk_alphabeta_12")]
    #[serde(serialize_with = "P::serialize_gt::<_>")]
    #[serde(deserialize_with = "P::deserialize_gt_element::<_>")]
    alpha_beta_gt: P::TargetField,
    /// Referred to as `gamma_abc_g1` in [`ark_groth16::data_structures::VerifyingKey`] and is used to bind the public inputs to the proof
    #[serde(rename = "IC")]
    #[serde(serialize_with = "serialize_g1_sequence::<_,P>")]
    #[serde(deserialize_with = "deserialize_g1_sequence::<_,P>")]
    ic: Vec<P::G1Affine>,
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
    deserializer.deserialize_seq(G1SeqVisitor::<P>::new())
}
struct G1SeqVisitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> G1SeqVisitor<P>
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
                    P::g1_from_strings_projective(&point[0], &point[1], &point[2]).map_err(
                        |_| de::Error::custom("Invalid projective point on G1.".to_owned()),
                    )?,
                );
            }
        }
        Ok(values)
    }
}

impl<P: Pairing + CircomArkworksPairingBridge> From<PreparedVerifyingKey<P>>
    for JsonVerificationKey<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn from(value: PreparedVerifyingKey<P>) -> Self {
        let vk = value.vk;
        Self {
            n_public: vk.gamma_abc_g1.len() - 1,
            alpha_1: vk.alpha_g1,
            beta_2: vk.beta_g2,
            gamma_2: vk.gamma_g2,
            delta_2: vk.delta_g2,
            alpha_beta_gt: value.alpha_g1_beta_g2,
            ic: vk.gamma_abc_g1,
            protocol: "groth16".to_owned(),
        }
    }
}

impl<P: Pairing + CircomArkworksPairingBridge> From<JsonVerificationKey<P>>
    for PreparedVerifyingKey<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn from(json_key: JsonVerificationKey<P>) -> Self {
        Self {
            vk: VerifyingKey::<P> {
                alpha_g1: json_key.alpha_1,
                beta_g2: json_key.beta_2,
                gamma_g2: json_key.gamma_2,
                delta_g2: json_key.delta_2,
                gamma_abc_g1: json_key.ic,
            },
            alpha_g1_beta_g2: json_key.alpha_beta_gt,
            gamma_g2_neg_pc: json_key.gamma_2.into_group().neg().into_affine().into(),
            delta_g2_neg_pc: json_key.delta_2.into_group().neg().into_affine().into(),
        }
    }
}

impl<P: Pairing + CircomArkworksPairingBridge> JsonVerificationKey<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Converts the [`JsonVerificationKey`] into a [`PreparedVerifyingKey`].
    pub fn prepare_verifying_key(self) -> PreparedVerifyingKey<P> {
        PreparedVerifyingKey::<P>::from(self)
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
        let vk_string =
            fs::read_to_string("../test_vectors/Groth16/bn254/multiplier2/verification_key.json")
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
        let vk_string =
            fs::read_to_string("../test_vectors/Groth16/bls12_381/verification_key.json").unwrap();
        let vk = serde_json::from_str::<JsonVerificationKey<Bls12_381>>(&vk_string).unwrap();
        let alpha_1 = test_utils::to_g1_bls12_381!(
            "1006274644424409217186953213662503172434575368717179668374437354164299156533023899663544377042948523039106817870257",
            "1056550161284843386841851874013894300183177686460359778532448293436751746312447247913808276245741832724930728476526"
        );
        let beta_2 = test_utils::to_g2_bls12_381!(
            { "3833290875431013323062530478493530418968389153270439753829063257458623453461561795554297289256242122137266954062295", "2228117692250510301392216006578948043594029389519653120062719996832142506700092357578079263683164163924336049094915"},
            { "2239366679955912352262542791898598086155873390998098510086037278986752535371878857599163683200125604962837774856145", "3424627907649077420232688844078275395998719638992940625343328599614593201412881339495541466557865160709666604131438"}
        );
        let gamma_2 = test_utils::to_g2_bls12_381!(
            { "352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160", "3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758"},
            { "1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905", "927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"}
        );
        let delta_2 = test_utils::to_g2_bls12_381!(
            { "407283034676191828394615292491615868521697501403569316394352959421232304452252225405687605369694866481449170561127", "1916310290135728228111042918457706755180843525757258989391918328848764641281205237939637145938907805690848641923870"},
            { "773220331199800641076428580097194510928479849961841626173884910801812589228121209118641713073715764746810093487066", "842139937243481099227693813875901684226562411038967434221031340713350500808075916468091174861623414800092800698492"}
        );
        let ic = vec![
            test_utils::to_g1_bls12_381!("1495026532898515620469577696845787397974195382948513706110048251507786092667423164714014110327294560434168043450964", "1265314875542003637362702953597715823307674187372364159978688398350561983587011928684022513712198594921110529956046"),
            test_utils::to_g1_bls12_381!("777468538140426271424529094657337215335578494839835150872699847044084179692930552100250347883471985898700200932803", "2922638943052571768310240714689471196602837016420790391524646033812246018420763234713405738236179611794749095521486"),

        ];
        //build the element in the target group
        let alpha_beta_gt = ark_bls12_381::Fq12::new(
        ark_bls12_381::Fq6::new(
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("245953587653747364661272996601367517819599136333537896751364566894521515741288251670042624819123653508612108920176").unwrap(),
            ark_bls12_381::Fq::from_str("1043495016811974826271064895744558799045638417482036826524608783985042816338812352101618607035139517940603573783892").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("1436077403984428712715577715493143380738440840354638763535607114970024818330460046200109908912644404056635481232917").unwrap(),
            ark_bls12_381::Fq::from_str("2830257175595044822889689804353215304269461116847276249711335235260334231408550261007395202110126350678917157333167").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("1508754290750078910643170136007034715692777756790015396818460513696413854859616289908355385651830849206992219710332").unwrap(),
            ark_bls12_381::Fq::from_str("313964845217783156613100981543020398852860585996997395986766332008219117989958253817480932103015746698841120007660").unwrap(),
        )),
        ark_bls12_381::Fq6::new(
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("2395025368126554512383041528696450179551770206855623946498536634596941935350232759007641897980542866101729353037334").unwrap(),
            ark_bls12_381::Fq::from_str("672155520622114343117951403318374335972732248237104144448044619992830327356868811268917651305841771084307320591267").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("3598603864633487002300774401458771219600362131474396535229871539610288111910104591375003059125300297421162697844113").unwrap(),
            ark_bls12_381::Fq::from_str("3639609955925134700378752121058019264876307475814452936130142657917747902435857678122697126910962748292392549153095").unwrap(),
        ),
        ark_bls12_381::Fq2::new(
            ark_bls12_381::Fq::from_str("552001153915152500567315522071697673111122326457305118818873061190607796934517550348620797435452644310226360562485").unwrap(),
            ark_bls12_381::Fq::from_str("1274088299258435998313079812684764556026533458463307469668809366079589204850590728652025694366571979534139463158423").unwrap(),
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
