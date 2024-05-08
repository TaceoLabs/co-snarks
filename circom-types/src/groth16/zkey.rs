//Copyright (c) 2021 Georgios Konstantopoulos
//
//Permission is hereby granted, free of charge, to any
//person obtaining a copy of this software and associated
//documentation files (the "Software"), to deal in the
//Software without restriction, including without
//limitation the rights to use, copy, modify, merge,
//publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software
//is furnished to do so, subject to the following
//conditions:
//
//The above copyright notice and this permission notice
//shall be included in all copies or substantial portions
//of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//IN CONNECTION WITH THE SOFTWARE O THE USE OR OTHER
//DEALINGS IN THE SOFTWARE.R

//!Inspired by <https://github.com/arkworks-rs/circom-compat/blob/170b10fc9ed182b5f72ecf379033dda023d0bf07/src/zkey.rs>
//! ZKey Parsing
//!
//! Each ZKey file is broken into sections:
//!  Header(1)
//!       Prover Type 1 Groth
//!  HeaderGroth(2)
//!       n8q
//!       q
//!       n8r
//!       r
//!       NVars
//!       NPub
//!       DomainSize  (multiple of 2
//!       alpha1
//!       beta1
//!       delta1
//!       beta2
//!       gamma2
//!       delta2
//!  IC(3)
//!  Coefs(4)
//!  PointsA(5)
//!  PointsB1(6)
//!  PointsB2(7)
//!  PointsC(8)
//!  PointsH(9)
//!  Contributions(10)
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::log2;
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
};

use ark_groth16::{ProvingKey, VerifyingKey};

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};

use crate::reader_utils;
type Result<T> = std::result::Result<T, ZKeyParserError>;

#[derive(Debug, Error)]
pub enum ZKeyParserError {
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    #[error("invalid modulus found in header for chosen curve")]
    InvalidGroth16Header,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
struct Section {
    position: u64,
    #[allow(dead_code)]
    size: usize,
}

pub struct ZKey<P: Pairing> {
    pk: ProvingKey<P>,
    matrices: ConstraintMatrices<P::ScalarField>,
}

impl<P: Pairing + CircomArkworksPairingBridge> ZKey<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    pub fn from_reader<R: Read + Seek>(mut reader: R) -> Result<Self> {
        let mut binfile = BinFile::<_, P>::new(&mut reader)?;
        let pk = binfile.proving_key()?;
        let matrices = binfile.matrices()?;
        Ok(Self { pk, matrices })
    }

    pub fn split(self) -> (ProvingKey<P>, ConstraintMatrices<P::ScalarField>) {
        (self.pk, self.matrices)
    }
}

#[derive(Debug)]
struct BinFile<'a, R, P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    reader: &'a mut R,
    phantom_data: PhantomData<P>,
}

impl<'a, R: Read + Seek, P: Pairing + CircomArkworksPairingBridge> BinFile<'a, R, P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new(reader: &'a mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let version = reader.read_u32::<LittleEndian>()?;

        let num_sections = reader.read_u32::<LittleEndian>()?;

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            let section_id = reader.read_u32::<LittleEndian>()?;
            let section_length = reader.read_u64::<LittleEndian>()?;

            let section = sections.entry(section_id).or_insert_with(Vec::new);
            section.push(Section {
                position: reader.stream_position()?,
                size: section_length as usize,
            });

            reader.seek(SeekFrom::Current(section_length as i64))?;
        }

        Ok(Self {
            ftype: std::str::from_utf8(&magic[..]).unwrap().to_string(),
            version,
            sections,
            reader,
            phantom_data: PhantomData::<P>,
        })
    }

    fn proving_key(&mut self) -> Result<ProvingKey<P>> {
        let header = self.groth_header()?;
        let ic = self.ic(header.n_public)?;

        let a_query = self.a_query(header.n_vars)?;
        let b_g1_query = self.b_g1_query(header.n_vars)?;
        let b_g2_query = self.b_g2_query(header.n_vars)?;
        let l_query = self.l_query(header.n_vars - header.n_public - 1)?;
        let h_query = self.h_query(header.domain_size as usize)?;

        let vk = VerifyingKey::<P> {
            alpha_g1: header.verifying_key.alpha_g1,
            beta_g2: header.verifying_key.beta_g2,
            gamma_g2: header.verifying_key.gamma_g2,
            delta_g2: header.verifying_key.delta_g2,
            gamma_abc_g1: ic,
        };

        let pk = ProvingKey::<P> {
            vk,
            beta_g1: header.verifying_key.beta_g1,
            delta_g1: header.verifying_key.delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        Ok(pk)
    }

    fn get_section(&self, id: u32) -> Section {
        self.sections.get(&id).unwrap()[0].clone()
    }

    fn groth_header(&mut self) -> Result<HeaderGroth<P>> {
        let section = self.get_section(2);
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    fn ic(&mut self, n_public: usize) -> Result<Vec<P::G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    /// Returns the [`ConstraintMatrices`] corresponding to the zkey
    pub fn matrices(&mut self) -> Result<ConstraintMatrices<P::ScalarField>> {
        let header = self.groth_header()?;

        let section = self.get_section(4);
        self.reader.seek(SeekFrom::Start(section.position))?;
        let num_coeffs: u32 = self.reader.read_u32::<LittleEndian>()?;

        // instantiate AB
        let mut matrices = vec![vec![vec![]; header.domain_size as usize]; 2];
        let mut max_constraint_index = 0;
        for _ in 0..num_coeffs {
            let matrix: u32 = self.reader.read_u32::<LittleEndian>()?;
            let constraint: u32 = self.reader.read_u32::<LittleEndian>()?;
            let signal: u32 = self.reader.read_u32::<LittleEndian>()?;

            let value = P::ScalarField::from_reader(&mut self.reader)?;
            max_constraint_index = std::cmp::max(max_constraint_index, constraint);
            matrices[matrix as usize][constraint as usize].push((value, signal as usize));
        }

        let num_constraints = max_constraint_index as usize - header.n_public;
        // Remove the public input constraints, Arkworks adds them later
        matrices.iter_mut().for_each(|m| {
            m.truncate(num_constraints);
        });
        // This is taken from Arkworks' to_matrices() function
        let a = matrices[0].clone();
        let b = matrices[1].clone();
        let a_num_non_zero: usize = a.iter().map(|lc| lc.len()).sum();
        let b_num_non_zero: usize = b.iter().map(|lc| lc.len()).sum();
        let matrices = ConstraintMatrices {
            num_instance_variables: header.n_public + 1,
            num_witness_variables: header.n_vars - header.n_public,
            num_constraints,

            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero: 0,

            a,
            b,
            c: vec![],
        };

        Ok(matrices)
    }

    fn a_query(&mut self, n_vars: usize) -> Result<Vec<P::G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    fn b_g1_query(&mut self, n_vars: usize) -> Result<Vec<P::G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    fn b_g2_query(&mut self, n_vars: usize) -> Result<Vec<P::G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    fn l_query(&mut self, n_vars: usize) -> Result<Vec<P::G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    fn h_query(&mut self, n_vars: usize) -> Result<Vec<P::G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    fn g1_section(&mut self, num: usize, section_id: usize) -> Result<Vec<P::G1Affine>> {
        let section = self.get_section(section_id as u32);
        self.reader.seek(SeekFrom::Start(section.position))?;
        Ok(reader_utils::read_g1_vector::<P, _>(&mut self.reader, num)?)
    }

    fn g2_section(&mut self, num: usize, section_id: usize) -> Result<Vec<P::G2Affine>> {
        let section = self.get_section(section_id as u32);
        self.reader.seek(SeekFrom::Start(section.position))?;
        Ok(reader_utils::read_g2_vector::<P, _>(&mut self.reader, num)?)
    }
}

#[derive(Default, Clone, Debug)]
pub struct ZVerifyingKey<P: Pairing> {
    alpha_g1: P::G1Affine,
    beta_g1: P::G1Affine,
    beta_g2: P::G2Affine,
    gamma_g2: P::G2Affine,
    delta_g1: P::G1Affine,
    delta_g2: P::G2Affine,
}

impl<P: Pairing + CircomArkworksPairingBridge> ZVerifyingKey<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new<R: Read>(mut reader: R) -> Result<Self> {
        let alpha_g1 = P::g1_from_reader(&mut reader)?;
        let beta_g1 = P::g1_from_reader(&mut reader)?;
        let beta_g2 = P::g2_from_reader(&mut reader)?;
        let gamma_g2 = P::g2_from_reader(&mut reader)?;
        let delta_g1 = P::g1_from_reader(&mut reader)?;
        let delta_g2 = P::g2_from_reader(&mut reader)?;

        Ok(Self {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

#[derive(Clone, Debug)]
struct HeaderGroth<P: Pairing> {
    #[allow(dead_code)]
    n8q: u32,
    #[allow(dead_code)]
    n8r: u32,

    n_vars: usize,
    n_public: usize,

    domain_size: u32,
    #[allow(dead_code)]
    power: u32,

    verifying_key: ZVerifyingKey<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> HeaderGroth<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> Result<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> Result<Self> {
        // TODO: Impl From<u32> in Arkworks
        let n8q: u32 = u32::deserialize_uncompressed(&mut reader)?;
        //modulos of BaseField
        let q = <P::BaseField as PrimeField>::BigInt::deserialize_uncompressed(&mut reader)?;
        let modulus = <P::BaseField as PrimeField>::MODULUS;
        if q != modulus {
            return Err(ZKeyParserError::InvalidGroth16Header);
        }
        let n8r: u32 = u32::deserialize_uncompressed(&mut reader)?;
        //modulos of ScalarField
        let r = <P::ScalarField as PrimeField>::BigInt::deserialize_uncompressed(&mut reader)?;
        let modulus = <P::ScalarField as PrimeField>::MODULUS;
        assert_eq!(r, modulus);

        let n_vars = u32::deserialize_uncompressed(&mut reader)? as usize;
        let n_public = u32::deserialize_uncompressed(&mut reader)? as usize;

        let domain_size: u32 = u32::deserialize_uncompressed(&mut reader)?;
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;
        Ok(Self {
            n8q,
            n8r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::groth16::test_utils;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ff::BigInteger256;
    use num_bigint::BigUint;
    use std::fs::File;

    use num_traits::{One, Zero};
    use std::str::FromStr;

    use std::convert::TryFrom;

    #[test]
    fn can_deser_bls12_381_mult2_key() {
        let zkey = File::open("../test_vectors/bls12_381/multiplier2.zkey").unwrap();
        let (pk, _) = ZKey::<Bls12_381>::from_reader(zkey).unwrap().split();
        let beta_g1 = test_utils::to_g1_bls12_381!(
            "3250926845764181697440489887589522470230793318088642572984668490087093900624850910545082127315229930931755140742241",
            "316529275544082453038501392826432978288816226993296382968176983689596132256113795423119530534863639021511852843536"
        );
        let delta_g1 = test_utils::to_g1_bls12_381!(
            "3522538514645581909595093356214410123778715444301346582233059879861465781757689043149432879158758625616912247982574",
            "51911653867234225694077203463991897198176746412409113752310499852716400259023436784245655686266588409880673165427"
        );
        let a_query = vec![
            test_utils::to_g1_bls12_381!(
                "1199600865347365846614772224387734992872742743645608363058523508602381603473044114758201229668495599599867977867598",
                "3360251230488362151644767476716308022549292636406245286137561532522181460109982012195555192859281802190503662832736"
            ),
            test_utils::to_g1_bls12_381!(
                "2711401121527458403237181198150867210012794522275697038284081574215400387744728516594242370397618691979353118309710",
                "3486606421648938033733836353242939867001978600304918082945875710002722663351772694500061121130580023392236655167993"
            ),
            test_utils::to_g1_bls12_381!(
                "2845615579988424625800306075148314585519267318584086206997304313851267575611155336142229648966642801213689032039159",
                "3695687848291797483510721912757824325296584645488047576713391249044617474215556821632323138620805664234894571180592"
            ),
            <Bls12_381 as Pairing>::G1Affine::identity(),
        ];
        let b_g1_query = vec![
            <Bls12_381 as Pairing>::G1Affine::identity(),
            <Bls12_381 as Pairing>::G1Affine::identity(),
            <Bls12_381 as Pairing>::G1Affine::identity(),
            test_utils::to_g1_bls12_381!(
                "2845615579988424625800306075148314585519267318584086206997304313851267575611155336142229648966642801213689032039159",
                "306721706929869909907067912978079831260298174450960308618666887079414176275281042810364490508209999802999701379195"
            ),
        ];
        let b_g2_query = vec![
            <Bls12_381 as Pairing>::G2Affine::identity(),
            <Bls12_381 as Pairing>::G2Affine::identity(),
            <Bls12_381 as Pairing>::G2Affine::identity(),
            test_utils::to_g2_bls12_381!(
                { "2113463851831955346801101153131028744507713186244833021702996637472083526360280280323203433869213952361519606241802", "1343119776677935885280234906336922828558416410993363988824774174482429883397806963454484361243084931802908922336930"},
                { "505552028995632751332517285584583873068423285035078833302642266216324841109336563940046397863289139182614918053017",  "992061159809716591013395830058584309354024259013530140231873280021661374063975105888602656400444397969041616244464"}
            ),
        ];

        let h_query = vec![
            test_utils::to_g1_bls12_381!(
                "2293029533522893095460116818499709494426283913180551777630398477755354415182042699034545957058675161919586139564369",
                "3039029592770404220034576726531549879388518921083701080160816055228575019078944614345422650334424530624522605602252"
            ),
            test_utils::to_g1_bls12_381!(
                "1407156869685999978227469740231020906526233742685801696126918955403519962511035029357286967127530367784961218222438",
                "1855218185257003477782967309635385120556867668053823102832548973518419320113479910316527564944213081692802738543260"
            ),
            test_utils::to_g1_bls12_381!(
                "3404527500055498472123936853446760581430347488697225486818935196485796749595477784108071017880634511008873815282539",
                "115505374684635036697626116765796590398730034768976423556277424868279831528319393384831625644304537374162766464872"
            ),
            test_utils::to_g1_bls12_381!(
                "3972054631656469239782601936632030776231742708006856922974253464145622884987442824222870295156875959367520099206331",
                "3025040223112008823108047033504664320309802049156899724449466847456059988684209675825135747621385371073210063386697"
            ),
        ];
        let l_query = vec![
            test_utils::to_g1_bls12_381!(
                "205369807008164157124824289364782273643340956185304458131472141330177970405131417533021663495042162636121671794451",
                "3130192026245620197326223555624313004960676293768731802523574035154850230338776204831014643324641668713935151613063"
            ),
            test_utils::to_g1_bls12_381!(
                "1407292015536137774830178334377832393502712774671497733893077608167926007781969246155750138777714147005284321811848",
                "355009792229307920564863475599607679977168981064095632836608588866145933539209405913407870349684241161840508453558"
            ),
        ];
        assert_eq!(beta_g1, pk.beta_g1);
        assert_eq!(delta_g1, pk.delta_g1);
        assert_eq!(a_query, pk.a_query);
        assert_eq!(b_g1_query, pk.b_g1_query);
        assert_eq!(b_g2_query, pk.b_g2_query);
        assert_eq!(h_query, pk.h_query);
        assert_eq!(l_query, pk.l_query);
        let vk = pk.vk;
        let alpha_g1 = test_utils::to_g1_bls12_381!(
            "573513743870798705896078935465463988747193691665514373553428213826028808426481266659437596949247877550493216010640",
            "3195692015363680281472407569911592878057544540747596023043039898101401350267601241530895953964131482377769738361054"
        );

        let beta_g2 = test_utils::to_g2_bls12_381!(
            { "1213509159032791114787919253810063723698125343911375817823407964507894154588429618034348468252648939670896208579873", "1573371412929811557753878280884507253544333246060733954030366147593600651713802914366664802456680232238300886611563"},
            { "227372997676533734391726211114649274508389438640619116602997243907961458158899171192162581346407208971296972028627", "3173649281634920042594077931157174670855523098488107297282865037955359011267273317056899941445467620214571651786849"}
        );
        let gamma_g2 = test_utils::to_g2_bls12_381!(
            { "352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160", "3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758"},
            { "1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905", "927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"}
        );
        let delta_g2 = test_utils::to_g2_bls12_381!(
            { "1225439548733361287866553883695456824469134186836570397762131498241583159823035296217074111710636342557133382852358", "2605368487020759648403319793196297851010839805929073625099854787778388904778675959353258883417612421791844637077008"},
            { "1154742119857928659368603772369477002539216605293799365584478673152507602473688973931247635774944414206241097299617", "3083613843092389681361977317882198510817133309742782178582263450336527557948727917944434768179612190551923309894740"}
        );
        let gamma_abc_g1 = vec![
            test_utils::to_g1_bls12_381!(
                "1496325678302426440401133733502043551289869837205655668080008848699551523921245028359850882036392240986058622892606",
                "1817947725837285375871533104780166089829860102882637736910105269739240593327578312097322455849119517519139026844600"
            ),
            test_utils::to_g1_bls12_381!(
                "1718008724910268123339696488143341961797261917931626884153637247409759465219924679458496161324559634841879674394994",
                "1374573688907712469603830822734104311026384172354584262904362700919219617284680686401889337872942140366529825919103"
            ),
        ];
        assert_eq!(alpha_g1, vk.alpha_g1);
        assert_eq!(beta_g2, vk.beta_g2);
        assert_eq!(gamma_g2, vk.gamma_g2);
        assert_eq!(delta_g2, vk.delta_g2);
        assert_eq!(gamma_abc_g1, vk.gamma_abc_g1);
    }

    #[test]
    fn test_can_deser_bn254_mult2_key() {
        //I AM BROKEN FIX MEEEEEEEEEEEE
        let zkey = File::open("../test_vectors/bn254/multiplier2/multiplier2.zkey").unwrap();
        let (pk, matrices) = ZKey::<Bn254>::from_reader(zkey).unwrap().split();
        let beta_g1 = test_utils::to_g1_bn254!(
            "1436132865180440050058953936123839411531217265376140788508003974087015278078",
            "11205704823000238875301065577649453768474753051476131547254697150385247310776"
        );
        let delta_g1 = test_utils::to_g1_bn254!(
            "12051011878221628389674080598285147317221736518934197297472514541067234049832",
            "1650222580766296097385922637359084411731487491591430805526365669999662996639"
        );
        let a_query = vec![
            test_utils::to_g1_bn254!(
                "18725433602048903662587995221665035320581462210120298037391596887019126094011",
                "21625684461343402533728380898217456926042732124391706885907422786058840125903"
            ),
            test_utils::to_g1_bn254!(
                "14584302574412698021277778760150385757204430056548033126783511194490502056178",
                "8186291620296944271807819840156212102452730374975807713458717497787335421034"
            ),
            test_utils::to_g1_bn254!(
                "18059833745039898949912416847640887946787247617387156526033491346630378607327",
                "2147855137744350757931593591513162308112825654177517603230709355109360763378"
            ),
            <Bn254 as Pairing>::G1Affine::identity(),
        ];
        let b_g1_query = vec![
            <Bn254 as Pairing>::G1Affine::identity(),
            <Bn254 as Pairing>::G1Affine::identity(),
            <Bn254 as Pairing>::G1Affine::identity(),
            test_utils::to_g1_bn254!(
                "18059833745039898949912416847640887946787247617387156526033491346630378607327",
                "19740387734094924464314812153744112780583485503120306059458328539535865445205"
            ),
        ];
        let b_g2_query = vec![
            <Bn254 as Pairing>::G2Affine::identity(),
            <Bn254 as Pairing>::G2Affine::identity(),
            <Bn254 as Pairing>::G2Affine::identity(),
            test_utils::to_g2_bn254!(
                { "11215382108502485715538966175422447511646180418195651381286746745387656917397", "13984595697374230032052495279471297756611885510635113203613893375403736850069"},
                { "10743976360697987164911081205247630965928262455850973730638489200185835784108",  "13396485108593384705951383471761272218148543108400450086557930691129737585849"}
            ),
        ];

        let h_query = vec![
            test_utils::to_g1_bn254!(
                "6700513793947040178272431538132695909814808341474700033179555096948265834163",
                "3702458429860293860126161729473184417690978782825186962373408709751934349255"
            ),
            test_utils::to_g1_bn254!(
                "3225757210775924198062688167188302863174919799399835717461711357401017733475",
                "8791371305241810326819180276689616469985548291962809871367438397488155336149"
            ),
            test_utils::to_g1_bn254!(
                "13493432095464357272608951933337268704371819533913523733687802071485012174481",
                "5531822087425040465533301450497735021203494273046107158269966026275807395639"
            ),
            test_utils::to_g1_bn254!(
                "15396782304271112846116855625124513047228463242415719456633010579521777763173",
                "8258083175634258927272835103331851780426370931797814635880535822054891487444"
            ),
        ];
        let l_query = vec![
            test_utils::to_g1_bn254!(
                "14293418265207147156122985951829773749976888191656636438805785399673848239092",
                "291952141266205370506542536801856778702146583588765672667099667518861492814"
            ),
            test_utils::to_g1_bn254!(
                "2058060186664785244243803292525142877328490944635412415694740369257034050464",
                "20518040155278230805559359774469944262370840294076847138351681247484905656843"
            ),
        ];
        assert_eq!(beta_g1, pk.beta_g1);
        assert_eq!(delta_g1, pk.delta_g1);
        assert_eq!(a_query, pk.a_query);
        assert_eq!(b_g1_query, pk.b_g1_query);
        assert_eq!(b_g2_query, pk.b_g2_query);
        assert_eq!(h_query, pk.h_query);
        assert_eq!(l_query, pk.l_query);
        let vk = pk.vk;

        let alpha_g1 = test_utils::to_g1_bn254!(
            "16899422092493380665487369855810985762968608626455123789954325961085508316984",
            "11126583514615198837401836505802377658281069969464374246623821884538475740573"
        );

        let beta_g2 = test_utils::to_g2_bn254!(
            { "10507543441632391771444308193378912964353702039245296649929512844719350719061", "18201322790656668038537601329094316169506292175603805191741014817443184049262"},
            { "5970405197328671009015216309153477729292937823545171027250144292199028398006", "207690659672174295265842461226025308763643182574816306177651013602294932409"}
        );
        let gamma_g2 = test_utils::to_g2_bn254!(
            { "10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"},
            { "8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"}
        );
        let delta_g2 = test_utils::to_g2_bn254!(
            { "16155635570759079539128338844496116072647798864000233687303657902717776158999", "146722472349298011683444548694315820674090918095096001856936731325601586110"},
            { "7220557679759413200896918190625936046017159618724594116959480938714251928850", "3740741795440491235944811815904112252316619638122978144672498770442910025884"}
        );
        let gamma_abc_g1 = vec![
            test_utils::to_g1_bn254!(
                "17064056514210178269621297150176790945669784643731237949186503569701111845663",
                "5160771857172547017310246971961987180872028348077571247747329170768684330052"
            ),
            test_utils::to_g1_bn254!(
                "19547536507588365344778723326587455846790642159887261127893730469532513538882",
                "10737415594461993507153866894812637432840367562913937920244709428556226500845"
            ),
        ];
        assert_eq!(alpha_g1, vk.alpha_g1);
        assert_eq!(beta_g2, vk.beta_g2);
        assert_eq!(gamma_g2, vk.gamma_g2);
        assert_eq!(delta_g2, vk.delta_g2);
        assert_eq!(gamma_abc_g1, vk.gamma_abc_g1);

        let a = vec![vec![(
            ark_bn254::Fr::from_str(
                "20943306190690066775594741490987529540057597548686591419080411327502682591834",
            )
            .unwrap(),
            2,
        )]];
        let b = vec![vec![(
            ark_bn254::Fr::from_str(
                "944936681149208446651664254269745548490766851729442924617792859073125903783",
            )
            .unwrap(),
            3,
        )]];
        assert_eq!(2, matrices.num_instance_variables);
        assert_eq!(3, matrices.num_witness_variables);
        assert_eq!(1, matrices.num_constraints);
        assert_eq!(1, matrices.a_num_non_zero);
        assert_eq!(1, matrices.b_num_non_zero);
        assert_eq!(0, matrices.c_num_non_zero);
        assert_eq!(a, matrices.a);
        assert_eq!(b, matrices.b);
        assert!(matrices.c.is_empty());
    }
    fn fq_from_str(s: &str) -> Fq {
        BigInteger256::try_from(BigUint::from_str(s).unwrap())
            .unwrap()
            .into()
    }

    // Circom snarkjs code:
    // console.log(curve.G1.F.one)
    fn fq_buf() -> Vec<u8> {
        vec![
            157, 13, 143, 197, 141, 67, 93, 211, 61, 11, 199, 245, 40, 235, 120, 10, 44, 70, 121,
            120, 111, 163, 110, 102, 47, 223, 7, 154, 193, 119, 10, 14,
        ]
    }

    // Circom snarkjs code:
    // const buff = new Uint8Array(curve.G1.F.n8*2);
    // curve.G1.toRprLEM(buff, 0, curve.G1.one);
    // console.dir( buff, { 'maxArrayLength': null })
    fn g1_buf() -> Vec<u8> {
        vec![
            157, 13, 143, 197, 141, 67, 93, 211, 61, 11, 199, 245, 40, 235, 120, 10, 44, 70, 121,
            120, 111, 163, 110, 102, 47, 223, 7, 154, 193, 119, 10, 14, 58, 27, 30, 139, 27, 135,
            186, 166, 123, 22, 142, 235, 81, 214, 241, 20, 88, 140, 242, 240, 222, 70, 221, 204,
            94, 190, 15, 52, 131, 239, 20, 28,
        ]
    }

    // Circom snarkjs code:
    // const buff = new Uint8Array(curve.G2.F.n8*2);
    // curve.G2.toRprLEM(buff, 0, curve.G2.one);
    // console.dir( buff, { 'maxArrayLength': null })
    fn g2_buf() -> Vec<u8> {
        vec![
            38, 32, 188, 2, 209, 181, 131, 142, 114, 1, 123, 73, 53, 25, 235, 220, 223, 26, 129,
            151, 71, 38, 184, 251, 59, 80, 150, 175, 65, 56, 87, 25, 64, 97, 76, 168, 125, 115,
            180, 175, 196, 216, 2, 88, 90, 221, 67, 96, 134, 47, 160, 82, 252, 80, 233, 9, 107,
            123, 234, 58, 131, 240, 254, 20, 246, 233, 107, 136, 157, 250, 157, 97, 120, 155, 158,
            245, 151, 210, 127, 254, 254, 125, 27, 35, 98, 26, 158, 255, 6, 66, 158, 174, 235, 126,
            253, 40, 238, 86, 24, 199, 86, 91, 9, 100, 187, 60, 125, 50, 34, 249, 87, 220, 118, 16,
            53, 51, 190, 53, 249, 85, 130, 100, 253, 147, 230, 160, 164, 13,
        ]
    }

    // Circom logs in Projective coordinates: console.log(curve.G1.one)
    fn g1_one() -> G1Affine {
        let x = Fq::one();
        let y = Fq::one() + Fq::one();
        let z = Fq::one();
        G1Affine::from(G1Projective::new(x, y, z))
    }

    // Circom logs in Projective coordinates: console.log(curve.G2.one)
    fn g2_one() -> G2Affine {
        let x = Fq2::new(
            fq_from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            ),
            fq_from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ),
        );

        let y = Fq2::new(
            fq_from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            ),
            fq_from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ),
        );
        let z = Fq2::new(Fq::one(), Fq::zero());
        G2Affine::from(G2Projective::new(x, y, z))
    }

    #[test]
    fn can_deser_fq() {
        let buf = fq_buf();
        let fq = <<Bn254 as Pairing>::BaseField as CircomArkworksPrimeFieldBridge>::from_reader_unchecked(
            &mut &buf[..],
        )
        .unwrap();
        assert_eq!(fq, Fq::one());
    }

    #[test]
    fn can_deser_g1() {
        let buf = g1_buf();
        assert_eq!(buf.len(), 64);
        let g1 = <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(&mut &buf[..]).unwrap();
        let expected = g1_one();
        assert_eq!(g1, expected);
    }

    #[test]
    fn can_deser_g1_vec() {
        let n_vars = 10;
        let buf = vec![g1_buf(); n_vars]
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let expected = vec![g1_one(); n_vars];

        let de = reader_utils::read_g1_vector::<Bn254, _>(buf.as_slice(), n_vars).unwrap();
        assert_eq!(expected, de);
    }

    #[test]
    fn can_deser_g2() {
        let buf = g2_buf();
        assert_eq!(buf.len(), 128);
        let g2 = <Bn254 as CircomArkworksPairingBridge>::g2_from_reader(&mut &buf[..]).unwrap();

        let expected = g2_one();
        assert_eq!(g2, expected);
    }

    #[test]
    fn can_deser_g2_vec() {
        let n_vars = 10;
        let buf = vec![g2_buf(); n_vars]
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let expected = vec![g2_one(); n_vars];

        let de = reader_utils::read_g2_vector::<Bn254, _>(buf.as_slice(), n_vars).unwrap();
        assert_eq!(expected, de);
    }
}
