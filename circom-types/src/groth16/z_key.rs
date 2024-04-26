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

//!Inspired by https://github.com/arkworks-rs/circom-compat/blob/master/src/zkey.rs
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

use super::reader_utils;
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

pub struct ZKey<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
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
    use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ff::BigInteger256;
    use hex_literal::hex;
    use num_bigint::BigUint;
    use std::io::Cursor;

    use num_traits::{One, Zero};
    use std::str::FromStr;

    use std::convert::TryFrom;

    #[test]
    fn test_can_deser_bns254_mult2_key() {
        let z_key_bytes = hex!("7a6b6579010000000a000000010000000400000000000000010000000200000094020000000000002000000047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e643020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e643004000000010000000400000073d28cba1705727b300c4d4f26b7d77b71c1b109c303f566ee57eadabd6c8313f588a3f993020cc302fc175234fddab40d21651861ae718eccf741fa05176000d04a4f69a9f8bad681ce0acbe902b1f02e14a878ebb7bc908a38ee6f18939308a6c2ad63161ac72c6cc5c85e203a2abf11d61a10efbc34aef4602f22abb5b01b42f07aa08bb3808c929049045f73ed151ea66719b6bfa69c1513ae79087b1b2c69dc0d9c5613c4b69113b4272f3d0faa3c28b56f165e77b1e86c5733681ddf2a7986f829092e149fb023795de98714347245f2378004bedcf3d8431cf747fd2f71aaa81d47be705f008d0f4c0daa9a15057f2f763118773b5dced0950638d8122620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40da36f7a3fcaa31639fa1de4e9340a728b606ea769b89403399127030df1a036216267c0c710c65477c42f56e98f68002f795bf7cb3c30bfee7f81049dc7d9581a8b47c02966db6e8dd919cf5621e05ba837d74b70a04dbee16b1965275a368a163b9594c507975fa54f69735161cef3233412da21b07411ee18371c45f64c76223ca9402b2396a4ed245a18cd6c1902d45f9b248c785d0c37ec726c85254cab0bbe68bd5b0219638e3b0a2060a2b4e6c577a4126d9942951cdf38e4e827ad4b1b03000000800000000000000016099153f2fd411668c740ad20fec7945d0469594689b902ba7383d092a95006ac52855e3b00774d0acf93ddc5b5738a5637d1714473992acc1e1906e205152a8d0a6a7d9511bd4f4ccf8e2662f8f78780ccfafefe8b05369b6c10836ec599235ed8db8d3ac77b1ed3e26dcb77626be0a2dc3c76b2e2278bd4b155aefddf591d04000000b400000000000000040000000000000000000000020000005a92de414e0f2928ae165d9696ad35d4d7d7c52d79c2062c845be361c17d4d2e010000000000000003000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000100000000000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000200000001000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d016020500000000010000000000008cf61e3a4aa13425775d5ff08202404060925a652bc93e9a7fc5a7593730be2d712cc7faad322531c590fee8cd90afd05dd28ddd00a7f33b77fdee221dffa317558150d964f094187748565ee4dd8929efec7ff8468ca8defa02476c731d1e2d03347af66d3e0cf5d4ff5c2444302c43330d87881fc9474b3cd4b7f8f86a881a01338ecb9fd282ef5b90ff41e0173348272412e4fb403d2dd5e0dee71f790b1df4ba4803e6aa4fb0d4051225f55c17df12a8ee32172348d17ccbc93459d7eb160000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001338ecb9fd282ef5b90ff41e0173348272412e4fb403d2dd5e0dee71f790b1d534234d530e1d08bb8c45f439c0d6ab84ab0924e9f2208e7acd467ac19777819070000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000552245583201c98d7e1d08be9f26a3b9741d48abb18cbb14c67929066f059a034e3327877ae56e1aff8bbfef09551f809abf656dc9abd20e273aaeda85232a14129d38287e07151d25f31c778ab5b3657d59c19f150e61876a41b915cbdbca11daf37d8c7bf8f354dca303a98c9a4916503e4dee85362bf61b57bda11b806f240800000080000000000000004ffaff4781a89ece9ba6866cdb8a310b5f418cf8a8ae06c76ffe55b47f59a918d205e885c8d78fc110bc066ae84f3e632a0139d4d6facbffe5a8b6091718aa21f440b75a0a5ff596bbe7efb8f3a8767a051b58059d5414226318fd5f0eed5903c77ff3e2665ef1bb36fc61d11e27a5cac401cd61ecbef354c3abf5037b7f232a090000000001000000000000660e10145ad96f4e9e049664fa3fde9677df302a8f3be6f7d230fd9c846cf4292481e35acf32d5959817e9a4c04403f109270aa36728ea969c31dae19c3d36238d5b74b2ae86124c36821344a0dcc50bb843a81a110beb0c2940bad25fd1fc1679e442b8be0aedc8f8fedbd34145adf4b6d3e1cab91d88c5bc2fa1e969e1d71060420f30f57545215671888d8074e7ef8f192f16b3d344b91f6e3fd83532a4094f386432eb27added390f1e6f907b60056095a1a811cd7a70c5ca1645cbe0b212c0d4f04c7a4ec14a9c7b5c9a4e7a2112960d19936c247d9d15a043dbf3b4006c4122e1f0abd347f1eef092a891febbd5d8ed785777933b75dea34f3ce8416180a000000e201000000000000c593936fa72c57811543a377249ccf8e930f3b74036772a935b5ef5164416c22098a5b38d0915cbf31ec277e212136e3318b49bf16fe23bf5e57df9a138084c601000000a36f7a3fcaa31639fa1de4e9340a728b606ea769b89403399127030df1a036216267c0c710c65477c42f56e98f68002f795bf7cb3c30bfee7f81049dc7d9581ac28c81432d0b083576971fce01f4c40ae5ee7acd9a1c53bdcf980b6b4badfc2a98d525f54bc4803ce585b9266a62783f6ab5fd0562b38ad05ca8e00338f44e030a7c623370149f5bc0689c8ad5e6a0dd2006899f2dfaea834f4fb906d0bb2908f17bb7e0a34b0edfba1e5188c70f11c8f2308b1fca2501c8946d672d850fbf17b423e1daba119931cb528e298790b1c46546b760c6293ff5cbffbc33224e1b029582ba3426a0e01eb7abc4fbdb459bf10b5ae51d111d07f83810e63db429190b283f4c8319bad425baf564ca236a5674c602e0577ac87ef9c2e6a9af6448c40771ef2e39619ee39cb62860541031e1dc9d01fd88ff877504751ce6c4a2490e063b4ceaac015e155eafabdaef755fc8223f8c0dbc839a57736233c4cc89d83f763ff1751cfab0f43a03d4cce60f34456261664a4cae5f45a8c725e2e9b8841e4b0000000016000000011431737420436f6e7472696275746f72204e616d65");
        let mut cursor = Cursor::new(z_key_bytes);
        let (pk, matrices) = ZKey::<Bn254>::from_reader(&mut cursor).unwrap().split();
        let beta_g1 = test_utils::to_g1_bn254!(
            "6509821695486859284312268454869307712281179418317998898774137007488098603082",
            "7622311663686293986827366177396357256900943626174592609041771474430550242470"
        );
        let delta_g1 = test_utils::to_g1_bn254!(
            "11638294436898489180373689031443918264064400681169564322618477228067505601905",
            "18600530024588384176785619819313325222076406955549548168323780974190976589003"
        );
        let a_query = vec![
            test_utils::to_g1_bn254!(
                "8999495347371735720375786457530320937480196503672687968076034829867405645534",
                "7964203098330204236753275144892291203073451615792066514555309284656187420305"
            ),
            test_utils::to_g1_bn254!(
                "7011977789023989841253053366767083542292130584075027802249778731708667986978",
                "16553259524258084535258700630374469361384459512994730170858824328214780146158"
            ),
            test_utils::to_g1_bn254!(
                "5208362789939124596528440555146089178559561477772454984868363992669689980431",
                "1641863956683847223438699968865945335648667576811373700356275657059750056531"
            ),
            <Bn254 as Pairing>::G1Affine::identity(),
        ];
        let b_g1_query = vec![
            <Bn254 as Pairing>::G1Affine::identity(),
            <Bn254 as Pairing>::G1Affine::identity(),
            <Bn254 as Pairing>::G1Affine::identity(),
            test_utils::to_g1_bn254!(
                "5208362789939124596528440555146089178559561477772454984868363992669689980431",
                "20246378915155427998807705776391329753047643580486449962332762237585476152052"
            ),
        ];
        let b_g2_query = vec![
            <Bn254 as Pairing>::G2Affine::identity(),
            <Bn254 as Pairing>::G2Affine::identity(),
            <Bn254 as Pairing>::G2Affine::identity(),
            test_utils::to_g2_bn254!(
                { "10984806598173486399859648857310196128374502167199224583217291886389671032517", "12180747581445936540777495602770448320707597259068444145125063956859385122860"},
                { "2838306547647554263781803790589885576143856766149701666545931967506141556022",  "15995546906212226006813754936539460929970961904378637289046410154812213999200"}
            ),
        ];

        let h_query = vec![
            test_utils::to_g1_bn254!(
                "8888515644035596122114651569119522376399221905233494633225108424317247286238",
                "1242829640928070775069944427368816018659820484864505996411719993798427519013"
            ),
            test_utils::to_g1_bn254!(
                "12426143380070367331991788221881569125268369316202125312591661987116548326197",
                "7923779291188213247926647952690135298363149169308620686157370614264257285324"
            ),
            test_utils::to_g1_bn254!(
                "5006916525249355617613108618316197721162516441847200488889682245666693155626",
                "3721981879223522106528198280173501749124279349131408247909956830057508449452"
            ),
            test_utils::to_g1_bn254!(
                "8156388543075417362581136608805205044142163387036967510345940783182813688998",
                "1771631557066366358177172793368102690220978574109826957399908295628416457420"
            ),
        ];
        let l_query = vec![
            test_utils::to_g1_bn254!(
                "21088609292438357291407404785552732752196933744756245771024211217323454503648",
                "10302396483242451425131907597675089781420151481524301300295410654145027967117"
            ),
            test_utils::to_g1_bn254!(
                "20931514859727949606979773132693803113543354259366846081559079815954100630728",
                "17820944147306069087788793851953764220798677637610273475139413872308006840373"
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
            "4273393631443605499166437922168696114401005081410601134980182012685463303330",
            "12082826159527119424778652937508446430232121004054882019301269577382069634755"
        );

        let beta_g2 = test_utils::to_g2_bn254!(
            { "7326677370695219875319538327588127460704970259796099637850289079833196611691", "6470666792586919668453032339444809558017686316372755207047120507826953733841"},
            { "17148475636459145029523998154072530641237370995909726152320413208583676413614", "10400614466445897833963526296791036198889563550789096328142822018618479551903"}
        );
        let gamma_g2 = test_utils::to_g2_bn254!(
            { "10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"},
            { "8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"}
        );
        let delta_g2 = test_utils::to_g2_bn254!(
            { "698314799478462835378244493211042210731741966559651488049251101161975174957", "21745141069920528722051685771323007856464081656487338108847884057483243229868"},
            { "21359365882263546314272854286318823053513380674954397321731766894461123476933", "11311492245124913276603179130444488061083767982989125429743447333700606676186"}
        );
        let gamma_abc_g1 = vec![
            test_utils::to_g1_bn254!(
                "17871991397984966673506808494608320984610247889175425494270627395085539769558",
                "14033615613229177525960295070132774163868274875014945363076425282842706136869"
            ),
            test_utils::to_g1_bn254!(
                "21028766542390158602107055131665304477591245162846282864752589255813666162154",
                "10836584330425710782407342078097057363896428402064890588439686147770081545198"
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

    #[test]
    fn header() {
        // `circom --r1cs` using the below file:
        //
        //  template Multiplier() {
        //     signal private input a;
        //     signal private input b;
        //     signal output c;
        //
        //     c <== a*b;
        // }
        //
        // component main = Multiplier();
        //
        // Then:
        // `snarkjs zkey new circuit.r1cs powersOfTau28_hez_final_10.ptau test.zkey`

        let z_key_bytes = hex!("7a6b6579010000000a000000010000000400000000000000010000000200000094020000000000002000000047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e643020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430040000000100000004000000170e112ab9a4cd01c36bab47402efccfe9ee4b1ae111de3ccf5e5c0f9802eb061e8b0ed6df2c4b3136b0295a1742e43c78027ecbaa357f1192653b4eda5146069840f945d0041e9d6aa03a979a4fcca38578c596dfb79a2e36d45dcf83f12c182aa25aa73eb7fccd9fb51506466af25471c80625317c6be185c35b86eeb01304e02767004aa368d40c5004b499c12979687767a7fe8104f57e1e73065a76f32a583e66c9641cd2331b9feb0e692900c8bf6a17d9e6244072bf850d012f90ca29369114eba7836e8fcd106037ef87fc7224fa34f8c712c6a4dae153a1a98a75153448f8a97a0d2418a87588d3fc40b6b9f9ca5b238c59592df4c6ccab03e7c22a2620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40d9d0d8fc58d435dd33d0bc7f528eb780a2c4679786fa36e662fdf079ac1770a0e3a1b1e8b1b87baa67b168eeb51d6f114588cf2f0de46ddcc5ebe0f3483ef141c2620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40d04000000b400000000000000040000000000000000000000020000005a92de414e0f2928ae165d9696ad35d4d7d7c52d79c2062c845be361c17d4d2e010000000000000003000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000100000000000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000200000001000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d016020300000080000000000000000bcdcdb0026981f3993a89593d5f63a185c999c0771371882b692fcea63751169a4d3a771ce6a0ce8662047370b82e753db4678a8dca6efcc7fc8dd3052ef40a7687c69c3fbed262c23ba9a8cca84cd06daa18c1391fb858eada763a6b815a24e6623ef3033744e37540bc5151f7a14444d28ebfae2b6ec2fd80d90436c46f2b090000000001000000000000154c68221cec87ccda10a073b92c133e2b183963cf690a8bc33c113955f4a70aa6a6a537264b7474b657d9701cedef7be7b47a6d4d745843663050d6892f5e1e90afcd7777c00b0a94e057a19de765d0370f0d10183b09163fd7ff1e4dbc472554e33b1d9f74655dd4dc9f8dcc6b8357ae95af48c76d406db496a0f9f621d41d81a934b342587bc7de451811dbeb76c39cd20e154c9bb2d2df04e90508129c185244b7ba077e02c9cfcf4a2d2cc710a519419dc75a9f0c96fa11b1c1f45de629cf3de5d6153d67a55d91368a8fd60553b716ae576c3b63601314198b72eec628b65801ffce849ca5b2ab00e2b31ec0044fc6452b918574562490be774ff14c10080000008000000000000000928e1deb09a254ff067756d69a120cbeca13a82d1d4cae82063b920fe552512832197cf7810c93236c77b274ee9121b84ac9802997063c549ce1c80ef0ab80141a2070e2a154bcec8de277a9ebdafdb09db86cf3497aefd927beef6993be502fd3449bd48bade5a07b75f36ea2bcd9ce661324bd57b77108a4852b8e8a6d4221050000000001000000000000f0a56ebb4827da3b805532aee501563a7df491cdf8fd7802a58c9a37dcfd0e13d46a3b137dc6ca043b4a0e3e14f8db2feacd36b72177a5542e4b2711e52ac0025d35b15232057b745b230ec42bb4360f5890c56939a73605bc6d115909df500127c1d3a8cb77a969119c356a0b662c5c7bdc9ef061fd1e7904ecab176422850bb12f15edf4494c62500a0a8e509128fe64d667212654eef8fcb54b206d105d17879dce7a6b69caa4c57cf264466c09b4e066fa95820e85b984bdc1e6b48f9c1e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b12f15edf4494c62500a0a8e509128fe64d667212654eef8fcb54b206d105d17c05fae5dab225697c74d7f034bfe77e37cf186eb3337cbfea4e26ffabdbec711070000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f0199de8a43198ccf4beb2b21d85cdafac1c0c7b8bcac40d43a5cc2a4a28062470683d436b704829d5d2f94b59909022b1e4124650c37c52287a5b15c6649a0110eb2904b06a09718dfb64e9bc80c2ad0064ce6e35dfa32fa6eb190c97ee2d004ed2383539d443bdfd843e3e7414eb0ff5711eb6217fcbe77c954adf27bed9290a00000044000000000000004289918fb00ce352b426119d49059905382c440e3439767db58836b96ce102b4ea11be6746375b98850f3fe6d5db5730122e33c765c9a1ec5e9480aacbb49b5d00000000");
        let mut cursor = Cursor::new(z_key_bytes);
        let mut binfile = BinFile::<_, Bn254>::new(&mut cursor).unwrap();
        let header = binfile.groth_header().unwrap();
        assert_eq!(header.n_vars, 4);
        assert_eq!(header.n_public, 1);
        assert_eq!(header.domain_size, 4);
        assert_eq!(header.power, 2);
    }

    #[test]
    fn deser_key() {
        let z_key_bytes = hex!("7a6b6579010000000a000000010000000400000000000000010000000200000094020000000000002000000047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e643020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430040000000100000004000000170e112ab9a4cd01c36bab47402efccfe9ee4b1ae111de3ccf5e5c0f9802eb061e8b0ed6df2c4b3136b0295a1742e43c78027ecbaa357f1192653b4eda5146069840f945d0041e9d6aa03a979a4fcca38578c596dfb79a2e36d45dcf83f12c182aa25aa73eb7fccd9fb51506466af25471c80625317c6be185c35b86eeb01304e02767004aa368d40c5004b499c12979687767a7fe8104f57e1e73065a76f32a583e66c9641cd2331b9feb0e692900c8bf6a17d9e6244072bf850d012f90ca29369114eba7836e8fcd106037ef87fc7224fa34f8c712c6a4dae153a1a98a75153448f8a97a0d2418a87588d3fc40b6b9f9ca5b238c59592df4c6ccab03e7c22a2620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40d9d0d8fc58d435dd33d0bc7f528eb780a2c4679786fa36e662fdf079ac1770a0e3a1b1e8b1b87baa67b168eeb51d6f114588cf2f0de46ddcc5ebe0f3483ef141c2620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40d04000000b400000000000000040000000000000000000000020000005a92de414e0f2928ae165d9696ad35d4d7d7c52d79c2062c845be361c17d4d2e010000000000000003000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000100000000000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000200000001000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d016020300000080000000000000000bcdcdb0026981f3993a89593d5f63a185c999c0771371882b692fcea63751169a4d3a771ce6a0ce8662047370b82e753db4678a8dca6efcc7fc8dd3052ef40a7687c69c3fbed262c23ba9a8cca84cd06daa18c1391fb858eada763a6b815a24e6623ef3033744e37540bc5151f7a14444d28ebfae2b6ec2fd80d90436c46f2b090000000001000000000000154c68221cec87ccda10a073b92c133e2b183963cf690a8bc33c113955f4a70aa6a6a537264b7474b657d9701cedef7be7b47a6d4d745843663050d6892f5e1e90afcd7777c00b0a94e057a19de765d0370f0d10183b09163fd7ff1e4dbc472554e33b1d9f74655dd4dc9f8dcc6b8357ae95af48c76d406db496a0f9f621d41d81a934b342587bc7de451811dbeb76c39cd20e154c9bb2d2df04e90508129c185244b7ba077e02c9cfcf4a2d2cc710a519419dc75a9f0c96fa11b1c1f45de629cf3de5d6153d67a55d91368a8fd60553b716ae576c3b63601314198b72eec628b65801ffce849ca5b2ab00e2b31ec0044fc6452b918574562490be774ff14c10080000008000000000000000928e1deb09a254ff067756d69a120cbeca13a82d1d4cae82063b920fe552512832197cf7810c93236c77b274ee9121b84ac9802997063c549ce1c80ef0ab80141a2070e2a154bcec8de277a9ebdafdb09db86cf3497aefd927beef6993be502fd3449bd48bade5a07b75f36ea2bcd9ce661324bd57b77108a4852b8e8a6d4221050000000001000000000000f0a56ebb4827da3b805532aee501563a7df491cdf8fd7802a58c9a37dcfd0e13d46a3b137dc6ca043b4a0e3e14f8db2feacd36b72177a5542e4b2711e52ac0025d35b15232057b745b230ec42bb4360f5890c56939a73605bc6d115909df500127c1d3a8cb77a969119c356a0b662c5c7bdc9ef061fd1e7904ecab176422850bb12f15edf4494c62500a0a8e509128fe64d667212654eef8fcb54b206d105d17879dce7a6b69caa4c57cf264466c09b4e066fa95820e85b984bdc1e6b48f9c1e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b12f15edf4494c62500a0a8e509128fe64d667212654eef8fcb54b206d105d17c05fae5dab225697c74d7f034bfe77e37cf186eb3337cbfea4e26ffabdbec711070000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f0199de8a43198ccf4beb2b21d85cdafac1c0c7b8bcac40d43a5cc2a4a28062470683d436b704829d5d2f94b59909022b1e4124650c37c52287a5b15c6649a0110eb2904b06a09718dfb64e9bc80c2ad0064ce6e35dfa32fa6eb190c97ee2d004ed2383539d443bdfd843e3e7414eb0ff5711eb6217fcbe77c954adf27bed9290a00000044000000000000004289918fb00ce352b426119d49059905382c440e3439767db58836b96ce102b4ea11be6746375b98850f3fe6d5db5730122e33c765c9a1ec5e9480aacbb49b5d00000000");
        let mut cursor = Cursor::new(z_key_bytes);

        let z_key = ZKey::<Bn254>::from_reader(&mut cursor).unwrap();
        let (params, _matrices) = (z_key.pk, z_key.matrices);

        // Check IC
        let expected = vec![
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    11, 205, 205, 176, 2, 105, 129, 243, 153, 58, 137, 89, 61, 95, 99, 161, 133,
                    201, 153, 192, 119, 19, 113, 136, 43, 105, 47, 206, 166, 55, 81, 22, 154, 77,
                    58, 119, 28, 230, 160, 206, 134, 98, 4, 115, 112, 184, 46, 117, 61, 180, 103,
                    138, 141, 202, 110, 252, 199, 252, 141, 211, 5, 46, 244, 10,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    118, 135, 198, 156, 63, 190, 210, 98, 194, 59, 169, 168, 204, 168, 76, 208,
                    109, 170, 24, 193, 57, 31, 184, 88, 234, 218, 118, 58, 107, 129, 90, 36, 230,
                    98, 62, 243, 3, 55, 68, 227, 117, 64, 188, 81, 81, 247, 161, 68, 68, 210, 142,
                    191, 174, 43, 110, 194, 253, 128, 217, 4, 54, 196, 111, 43,
                ][..],
            )
            .unwrap(),
        ];
        assert_eq!(expected, params.vk.gamma_abc_g1);

        // Check A Query
        let expected = vec![
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    240, 165, 110, 187, 72, 39, 218, 59, 128, 85, 50, 174, 229, 1, 86, 58, 125,
                    244, 145, 205, 248, 253, 120, 2, 165, 140, 154, 55, 220, 253, 14, 19, 212, 106,
                    59, 19, 125, 198, 202, 4, 59, 74, 14, 62, 20, 248, 219, 47, 234, 205, 54, 183,
                    33, 119, 165, 84, 46, 75, 39, 17, 229, 42, 192, 2,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    93, 53, 177, 82, 50, 5, 123, 116, 91, 35, 14, 196, 43, 180, 54, 15, 88, 144,
                    197, 105, 57, 167, 54, 5, 188, 109, 17, 89, 9, 223, 80, 1, 39, 193, 211, 168,
                    203, 119, 169, 105, 17, 156, 53, 106, 11, 102, 44, 92, 123, 220, 158, 240, 97,
                    253, 30, 121, 4, 236, 171, 23, 100, 34, 133, 11,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    177, 47, 21, 237, 244, 73, 76, 98, 80, 10, 10, 142, 80, 145, 40, 254, 100, 214,
                    103, 33, 38, 84, 238, 248, 252, 181, 75, 32, 109, 16, 93, 23, 135, 157, 206,
                    122, 107, 105, 202, 164, 197, 124, 242, 100, 70, 108, 9, 180, 224, 102, 250,
                    149, 130, 14, 133, 185, 132, 189, 193, 230, 180, 143, 156, 30,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
        ];
        assert_eq!(expected, params.a_query);

        // B G1 Query
        let expected = vec![
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    177, 47, 21, 237, 244, 73, 76, 98, 80, 10, 10, 142, 80, 145, 40, 254, 100, 214,
                    103, 33, 38, 84, 238, 248, 252, 181, 75, 32, 109, 16, 93, 23, 192, 95, 174, 93,
                    171, 34, 86, 151, 199, 77, 127, 3, 75, 254, 119, 227, 124, 241, 134, 235, 51,
                    55, 203, 254, 164, 226, 111, 250, 189, 190, 199, 17,
                ][..],
            )
            .unwrap(),
        ];
        assert_eq!(expected, params.b_g1_query);

        // B G2 Query
        let expected = vec![
            <Bn254 as CircomArkworksPairingBridge>::g2_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g2_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g2_from_reader(
                &mut &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g2_from_reader(
                &mut &[
                    240, 25, 157, 232, 164, 49, 152, 204, 244, 190, 178, 178, 29, 133, 205, 175,
                    172, 28, 12, 123, 139, 202, 196, 13, 67, 165, 204, 42, 74, 40, 6, 36, 112, 104,
                    61, 67, 107, 112, 72, 41, 213, 210, 249, 75, 89, 144, 144, 34, 177, 228, 18,
                    70, 80, 195, 124, 82, 40, 122, 91, 21, 198, 100, 154, 1, 16, 235, 41, 4, 176,
                    106, 9, 113, 141, 251, 100, 233, 188, 128, 194, 173, 0, 100, 206, 110, 53, 223,
                    163, 47, 166, 235, 25, 12, 151, 238, 45, 0, 78, 210, 56, 53, 57, 212, 67, 189,
                    253, 132, 62, 62, 116, 20, 235, 15, 245, 113, 30, 182, 33, 127, 203, 231, 124,
                    149, 74, 223, 39, 190, 217, 41,
                ][..],
            )
            .unwrap(),
        ];
        assert_eq!(expected, params.b_g2_query);

        // Check L Query
        let expected = vec![
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    146, 142, 29, 235, 9, 162, 84, 255, 6, 119, 86, 214, 154, 18, 12, 190, 202, 19,
                    168, 45, 29, 76, 174, 130, 6, 59, 146, 15, 229, 82, 81, 40, 50, 25, 124, 247,
                    129, 12, 147, 35, 108, 119, 178, 116, 238, 145, 33, 184, 74, 201, 128, 41, 151,
                    6, 60, 84, 156, 225, 200, 14, 240, 171, 128, 20,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    26, 32, 112, 226, 161, 84, 188, 236, 141, 226, 119, 169, 235, 218, 253, 176,
                    157, 184, 108, 243, 73, 122, 239, 217, 39, 190, 239, 105, 147, 190, 80, 47,
                    211, 68, 155, 212, 139, 173, 229, 160, 123, 117, 243, 110, 162, 188, 217, 206,
                    102, 19, 36, 189, 87, 183, 113, 8, 164, 133, 43, 142, 138, 109, 66, 33,
                ][..],
            )
            .unwrap(),
        ];
        assert_eq!(expected, params.l_query);

        // Check H Query
        let expected = vec![
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    21, 76, 104, 34, 28, 236, 135, 204, 218, 16, 160, 115, 185, 44, 19, 62, 43, 24,
                    57, 99, 207, 105, 10, 139, 195, 60, 17, 57, 85, 244, 167, 10, 166, 166, 165,
                    55, 38, 75, 116, 116, 182, 87, 217, 112, 28, 237, 239, 123, 231, 180, 122, 109,
                    77, 116, 88, 67, 102, 48, 80, 214, 137, 47, 94, 30,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    144, 175, 205, 119, 119, 192, 11, 10, 148, 224, 87, 161, 157, 231, 101, 208,
                    55, 15, 13, 16, 24, 59, 9, 22, 63, 215, 255, 30, 77, 188, 71, 37, 84, 227, 59,
                    29, 159, 116, 101, 93, 212, 220, 159, 141, 204, 107, 131, 87, 174, 149, 175,
                    72, 199, 109, 64, 109, 180, 150, 160, 249, 246, 33, 212, 29,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    129, 169, 52, 179, 66, 88, 123, 199, 222, 69, 24, 17, 219, 235, 118, 195, 156,
                    210, 14, 21, 76, 155, 178, 210, 223, 4, 233, 5, 8, 18, 156, 24, 82, 68, 183,
                    186, 7, 126, 2, 201, 207, 207, 74, 45, 44, 199, 16, 165, 25, 65, 157, 199, 90,
                    159, 12, 150, 250, 17, 177, 193, 244, 93, 230, 41,
                ][..],
            )
            .unwrap(),
            <Bn254 as CircomArkworksPairingBridge>::g1_from_reader(
                &mut &[
                    207, 61, 229, 214, 21, 61, 103, 165, 93, 145, 54, 138, 143, 214, 5, 83, 183,
                    22, 174, 87, 108, 59, 99, 96, 19, 20, 25, 139, 114, 238, 198, 40, 182, 88, 1,
                    255, 206, 132, 156, 165, 178, 171, 0, 226, 179, 30, 192, 4, 79, 198, 69, 43,
                    145, 133, 116, 86, 36, 144, 190, 119, 79, 241, 76, 16,
                ][..],
            )
            .unwrap(),
        ];
        assert_eq!(expected, params.h_query);
    }
}
