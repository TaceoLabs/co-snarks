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
use ark_ff::{BigInteger256, PrimeField};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::log2;
use byteorder::{LittleEndian, ReadBytesExt};

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{ProvingKey, VerifyingKey};
use num_traits::Zero;
type IoResult<T> = Result<T, SerializationError>;

#[derive(Clone, Debug)]
struct Section {
    position: u64,
    #[allow(dead_code)]
    size: usize,
}

/// Reads a SnarkJS ZKey file into an Arkworks ProvingKey.
pub fn read_zkey<R: Read + Seek>(
    mut reader: R,
) -> IoResult<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    let mut binfile = BinFile::new(&mut reader)?;
    let proving_key = binfile.proving_key()?;
    let matrices = binfile.matrices()?;
    Ok((proving_key, matrices))
}

#[derive(Debug)]
struct BinFile<'a, R> {
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    fn new(reader: &'a mut R) -> IoResult<Self> {
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
        })
    }

    fn proving_key(&mut self) -> IoResult<ProvingKey<Bn254>> {
        let header = self.groth_header()?;
        let ic = self.ic(header.n_public)?;

        let a_query = self.a_query(header.n_vars)?;
        let b_g1_query = self.b_g1_query(header.n_vars)?;
        let b_g2_query = self.b_g2_query(header.n_vars)?;
        let l_query = self.l_query(header.n_vars - header.n_public - 1)?;
        let h_query = self.h_query(header.domain_size as usize)?;

        let vk = VerifyingKey::<Bn254> {
            alpha_g1: header.verifying_key.alpha_g1,
            beta_g2: header.verifying_key.beta_g2,
            gamma_g2: header.verifying_key.gamma_g2,
            delta_g2: header.verifying_key.delta_g2,
            gamma_abc_g1: ic,
        };

        let pk = ProvingKey::<Bn254> {
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

    fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        let section = self.get_section(2);
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    fn ic(&mut self, n_public: usize) -> IoResult<Vec<G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    /// Returns the [`ConstraintMatrices`] corresponding to the zkey
    pub fn matrices(&mut self) -> IoResult<ConstraintMatrices<Fr>> {
        let header = self.groth_header()?;

        let section = self.get_section(4);
        self.reader.seek(SeekFrom::Start(section.position))?;
        let num_coeffs: u32 = self.reader.read_u32::<LittleEndian>()?;

        // insantiate AB
        let mut matrices = vec![vec![vec![]; header.domain_size as usize]; 2];
        let mut max_constraint_index = 0;
        for _ in 0..num_coeffs {
            let matrix: u32 = self.reader.read_u32::<LittleEndian>()?;
            let constraint: u32 = self.reader.read_u32::<LittleEndian>()?;
            let signal: u32 = self.reader.read_u32::<LittleEndian>()?;

            let value: Fr = deserialize_field_fr(&mut self.reader)?;
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

    fn a_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    fn b_g1_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    fn b_g2_query(&mut self, n_vars: usize) -> IoResult<Vec<G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    fn l_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    fn h_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    fn g1_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G1Affine>> {
        let section = self.get_section(section_id as u32);
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g1_vec(self.reader, num as u32)
    }

    fn g2_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G2Affine>> {
        let section = self.get_section(section_id as u32);
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g2_vec(self.reader, num as u32)
    }
}

#[derive(Default, Clone, Debug, CanonicalDeserialize)]
pub struct ZVerifyingKey {
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

impl ZVerifyingKey {
    fn new<R: Read>(reader: &mut R) -> IoResult<Self> {
        let alpha_g1 = deserialize_g1(reader)?;
        let beta_g1 = deserialize_g1(reader)?;
        let beta_g2 = deserialize_g2(reader)?;
        let gamma_g2 = deserialize_g2(reader)?;
        let delta_g1 = deserialize_g1(reader)?;
        let delta_g2 = deserialize_g2(reader)?;

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
struct HeaderGroth {
    #[allow(dead_code)]
    n8q: u32,
    #[allow(dead_code)]
    q: BigInteger256,
    #[allow(dead_code)]
    n8r: u32,
    #[allow(dead_code)]
    r: BigInteger256,

    n_vars: usize,
    n_public: usize,

    domain_size: u32,
    #[allow(dead_code)]
    power: u32,

    verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> IoResult<Self> {
        // TODO: Impl From<u32> in Arkworks
        let n8q: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // group order r of Bn254
        let q = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n8r: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // Prime field modulus
        let r = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n_vars = u32::deserialize_uncompressed(&mut reader)? as usize;
        let n_public = u32::deserialize_uncompressed(&mut reader)? as usize;
        println!("n_pub is {n_public}");

        let domain_size: u32 = u32::deserialize_uncompressed(&mut reader)?;
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;
        Ok(Self {
            n8q,
            q,
            n8r,
            r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

// need to divide by R, since snarkjs outputs the zkey with coefficients
// multiplieid by R^2
fn deserialize_field_fr<R: Read>(reader: &mut R) -> IoResult<Fr> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    Ok(Fr::new_unchecked(Fr::new_unchecked(bigint).into_bigint()))
}

// skips the multiplication by R because Circom points are already in Montgomery form
fn deserialize_field<R: Read>(reader: &mut R) -> IoResult<Fq> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    // if you use Fq::new it multiplies by R
    Ok(Fq::new_unchecked(bigint))
}

pub fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
    let c0 = deserialize_field(reader)?;
    let c1 = deserialize_field(reader)?;
    Ok(Fq2::new(c0, c1))
}

fn deserialize_g1<R: Read>(reader: &mut R) -> IoResult<G1Affine> {
    let x = deserialize_field(reader)?;
    let y = deserialize_field(reader)?;
    let infinity = x.is_zero() && y.is_zero();
    if infinity {
        Ok(G1Affine::identity())
    } else {
        println!("({x}; {y})");
        Ok(G1Affine::new(x, y))
    }
}

fn deserialize_g2<R: Read>(reader: &mut R) -> IoResult<G2Affine> {
    let f1 = deserialize_field2(reader)?;
    let f2 = deserialize_field2(reader)?;
    let infinity = f1.is_zero() && f2.is_zero();
    if infinity {
        Ok(G2Affine::identity())
    } else {
        Ok(G2Affine::new(f1, f2))
    }
}

fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G1Affine>> {
    (0..n_vars).map(|_| deserialize_g1(reader)).collect()
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G2Affine>> {
    (0..n_vars).map(|_| deserialize_g2(reader)).collect()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use hex_literal::hex;

    use crate::groth16::z_key::read_zkey;

    use super::deserialize_g1;

    #[test]
    fn test() {
        //from their test
        //deserialize_g1(
        //    &mut &[
        //        207, 61, 229, 214, 21, 61, 103, 165, 93, 145, 54, 138, 143, 214, 5, 83, 183, 22,
        //        174, 87, 108, 59, 99, 96, 19, 20, 25, 139, 114, 238, 198, 40, 182, 88, 1, 255, 206,
        //        132, 156, 165, 178, 171, 0, 226, 179, 30, 192, 4, 79, 198, 69, 43, 145, 133, 116,
        //        86, 36, 144, 190, 119, 79, 241, 76, 16,
        //    ][..],
        //)
        //.unwrap();
        let z_key_bytes = hex!("7a6b6579010000000a000000010000000400000000000000010000000200000094020000000000002000000047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e643020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430040000000100000004000000027e9fb2cb94e617cd71cc2ef8637b40ead6441b089d8ba88f60ce98e87c9117146737fd7cd8fa501f67b70ac52838cc6a7c08099a814e45430874985fd1a80e0ec211c22c964bd5cd445e61a0bfac6d353eb2f0d860e3f86b05ea912ed3b32eaf3045d1d5305dbe0f0b415ec9fd5ce45572436831d88cb4ed7d8844be0b90139a9d12878646b78d32cc7d394c7f446e5bee9bad78cc38233db3e5ef554a952701c8300b58a5338cf86354145f3b8c8cecb394c9b102d8289a70d81df6bcfd2ad8bd985423ab08ee87af16e135869c16024ad30a16b697bafa1e73820d8da81765c28f93acbc9d19014db813ee2433245e24e6f56e7bba1353ea2f7afdb5520c2620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40d4cc19c40b7d561175b65dc98b92614ddd285a11be8e03cf18267321d5e0a62191f51760b48b5773f5680c494f84f59957624c022fa1facffc2dcaa565bddf109b494d100145a1962f8c1018a7e66ded58529e19446efbc393847ba842881c025d8b2c85bcb10e71ba9c8c31120fae71fa5ed983349384f30519a2c7949d8280a5cb12f9b189bce1c74d03018778c614e09d04905cfeada5e992cbb5d7619202cd49b35b903bf71ec6da3df34317b64ee08c336be712a25696eaa847e990f8929030000008000000000000000bc6933dd9846cd05a4d9641a37bbeb13db86b46015b1f78ba12cbf7296f4f11b44e263a510cd1612aefce8f063b0f8ee0790808e5ca6c53124371d9911feff0544a00e56c32c632390a35e20d1ad882b25f434917da80cdbb1e5cb40b688d72b1fcd57dcf9a06192523cde9efc0bc8f90a8b683ba855e13eed86e89211ba5d1404000000b400000000000000040000000000000000000000020000005a92de414e0f2928ae165d9696ad35d4d7d7c52d79c2062c845be361c17d4d2e010000000000000003000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000100000000000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602000000000200000001000000a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602050000000001000000000000376ae13e3ec67daf95c78bf929ac32038b9ab751cb5038b1b1c1741cb9cd7b0fcd938d847229faea26b8296a5bcfb5f2395ce66521af09041dcd87a04c9ab521c2ada80dd6091a02f6a373cd8b25404cdb9948044d2b7895a8701ae396dc552ba15dc7bbb2f9d1d45fa2e9073ce6a5e2360d2b0483006ffb50cf3b0757a351303c786effb730f67d404dc88dfd98e3c73045ed6408c318b8f23038db3c2910214aee016adb9f87bd61029e253fed08f753740565a93f322c0179a8e2f06aec00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c786effb730f67d404dc88dfd98e3c73045ed6408c318b8f23038db3c291021fd0e7b6e3bec987e2bc8d342527d78a009e47b1c0d061e8c282789fe81e3772f07000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012303fe547c275b0fc7c3358bb1ee15f4c209584d7e30e4469a9a7265cde271c68d3a5ea5fb2a392c820f4fe7a4b49a75882bf30b56c9d992cf8154c4536dc17cd186b9211092e366e4a038ea9e2331b27f36844dd12fd89359b26cc79471c0da960f490a7467661d530e69c95a538279434a80aec7d6a5bb9ce58538de50807080000008000000000000000454ee619c4f07b4f111a00adbed1265da783bbbf28bc57ee8d60a2915e991401819dc403af67a1efef7024e3b151749cae633e6a582a3bb89bbb4d8e75afef021ae3567ce80d2c00c8e41fcc470b2adee059f1e650982ba5a989b4d8153d270f1ce6b90463d2ef2c6b6a4d95925c25e5e23bf9e6bb6ea43b5aa1ae9dce997e01090000000001000000000000c4e3ec12c510235d6e263f1e7367ee81bb50ef0878e00d669e4d40ac4a490e11e8dc6bb0c90c78f2ebdf46dfbd289e45f74aa72e78e8ec4baaf94420d1fca60b05058fea6355ba4c984f982a05229a9b93f5971437bae66327322914691b4d09d2a84b7926593ae93901f537a13c49d3d1b4f37324c975139c2051e72a23e3240cce6f0675357bcb0a1d5b0c427be3cb4d75eabd17b15ec94bf1ef95b7a82608d0c44e2989b56784f1eb375ebc88d3ba0ef3ce02d6220934ee14a1eb2281102e721b3014e1de6672d2b2cfbd51b11a42ed0bd72356ed19b9ec61d89756da120de089f5c570aaa74bfc59e4ec4f4c6ab4fc130843b01e98f14897b5ebd8aeaf1f0a000000e201000000000000d18d78a175674762ef69537202f163bcf68ad4365446b60a60163c70f08ce738765a4f0ace202dfbc7a59bc908857bf231f2c0c28e43ee6afcd2c704b7d89a99010000004cc19c40b7d561175b65dc98b92614ddd285a11be8e03cf18267321d5e0a62191f51760b48b5773f5680c494f84f59957624c022fa1facffc2dcaa565bddf109fe9539180b6c662f98b6e0fb8a2b89e07534cb916139e428e8be431f6e80711cf8565e631fde06d56e1c4d5250ca6e3b7bb53cd34aa1d787f2e9a99634e26d244c00c34128f4acbe221686fe7b8e31c4473bed6c58fa102ac525629d7d65ea03308fc340098bc56c78eadb551956d1f66af693232bbc75df6bf474c9080da304669467aa327905ef72a039f2031c8f5383d4eec8b1f41be855b8b155504b0e1fb6dd5be0376bec9a1846e496d3ba706913a5409f61bc45929e3fcf3b18c343155643da8c44e0027c5646cb0d2383edc3a1c92e9546d24ff5a346c145ff11342134b337402c210cf58f28a437986b81f1353b0b82fbbb1fcdfd2108ef3e5d6010d45a7de7ab09c65f85d663194d0ba3af7f3af53e28dcf85929878393e282ac7fb12991cdee39319bdd15c5fe3cbe1cfe99b70826fa87806a2a47fdae59a5dc9f0000000016000000011431737420436f6e7472696275746f72204e616d65");
        let mut cursor = Cursor::new(z_key_bytes);
        let test = read_zkey(&mut cursor);
    }
}
