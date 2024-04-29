use std::io::Read;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{PrimeField, Zero};
use ark_serialize::SerializationError;
use serde::ser::SerializeSeq;
use serde::Serializer;
use std::str::FromStr;

type IoResult<T> = Result<T, SerializationError>;
pub trait CircomArkworksPairingBridge: Pairing
where
    Self::BaseField: CircomArkworksPrimeFieldBridge,
    Self::ScalarField: CircomArkworksPrimeFieldBridge,
{
    const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    fn g1_from_reader(reader: impl Read) -> IoResult<Self::G1Affine>;
    fn g2_from_reader(reader: impl Read) -> IoResult<Self::G2Affine>;
    fn gt_from_reader(reader: impl Read) -> IoResult<Self::G2Affine>;
    fn g1_from_strings_projective(x: &str, y: &str, z: &str) -> IoResult<Self::G1Affine>;
    fn g2_from_strings_projective(
        x0: &str,
        x1: &str,
        y0: &str,
        y1: &str,
        z0: &str,
        z1: &str,
    ) -> IoResult<Self::G2Affine>;
    fn serialize_g1<S: Serializer>(p: &Self::G1Affine, ser: S) -> Result<S::Ok, S::Error> {
        let (x, y) = p.xy().unwrap();
        let mut seq = ser.serialize_seq(Some(3)).unwrap();
        seq.serialize_element(&x.to_string())?;
        seq.serialize_element(&y.to_string())?;
        seq.serialize_element("1")?;
        seq.end()
    }
    fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error>;
}

pub trait CircomArkworksPrimeFieldBridge: PrimeField {
    const SERIALIZED_BYTE_SIZE: usize;
    //deserializes field elements and performs montgomery reduction
    fn from_reader(reader: impl Read) -> IoResult<Self>;
    //deserializes field elements that are already in montgomery
    //from. DOES NOT perform montgomery reduction
    fn from_reader_unchecked(reader: impl Read) -> IoResult<Self>;
}

/// Module containing the implementation of the Bridge between circom-crypto and arkwors for BN254
mod bn254 {
    use ark_bn254::{Bn254, Fq, Fq2, Fr};
    use ark_ff::BigInt;
    use ark_serialize::{CanonicalDeserialize, SerializationError};

    use super::*;

    macro_rules! parse_bn254_field {
        ($str: expr) => {{
            match ark_bn254::Fq::from_str($str) {
                Ok(x) => x,
                Err(_) => return Err(SerializationError::InvalidData),
            }
        }};
    }
    impl CircomArkworksPrimeFieldBridge for Fr {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_le_bytes_mod_order(&buf))
        }

        #[inline]
        fn from_reader_unchecked(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::new_unchecked(BigInt::deserialize_uncompressed(
                buf.as_slice(),
            )?))
        }
    }
    impl CircomArkworksPrimeFieldBridge for Fq {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_le_bytes_mod_order(&buf))
        }

        #[inline]
        fn from_reader_unchecked(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::new_unchecked(BigInt::deserialize_uncompressed(
                buf.as_slice(),
            )?))
        }
    }

    impl CircomArkworksPairingBridge for Bn254 {
        const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 32;
        const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 32 * 2;
        const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 32 * 2;
        const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 32 * 2 * 2;
        const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 0;
        const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 0;

        //Circom deserializes its field elements in montgomery form
        //therefore we use Fq::from_reader_unchecked
        fn g1_from_reader(mut reader: impl Read) -> IoResult<Self::G1Affine> {
            let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;
            //already in montgomery form
            let x = Fq::from_reader_unchecked(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let y = Fq::from_reader_unchecked(&buf[Fq::SERIALIZED_BYTE_SIZE..])?;

            if x.is_zero() && y.is_zero() {
                return Ok(Self::G1Affine::zero());
            }

            let p = ark_bn254::G1Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn g2_from_reader(mut reader: impl Read) -> IoResult<Self::G2Affine> {
            let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;
            //already in montgomery form
            let x0 = Fq::from_reader_unchecked(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let x1 = Fq::from_reader_unchecked(
                &buf[Fq::SERIALIZED_BYTE_SIZE..Fq::SERIALIZED_BYTE_SIZE * 2],
            )?;
            let y0 = Fq::from_reader_unchecked(
                &buf[Fq::SERIALIZED_BYTE_SIZE * 2..Fq::SERIALIZED_BYTE_SIZE * 3],
            )?;
            let y1 = Fq::from_reader_unchecked(
                &buf[Fq::SERIALIZED_BYTE_SIZE * 3..Fq::SERIALIZED_BYTE_SIZE * 4],
            )?;

            let x = Fq2::new(x0, x1);
            let y = Fq2::new(y0, y1);

            if x.is_zero() && y.is_zero() {
                return Ok(Self::G2Affine::zero());
            }

            let p = Self::G2Affine::new_unchecked(x, y);
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn gt_from_reader(_reader: impl Read) -> IoResult<Self::G2Affine> {
            todo!()
        }

        fn g1_from_strings_projective(x: &str, y: &str, z: &str) -> IoResult<Self::G1Affine> {
            let x = parse_bn254_field!(x);
            let y = parse_bn254_field!(y);
            let z = parse_bn254_field!(z);
            let p = ark_bn254::G1Affine::from(ark_bn254::G1Projective::new(x, y, z));
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn g2_from_strings_projective(
            x0: &str,
            x1: &str,
            y0: &str,
            y1: &str,
            z0: &str,
            z1: &str,
        ) -> IoResult<Self::G2Affine> {
            let x0 = parse_bn254_field!(x0);
            let x1 = parse_bn254_field!(x1);
            let y0 = parse_bn254_field!(y0);
            let y1 = parse_bn254_field!(y1);
            let z0 = parse_bn254_field!(z0);
            let z1 = parse_bn254_field!(z1);

            let x = ark_bn254::Fq2::new(x0, x1);
            let y = ark_bn254::Fq2::new(y0, y1);
            let z = ark_bn254::Fq2::new(z0, z1);
            let p = ark_bn254::G2Affine::from(ark_bn254::G2Projective::new(x, y, z));
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error> {
            let (x, y) = p.xy().unwrap();
            let mut x_seq = ser.serialize_seq(Some(3))?;
            x_seq.serialize_element(&vec![x.c0.to_string(), x.c1.to_string()])?;
            x_seq.serialize_element(&vec![y.c0.to_string(), y.c1.to_string()])?;
            x_seq.serialize_element(&vec!["1", "0"])?;
            x_seq.end()
        }
    }
}

mod bls12_381 {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr};
    use ark_ff::BigInt;
    use ark_serialize::{CanonicalDeserialize, SerializationError};

    use super::*;

    macro_rules! parse_bls12_381_field {
        ($str: expr) => {{
            match ark_bls12_381::Fq::from_str($str) {
                Ok(x) => x,
                Err(_) => return Err(SerializationError::InvalidData),
            }
        }};
    }
    impl CircomArkworksPrimeFieldBridge for Fr {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_le_bytes_mod_order(&buf))
        }

        fn from_reader_unchecked(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::new_unchecked(BigInt::deserialize_uncompressed(
                buf.as_slice(),
            )?))
        }
    }
    impl CircomArkworksPrimeFieldBridge for Fq {
        const SERIALIZED_BYTE_SIZE: usize = 48;
        #[inline]
        fn from_reader(mut reader: impl Read) -> Result<Self, SerializationError> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_le_bytes_mod_order(&buf))
        }

        fn from_reader_unchecked(mut reader: impl Read) -> Result<Self, SerializationError> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::new_unchecked(BigInt::deserialize_uncompressed(
                buf.as_slice(),
            )?))
        }
    }

    impl CircomArkworksPairingBridge for Bls12_381 {
        const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 48;
        const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 48 * 2;
        const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 48 * 2;
        const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 48 * 2 * 2;
        const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 0;
        const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 0;

        //Circom deserializes its field elements in montgomery form
        //therefore we use Fq::from_reader_unchecked
        fn g1_from_reader(mut reader: impl Read) -> Result<Self::G1Affine, SerializationError> {
            let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;
            //already in montgomery form
            let x = Fq::from_reader_unchecked(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let y = Fq::from_reader_unchecked(&buf[Fq::SERIALIZED_BYTE_SIZE..])?;

            if x.is_zero() && y.is_zero() {
                return Ok(Self::G1Affine::zero());
            }
            let p = Self::G1Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }

            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn g2_from_reader(mut reader: impl Read) -> Result<Self::G2Affine, SerializationError> {
            let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;

            //already in montgomery form
            let x0 = Fq::from_reader_unchecked(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let x1 = Fq::from_reader_unchecked(
                &buf[Fq::SERIALIZED_BYTE_SIZE..Fq::SERIALIZED_BYTE_SIZE * 2],
            )?;
            let y0 = Fq::from_reader_unchecked(
                &buf[Fq::SERIALIZED_BYTE_SIZE * 2..Fq::SERIALIZED_BYTE_SIZE * 3],
            )?;
            let y1 = Fq::from_reader_unchecked(
                &buf[Fq::SERIALIZED_BYTE_SIZE * 3..Fq::SERIALIZED_BYTE_SIZE * 4],
            )?;

            let x = Fq2::new(x0, x1);
            let y = Fq2::new(y0, y1);
            if x.is_zero() && y.is_zero() {
                return Ok(Self::G2Affine::zero());
            }

            let p = Self::G2Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn gt_from_reader(_reader: impl Read) -> Result<Self::G2Affine, SerializationError> {
            todo!()
        }

        fn g1_from_strings_projective(x: &str, y: &str, z: &str) -> IoResult<Self::G1Affine> {
            let x = parse_bls12_381_field!(x);
            let y = parse_bls12_381_field!(y);
            let z = parse_bls12_381_field!(z);
            let p = ark_bls12_381::G1Affine::from(ark_bls12_381::G1Projective::new(x, y, z));
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn g2_from_strings_projective(
            x0: &str,
            x1: &str,
            y0: &str,
            y1: &str,
            z0: &str,
            z1: &str,
        ) -> IoResult<Self::G2Affine> {
            let x0 = parse_bls12_381_field!(x0);
            let x1 = parse_bls12_381_field!(x1);
            let y0 = parse_bls12_381_field!(y0);
            let y1 = parse_bls12_381_field!(y1);
            let z0 = parse_bls12_381_field!(z0);
            let z1 = parse_bls12_381_field!(z1);

            let x = ark_bls12_381::Fq2::new(x0, x1);
            let y = ark_bls12_381::Fq2::new(y0, y1);
            let z = ark_bls12_381::Fq2::new(z0, z1);
            let p = ark_bls12_381::G2Affine::from(ark_bls12_381::G2Projective::new(x, y, z));
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }
        fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error> {
            let (x, y) = p.xy().unwrap();
            let mut x_seq = ser.serialize_seq(Some(3))?;
            x_seq.serialize_element(&vec![x.c0.to_string(), x.c1.to_string()])?;
            x_seq.serialize_element(&vec![y.c0.to_string(), y.c1.to_string()])?;
            x_seq.serialize_element(&vec!["1", "0"])?;
            x_seq.end()
        }
    }
}
