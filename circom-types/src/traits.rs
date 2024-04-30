use std::io::Read;
use std::marker::PhantomData;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{PrimeField, Zero};
use ark_serialize::SerializationError;
use serde::ser::SerializeSeq;
use serde::{de, Serializer};
use std::str::FromStr;

type IoResult<T> = Result<T, SerializationError>;

macro_rules! implement_gt_visitor {
    ($config: ident, $curve: ident, $name: expr, $parser: ident) => {
    impl<'de> de::Visitor<'de> for TargetGroupVisitor<$config> {
        type Value = $curve::Fq12;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str(
                &format!("An element of {}::Fq12 represented as string with radix 10. Must be a sequence of form [[[String; 2]; 3]; 2].", $name),
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let x = seq
                .next_element::<Vec<Vec<String>>>()?
                .ok_or(de::Error::custom(
                    &format!("expected elements target group in {} as sequence of sequences", $name),
                ))?;
            let y = seq
                .next_element::<Vec<Vec<String>>>()?
                .ok_or(de::Error::custom(
                    &format!("expected elements target group in {} as sequence of sequences", $name),
                ))?;
            if x.len() != 3 || y.len() != 3 {
                Err(de::Error::custom(
                    &format!("need three elements for cubic extension field in {}", $name),
                ))
            } else {
                let c0 = cubic_extension_field_from_vec(x).map_err(|_| {
                    de::Error::custom("InvalidData for target group (cubic extension field)")
                })?;
                let c1 = cubic_extension_field_from_vec(y).map_err(|_| {
                    de::Error::custom("InvalidData for target group (cubic extension field)")
                })?;
                Ok($curve::Fq12::new(c0, c1))
            }
        }
    }
    #[inline]
    fn cubic_extension_field_from_vec(strings: Vec<Vec<String>>) -> IoResult<$curve::Fq6> {
        if strings.len() != 3 {
            Err(SerializationError::InvalidData)
        } else {
            let c0 = quadratic_extension_field_from_vec(&strings[0])?;
            let c1 = quadratic_extension_field_from_vec(&strings[1])?;
            let c2 = quadratic_extension_field_from_vec(&strings[2])?;
            Ok($curve::Fq6::new(c0, c1, c2))
        }
    }
    #[inline]
    fn quadratic_extension_field_from_vec(strings: &[String]) -> IoResult<$curve::Fq2> {
        if strings.len() != 2 {
            Err(SerializationError::InvalidData)
        } else {
            let c0 = $parser!(&strings[0]);
            let c1 = $parser!(&strings[1]);
            Ok($curve::Fq2::new(c0, c1))
        }
    }
    };
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

impl<P: Pairing + CircomArkworksPairingBridge> TargetGroupVisitor<P>
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
            .write_str("a sequence of 3 sequences, representing a projective point on G2. The 3 sequences each consist of two strings")
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

struct TargetGroupVisitor<P: Pairing + CircomArkworksPairingBridge>
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

    fn deserialize_g1_element<'de, D>(deserializer: D) -> Result<Self::G1Affine, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(G1Visitor::<Self>::new())
    }
    fn deserialize_g2_element<'de, D>(deserializer: D) -> Result<Self::G2Affine, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(G2Visitor::<Self>::new())
    }
    fn deserialize_gt_element<'de, D>(deserializer: D) -> Result<Self::TargetField, D::Error>
    where
        D: de::Deserializer<'de>;

    fn serialize_g1<S: Serializer>(p: &Self::G1Affine, ser: S) -> Result<S::Ok, S::Error> {
        let strings = Self::g1_to_strings_projective(p);
        let mut seq = ser.serialize_seq(Some(strings.len())).unwrap();
        for ele in strings {
            seq.serialize_element(&ele)?;
        }
        seq.end()
    }
    fn g1_to_strings_projective(p: &Self::G1Affine) -> Vec<String>;
    fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error>;
    fn serialize_gt<S: Serializer>(p: &Self::TargetField, ser: S) -> Result<S::Ok, S::Error>;
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
    use serde::ser::SerializeSeq;

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
            if p.is_zero() {
                return Ok(p);
            }
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn g1_to_strings_projective(p: &Self::G1Affine) -> Vec<String> {
            if let Some((x, y)) = p.xy() {
                vec![x.to_string(), y.to_string(), "1".to_owned()]
            } else {
                //point at infinity
                vec!["0".to_owned(), "0".to_owned(), "1".to_owned()]
            }
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
            if p.is_zero() {
                return Ok(p);
            }
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
        fn serialize_gt<S: Serializer>(p: &Self::TargetField, ser: S) -> Result<S::Ok, S::Error> {
            let a = p.c0;
            let b = p.c1;
            let aa = a.c0;
            let ab = a.c1;
            let ac = a.c2;
            let ba = b.c0;
            let bb = b.c1;
            let bc = b.c2;
            let a = vec![
                vec![aa.c0.to_string(), aa.c1.to_string()],
                vec![ab.c0.to_string(), ab.c1.to_string()],
                vec![ac.c0.to_string(), ac.c1.to_string()],
            ];
            let b = vec![
                vec![ba.c0.to_string(), ba.c1.to_string()],
                vec![bb.c0.to_string(), bb.c1.to_string()],
                vec![bc.c0.to_string(), bc.c1.to_string()],
            ];
            let mut seq = ser.serialize_seq(Some(2))?;
            seq.serialize_element(&a)?;
            seq.serialize_element(&b)?;
            seq.end()
        }

        fn deserialize_gt_element<'de, D>(deserializer: D) -> Result<Self::TargetField, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_seq(TargetGroupVisitor::<Self>::new())
        }
    }
    implement_gt_visitor!(Bn254, ark_bn254, "bn254", parse_bn254_field);
}

mod bls12_381 {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr};
    use ark_ff::BigInt;
    use ark_serialize::{CanonicalDeserialize, SerializationError};
    use serde::ser::SerializeSeq;

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
            let p =
                ark_bls12_381::G1Affine::from(ark_bls12_381::G1Projective::new_unchecked(x, y, z));
            if p.is_zero() {
                return Ok(p);
            }
            if !p.is_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }
        fn g1_to_strings_projective(p: &Self::G1Affine) -> Vec<String> {
            if let Some((x, y)) = p.xy() {
                vec![x.to_string(), y.to_string(), "1".to_owned()]
            } else {
                //point at infinity
                vec!["0".to_owned(), "0".to_owned(), "1".to_owned()]
            }
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
            if p.is_zero() {
                return Ok(p);
            }
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

        fn serialize_gt<S: Serializer>(p: &Self::TargetField, ser: S) -> Result<S::Ok, S::Error> {
            let a = p.c0;
            let b = p.c1;
            let aa = a.c0;
            let ab = a.c1;
            let ac = a.c2;
            let ba = b.c0;
            let bb = b.c1;
            let bc = b.c2;
            let a = vec![
                vec![aa.c0.to_string(), aa.c1.to_string()],
                vec![ab.c0.to_string(), ab.c1.to_string()],
                vec![ac.c0.to_string(), ac.c1.to_string()],
            ];
            let b = vec![
                vec![ba.c0.to_string(), ba.c1.to_string()],
                vec![bb.c0.to_string(), bb.c1.to_string()],
                vec![bc.c0.to_string(), bc.c1.to_string()],
            ];
            let mut seq = ser.serialize_seq(Some(2))?;
            seq.serialize_element(&a)?;
            seq.serialize_element(&b)?;
            seq.end()
        }
        fn deserialize_gt_element<'de, D>(deserializer: D) -> Result<Self::TargetField, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_seq(TargetGroupVisitor::<Self>::new())
        }
    }

    implement_gt_visitor!(Bls12_381, ark_bls12_381, "bls12_381", parse_bls12_381_field);
}
