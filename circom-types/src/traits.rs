use std::io::Read;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{PrimeField, Zero};
use ark_serialize::SerializationError;

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
}

pub trait CircomArkworksPrimeFieldBridge: PrimeField {
    const SERIALIZED_BYTE_SIZE: usize;
    //deserializes field elements and performs montgomery reduction
    fn from_reader(reader: impl Read) -> IoResult<Self>;
    //deserializes field elements that are already in montgomery
    //from. DOES NOT perform montgomery reduction
    fn from_reader_unchecked(reader: impl Read) -> IoResult<Self>;
}

pub mod reader_utils {}

/// Module containing the implementation of the Bridge between circom-crypto and arkwors for BN254
mod bn254 {
    use ark_bn254::{Bn254, Fq, Fq2, Fr};
    use ark_ff::BigInt;
    use ark_serialize::{CanonicalDeserialize, SerializationError};

    use super::*;

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
    }
}

mod bls12_381 {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr};
    use ark_ff::BigInt;
    use ark_serialize::{CanonicalDeserialize, SerializationError};

    use super::*;

    impl CircomArkworksPrimeFieldBridge for Fr {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> IoResult<Self> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_be_bytes_mod_order(&buf))
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
            Ok(Self::from_be_bytes_mod_order(&buf))
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

        fn g1_from_reader(mut reader: impl Read) -> Result<Self::G1Affine, SerializationError> {
            todo!()
            //let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            //reader.read_exact(&mut buf)?;
            //let flag = buf[0] & FLAG_MASK;
            //if invalid_mask(flag) {
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "invalid mask encoding",
            //    ));
            //}
            //if flag != FLAG_UNCOMPRESSED && flag != FLAG_UNCOMPRESSED_INFINITY {
            //    // TODO: handle point compression
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "invalid flag, expected uncompressed points",
            //    ));
            //}
            //if flag == FLAG_UNCOMPRESSED_INFINITY {
            //    buf[0] = buf[0] & !FLAG_MASK;
            //    if buf.iter().all(|&b| b == 0) {
            //        return Ok(Self::G1Affine::zero());
            //    } else {
            //        return Err(std::io::Error::new(
            //            std::io::ErrorKind::InvalidData,
            //            "invalid uncompressed infinity point",
            //        ));
            //    }
            //}

            //// uncompressed point
            //let x = Fq::from_reader(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            //let y = Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE..])?;

            //let p = Self::G1Affine::new_unchecked(x, y);

            //if !p.is_on_curve() {
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "point is not on curve",
            //    ));
            //}

            //if !p.is_in_correct_subgroup_assuming_on_curve() {
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "point is not in correct subgroup",
            //    ));
            //}
            //Ok(p)
        }

        fn g2_from_reader(mut _reader: impl Read) -> Result<Self::G2Affine, SerializationError> {
            todo!()
            //let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            //reader.read_exact(&mut buf)?;

            //let flag = buf[0] & FLAG_MASK;
            //if invalid_mask(flag) {
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "invalid mask encoding",
            //    ));
            //}
            //if flag != FLAG_UNCOMPRESSED && flag != FLAG_UNCOMPRESSED_INFINITY {
            //    // TODO: handle point compression
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "invalid flag, expected uncompressed points",
            //    ));
            //}
            //if flag == FLAG_UNCOMPRESSED_INFINITY {
            //    buf[0] = buf[0] & !FLAG_MASK;
            //    if buf.iter().all(|&b| b == 0) {
            //        return Ok(Self::G2Affine::zero());
            //    } else {
            //        return Err(std::io::Error::new(
            //            std::io::ErrorKind::InvalidData,
            //            "invalid uncompressed infinity point",
            //        ));
            //    }
            //}

            //let x1 = Fq::from_reader(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            //let x0 = Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE..Fq::SERIALIZED_BYTE_SIZE * 2])?;
            //let y1 =
            //    Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE * 2..Fq::SERIALIZED_BYTE_SIZE * 3])?;
            //let y0 =
            //    Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE * 3..Fq::SERIALIZED_BYTE_SIZE * 4])?;

            //let x = Fq2::new(x0, x1);
            //let y = Fq2::new(y0, y1);

            //let p = Self::G2Affine::new_unchecked(x, y);

            //if !p.is_on_curve() {
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "point is not on curve",
            //    ));
            //}
            //if !p.is_in_correct_subgroup_assuming_on_curve() {
            //    return Err(std::io::Error::new(
            //        std::io::ErrorKind::InvalidData,
            //        "point is not in correct subgroup",
            //    ));
            //}
            //Ok(p)
        }

        fn gt_from_reader(_reader: impl Read) -> Result<Self::G2Affine, SerializationError> {
            todo!()
        }
    }
}
