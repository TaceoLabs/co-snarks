use std::io::Read;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{PrimeField, Zero};

pub enum PointCompression {
    Disabled,
    Enabled,
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
    fn g1_from_reader(reader: impl Read) -> Result<Self::G1Affine, std::io::Error>;
    fn g2_from_reader(reader: impl Read) -> Result<Self::G2Affine, std::io::Error>;
    fn gt_from_reader(reader: impl Read) -> Result<Self::G2Affine, std::io::Error>;
}

pub trait CircomArkworksPrimeFieldBridge: PrimeField {
    const SERIALIZED_BYTE_SIZE: usize;
    fn from_reader(reader: impl Read) -> Result<Self, std::io::Error>;
}

pub mod reader_utils {

    use ark_ec::pairing::Pairing;
    use ark_serialize::Read;
    use byteorder::{BigEndian, ReadBytesExt};

    use super::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};

    #[inline]
    pub(crate) fn read_g1_vector<P: Pairing + CircomArkworksPairingBridge, R: Read>(
        mut reader: R,
    ) -> Result<Vec<P::G1Affine>, std::io::Error>
    where
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        (0..reader.read_u32::<BigEndian>()?)
            .map(|_| P::g1_from_reader(&mut reader))
            .collect::<Result<Vec<_>, std::io::Error>>()
    }
    #[inline]
    pub(crate) fn read_g2_vector<P: Pairing + CircomArkworksPairingBridge, R: Read>(
        mut reader: R,
    ) -> Result<Vec<P::G2Affine>, std::io::Error>
    where
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        (0..reader.read_u32::<BigEndian>()?)
            .map(|_| P::g2_from_reader(&mut reader))
            .collect::<Result<Vec<_>, std::io::Error>>()
    }

    #[inline]
    pub(crate) fn read_bool_vector<R: Read>(
        amount: u64,
        mut reader: R,
    ) -> Result<Vec<bool>, std::io::Error> {
        (0..amount)
            .map(|_| reader.read_u8().map(|b| b == 1))
            .collect::<Result<Vec<_>, std::io::Error>>()
    }

    #[inline]
    pub(crate) fn read_int_array<R: Read>(mut reader: R) -> Result<Vec<Vec<u64>>, std::io::Error> {
        let x = reader.read_u32::<BigEndian>()?;
        let mut result = Vec::with_capacity(usize::try_from(x).expect("u32 fits into usize"));
        for _ in 0..x {
            let y = reader.read_u32::<BigEndian>()?;
            result.push(
                (0..y)
                    .map(|_| reader.read_u64::<BigEndian>())
                    .collect::<Result<Vec<u64>, std::io::Error>>()?,
            );
        }
        Ok(result)
    }
}

/// Module containing the implementation of the Bridge between gnark-crypto and arkwors for BN254
mod bn254 {
    use ark_bn254::{Bn254, Fq, Fq2, Fr};

    use super::*;

    impl CircomArkworksPrimeFieldBridge for Fr {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> Result<Self, std::io::Error> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_le_bytes_mod_order(&buf))
        }
    }
    impl CircomArkworksPrimeFieldBridge for Fq {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> Result<Self, std::io::Error> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_le_bytes_mod_order(&buf))
        }
    }

    const FLAG_MASK: u8 = 0b11 << 6;
    const FLAG_UNCOMPRESSED: u8 = 0b00 << 6;
    const FLAG_COMPRESSED_SMALLEST: u8 = 0b10 << 6;
    const FLAG_COMPRESSED_LARGEST: u8 = 0b11 << 6;
    const FLAG_COMPRESSED_INFINITY: u8 = 0b01 << 6;

    impl CircomArkworksPairingBridge for Bn254 {
        const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 32;
        const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 32 * 2;
        const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 32 * 2;
        const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 32 * 2 * 2;
        const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 0;
        const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 0;

        fn g1_from_reader(mut reader: impl Read) -> Result<Self::G1Affine, std::io::Error> {
            let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;
            let flag = buf[0] & FLAG_MASK;
            if flag != FLAG_UNCOMPRESSED {
                // TODO: handle point compression
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid flag, expected uncompressed points",
                ));
            }
            let x = Fq::from_reader(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let y = Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE..])?;

            if x.is_zero() && y.is_zero() {
                return Ok(Self::G1Affine::zero());
            }

            let p = ark_bn254::G1Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not on curve",
                ));
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not in correct subgroup",
                ));
            }
            Ok(p)
        }

        fn g2_from_reader(mut reader: impl Read) -> Result<Self::G2Affine, std::io::Error> {
            let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;
            let flag = buf[0] & FLAG_MASK;
            if flag != FLAG_UNCOMPRESSED {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid flag, expected uncompressed points",
                ));
            }
            let x1 = Fq::from_reader(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let x0 = Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE..Fq::SERIALIZED_BYTE_SIZE * 2])?;
            let y1 =
                Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE * 2..Fq::SERIALIZED_BYTE_SIZE * 3])?;
            let y0 =
                Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE * 3..Fq::SERIALIZED_BYTE_SIZE * 4])?;

            let x = Fq2::new(x0, x1);
            let y = Fq2::new(y0, y1);

            if x.is_zero() && y.is_zero() {
                return Ok(Self::G2Affine::zero());
            }

            let p = Self::G2Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not on curve",
                ));
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not in correct subgroup",
                ));
            }
            Ok(p)
        }

        fn gt_from_reader(reader: impl Read) -> Result<Self::G2Affine, std::io::Error> {
            todo!()
        }
    }
}

mod bls12_381 {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr};

    use super::*;

    impl CircomArkworksPrimeFieldBridge for Fr {
        const SERIALIZED_BYTE_SIZE: usize = 32;
        #[inline]
        fn from_reader(mut reader: impl Read) -> Result<Self, std::io::Error> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_be_bytes_mod_order(&buf))
        }
    }
    impl CircomArkworksPrimeFieldBridge for Fq {
        const SERIALIZED_BYTE_SIZE: usize = 48;
        #[inline]
        fn from_reader(mut reader: impl Read) -> Result<Self, std::io::Error> {
            let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
            reader.read_exact(&mut buf[..])?;
            Ok(Self::from_be_bytes_mod_order(&buf))
        }
    }

    const FLAG_MASK: u8 = 0b111 << 5;
    const FLAG_UNCOMPRESSED: u8 = 0b000 << 5;
    const FLAG_UNCOMPRESSED_INFINITY: u8 = 0b010 << 5;
    const FLAG_COMPRESSED_SMALLEST: u8 = 0b100 << 5;
    const FLAG_COMPRESSED_LARGEST: u8 = 0b101 << 5;
    const FLAG_COMPRESSED_INFINITY: u8 = 0b110 << 5;

    fn invalid_mask(mask: u8) -> bool {
        match mask & FLAG_MASK {
            FLAG_UNCOMPRESSED => false,
            FLAG_UNCOMPRESSED_INFINITY => false,
            FLAG_COMPRESSED_SMALLEST => false,
            FLAG_COMPRESSED_LARGEST => false,
            FLAG_COMPRESSED_INFINITY => false,
            _ => true,
        }
    }

    impl CircomArkworksPairingBridge for Bls12_381 {
        const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 48;
        const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 48 * 2;
        const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 48 * 2;
        const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 48 * 2 * 2;
        const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 0;
        const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 0;

        fn g1_from_reader(mut reader: impl Read) -> Result<Self::G1Affine, std::io::Error> {
            let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;
            let flag = buf[0] & FLAG_MASK;
            if invalid_mask(flag) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid mask encoding",
                ));
            }
            if flag != FLAG_UNCOMPRESSED && flag != FLAG_UNCOMPRESSED_INFINITY {
                // TODO: handle point compression
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid flag, expected uncompressed points",
                ));
            }
            if flag == FLAG_UNCOMPRESSED_INFINITY {
                buf[0] = buf[0] & !FLAG_MASK;
                if buf.iter().all(|&b| b == 0) {
                    return Ok(Self::G1Affine::zero());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid uncompressed infinity point",
                    ));
                }
            }

            // uncompressed point
            let x = Fq::from_reader(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let y = Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE..])?;

            let p = Self::G1Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not on curve",
                ));
            }

            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not in correct subgroup",
                ));
            }
            Ok(p)
        }

        fn g2_from_reader(mut reader: impl Read) -> Result<Self::G2Affine, std::io::Error> {
            let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
            reader.read_exact(&mut buf)?;

            let flag = buf[0] & FLAG_MASK;
            if invalid_mask(flag) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid mask encoding",
                ));
            }
            if flag != FLAG_UNCOMPRESSED && flag != FLAG_UNCOMPRESSED_INFINITY {
                // TODO: handle point compression
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid flag, expected uncompressed points",
                ));
            }
            if flag == FLAG_UNCOMPRESSED_INFINITY {
                buf[0] = buf[0] & !FLAG_MASK;
                if buf.iter().all(|&b| b == 0) {
                    return Ok(Self::G2Affine::zero());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid uncompressed infinity point",
                    ));
                }
            }

            let x1 = Fq::from_reader(&buf[..Fq::SERIALIZED_BYTE_SIZE])?;
            let x0 = Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE..Fq::SERIALIZED_BYTE_SIZE * 2])?;
            let y1 =
                Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE * 2..Fq::SERIALIZED_BYTE_SIZE * 3])?;
            let y0 =
                Fq::from_reader(&buf[Fq::SERIALIZED_BYTE_SIZE * 3..Fq::SERIALIZED_BYTE_SIZE * 4])?;

            let x = Fq2::new(x0, x1);
            let y = Fq2::new(y0, y1);

            let p = Self::G2Affine::new_unchecked(x, y);

            if !p.is_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not on curve",
                ));
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "point is not in correct subgroup",
                ));
            }
            Ok(p)
        }

        fn gt_from_reader(reader: impl Read) -> Result<Self::G2Affine, std::io::Error> {
            todo!()
        }
    }
}
