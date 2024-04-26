use std::{io, str::Utf8Error};

use ark_serialize::{Read, SerializationError};
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

use crate::traits::CircomArkworksPrimeFieldBridge;
use ark_ff::BigInteger;

type Result<T> = std::result::Result<T, WitnessParserError>;
const WITNESS_HEADER: &str = "wtns";
const MAX_VERSION: u32 = 2;
const N_SECTIONS: u32 = 2;

#[derive(Debug, Error)]
pub enum WitnessParserError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    #[error("Max supported version is {0}, but got {1}")]
    VersionNotSupported(u32, u32),
    #[error("Wrong number of sections is {0}, but got {1}")]
    InvalidSectionNumber(u32, u32),
    #[error("ScalarField from curve does not match in witness file")]
    WrongScalarField,
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),
    #[error("Wrong header. Expected {0} but got {1}")]
    WrongHeader(String, String),
}

#[derive(Debug, Eq, PartialEq)]
pub struct Witness<F: CircomArkworksPrimeFieldBridge> {
    pub values: Vec<F>,
}

impl<F: CircomArkworksPrimeFieldBridge> Witness<F> {
    fn read_header<R: Read>(mut reader: R, should_header: &str) -> Result<()> {
        let mut buf = [0_u8; 4];
        reader.read_exact(&mut buf)?;
        let is_header = std::str::from_utf8(&buf[..])?;
        if is_header == should_header {
            Ok(())
        } else {
            Err(WitnessParserError::WrongHeader(
                should_header.to_owned(),
                is_header.to_owned(),
            ))
        }
    }
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        Self::read_header(&mut reader, WITNESS_HEADER)?;
        let version = reader.read_u32::<LittleEndian>()?;
        if version > MAX_VERSION {
            return Err(WitnessParserError::VersionNotSupported(
                MAX_VERSION,
                version,
            ));
        }

        let n_sections = reader.read_u32::<LittleEndian>()?;
        if n_sections > N_SECTIONS {
            return Err(WitnessParserError::InvalidSectionNumber(
                N_SECTIONS, n_sections,
            ));
        }
        //this is the section id and length
        //don't know if we need them, maybe at least log them later
        let _ = reader.read_u32::<LittleEndian>()?;
        let _ = reader.read_u64::<LittleEndian>()?;
        let n8 = reader.read_u32::<LittleEndian>()?;
        let mut buf = vec![0; usize::try_from(n8).expect("u32 fits into usize")];
        reader.read_exact(buf.as_mut_slice())?;
        if F::MODULUS.to_bytes_le() != buf {
            return Err(WitnessParserError::WrongScalarField);
        }
        let n_witness = reader.read_u32::<LittleEndian>()?;
        //this is the section id and length
        //don't know if we need them, maybe at least log them later
        let _ = reader.read_u32::<LittleEndian>()?;
        let _ = reader.read_u64::<LittleEndian>()?;
        Ok(Self {
            values: (0..n_witness)
                .map(|_| {
                    F::from_reader(&mut reader).map_err(WitnessParserError::SerializationError)
                })
                .collect::<Result<Vec<F>>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::Witness;

    #[test]
    fn can_deser_witness_bn254() {
        let witness_bytes = hex!("77746e73020000000200000001000000280000000000000020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430040000000200000080000000000000000100000000000000000000000000000000000000000000000000000000000000210000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000");
        let is_witness = Witness::<ark_bn254::Fr>::from_reader(witness_bytes.as_slice()).unwrap();
        assert_eq!(
            is_witness,
            Witness {
                values: vec![
                    ark_bn254::Fr::from(1),
                    ark_bn254::Fr::from(33),
                    ark_bn254::Fr::from(3),
                    ark_bn254::Fr::from(11),
                ],
            }
        );
    }

    #[test]
    fn can_deser_witness_bls12381() {
        let witness_bytes = hex!("77746e7302000000020000000100000028000000000000002000000001000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73040000000200000080000000000000000100000000000000000000000000000000000000000000000000000000000000210000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000");
        let is_witness =
            Witness::<ark_bls12_381::Fr>::from_reader(witness_bytes.as_slice()).unwrap();
        assert_eq!(
            is_witness,
            Witness {
                values: vec![
                    ark_bls12_381::Fr::from(1),
                    ark_bls12_381::Fr::from(33),
                    ark_bls12_381::Fr::from(3),
                    ark_bls12_381::Fr::from(11),
                ],
            }
        );
    }
}
