use std::io;

use ark_serialize::{Read, SerializationError};
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

use crate::traits::CircomArkworksPrimeFieldBridge;
use ark_ff::BigInteger;

use crate::reader_utils::{self, InvalidHeaderError};

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
    WrongHeader(#[from] InvalidHeaderError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Witness<F> {
    pub values: Vec<F>,
}

impl<F: CircomArkworksPrimeFieldBridge> Witness<F> {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        reader_utils::read_header(&mut reader, WITNESS_HEADER)?;
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
    use std::fs::File;

    use super::Witness;

    #[test]
    fn can_deser_witness_bn254() {
        let witness = File::open("../test_vectors/bn254/multiplier2/witness.wtns").unwrap();
        let is_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
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
        let witness = File::open("../test_vectors/bls12_381/witness.wtns").unwrap();
        let is_witness = Witness::<ark_bls12_381::Fr>::from_reader(witness).unwrap();
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
