use std::{error, io, marker::PhantomData};

use ark_ec::pairing::Pairing;
use ark_serialize::Read;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use thiserror::Error;

use crate::{
    groth16::reader_utils,
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};
use ark_ff::{fields::PrimeField, BigInt, BigInteger};

use super::reader_utils::ParserError;

type Result<T> = std::result::Result<T, WitnessError>;
const WITNESS_HEADER: &str = "wtns";
//TODO CHECK ME
const MAX_VERSION: u32 = 2;
const N_SECTIONS: u32 = 2;

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error(transparent)]
    ParserError(#[from] ParserError),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("Max supported version is {0}, but got {1}")]
    VersionNotSupported(u32, u32),
    #[error("Wrong number of sections is {0}, but got {1}")]
    InvalidSectionNumber(u32, u32),
    #[error("ScalarField from curve does not match in witness file")]
    WrongScalarField,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Witness<F: CircomArkworksPrimeFieldBridge> {
    pub values: Vec<F>,
}

impl<F: CircomArkworksPrimeFieldBridge> Witness<F> {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        reader_utils::read_header(&mut reader, WITNESS_HEADER)?;
        let version = reader.read_u32::<LittleEndian>()?;
        if version > MAX_VERSION {
            return Err(WitnessError::VersionNotSupported(MAX_VERSION, version));
        }

        let n_sections = reader.read_u32::<LittleEndian>()?;
        if n_sections > N_SECTIONS {
            return Err(WitnessError::InvalidSectionNumber(N_SECTIONS, n_sections));
        }
        //this is the section id and length
        //don't know if we need them, maybe at least log them later
        let _ = reader.read_u32::<LittleEndian>()?;
        let _ = reader.read_u64::<LittleEndian>()?;
        let n8 = reader.read_u32::<LittleEndian>()?;
        let mut buf = vec![0; usize::try_from(n8).expect("u32 fits into usize")];
        reader.read_exact(buf.as_mut_slice())?;
        if F::MODULUS.to_bytes_le() != buf {
            return Err(WitnessError::WrongScalarField);
        }
        let n_witness = reader.read_u32::<LittleEndian>()?;
        //this is the section id and length
        //don't know if we need them, maybe at least log them later
        let _ = reader.read_u32::<LittleEndian>()?;
        let _ = reader.read_u64::<LittleEndian>()?;
        Ok(Self {
            values: (0..n_witness)
                .map(|_| F::from_reader(&mut reader).map_err(WitnessError::IoError))
                .collect::<Result<Vec<F>>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::Witness;

    #[test]
    fn test() {
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
}
