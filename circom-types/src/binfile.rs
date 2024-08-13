use std::{
    io::{Cursor, Read},
    marker::PhantomData,
};

use ark_ec::pairing::Pairing;
use ark_serialize::SerializationError;
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};

pub(crate) type ZKeyParserResult<T> = std::result::Result<T, ZKeyParserError>;

/// Error type describing errors during parsing zkey files
#[derive(Debug, Error)]
pub enum ZKeyParserError {
    /// Error during serialization
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    /// Error describing that an invalid modulus was found in the header for the chosen curve
    #[error("invalid modulus found in header for chosen curve")]
    InvalidPrimeInHeader,
    #[error("Unexpected field size for curve in header. Expected {0} but got {1}")]
    UnexpectedByteSize(u32, u32),
    /// Error during IO operations (reading/opening file, etc.)
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("bin file corrupted: \"{0}\"")]
    CorruptedBinFile(String),
}

#[derive(Debug)]
pub(crate) struct BinFile<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: Vec<Vec<u8>>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> BinFile<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    pub(crate) fn new<R: Read>(reader: &mut R) -> ZKeyParserResult<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let ftype = std::str::from_utf8(&magic[..])
            .map_err(|_| ZKeyParserError::CorruptedBinFile("cannot parse magic number".to_owned()))?
            .to_string();

        let version = reader.read_u32::<LittleEndian>()?;

        let num_sections: usize = reader
            .read_u32::<LittleEndian>()?
            .try_into()
            .expect("u32 fits into usize");
        let mut sections = vec![vec![]; num_sections];

        for _ in 0..num_sections {
            let section_id: usize = reader
                .read_u32::<LittleEndian>()?
                .try_into()
                .expect("u32 fits into usize");
            let section_length: usize = reader
                .read_u64::<LittleEndian>()?
                .try_into()
                .expect("u64 fits into usize");

            let section = &mut sections[section_id - 1];
            if !section.is_empty() {
                todo!()
            }
            section.resize(section_length, 0);
            reader.read_exact(section)?;
        }

        Ok(Self {
            ftype,
            version,
            sections,
            phantom_data: PhantomData::<P>,
        })
    }

    pub(crate) fn take_section(&mut self, id: usize) -> Cursor<Vec<u8>> {
        Cursor::new(std::mem::take(&mut self.sections[id - 1]))
    }

    pub(crate) fn take_section_raw(&mut self, id: usize) -> Vec<u8> {
        std::mem::take(&mut self.sections[id - 1])
    }
}
