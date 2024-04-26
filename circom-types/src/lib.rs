pub mod groth16;
pub mod r1cs;
pub mod traits;

pub(crate) mod reader_utils {

    use std::str::Utf8Error;

    use ark_ec::pairing::Pairing;
    use ark_serialize::{Read, SerializationError};
    use thiserror::Error;

    use crate::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};

    #[derive(Debug, Error)]
    pub enum InvalidHeaderError {
        #[error(transparent)]
        IoError(#[from] std::io::Error),
        #[error(transparent)]
        Utf8Error(#[from] Utf8Error),
        #[error("Wrong header. Expected {0} but got {1}")]
        WrongHeader(String, String),
    }

    pub(crate) fn read_header<R: Read>(
        mut reader: R,
        should_header: &str,
    ) -> Result<(), InvalidHeaderError> {
        let mut buf = [0_u8; 4];
        reader.read_exact(&mut buf)?;
        let is_header = std::str::from_utf8(&buf[..])?;
        if is_header == should_header {
            Ok(())
        } else {
            Err(InvalidHeaderError::WrongHeader(
                should_header.to_owned(),
                is_header.to_owned(),
            ))
        }
    }
    #[inline]
    pub(crate) fn read_g1_vector<P: Pairing + CircomArkworksPairingBridge, R: Read>(
        mut reader: R,
        num: usize,
    ) -> Result<Vec<P::G1Affine>, SerializationError>
    where
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        (0..num)
            .map(|_| P::g1_from_reader(&mut reader))
            .collect::<Result<Vec<_>, SerializationError>>()
    }
    #[inline]
    pub(crate) fn read_g2_vector<P: Pairing + CircomArkworksPairingBridge, R: Read>(
        mut reader: R,
        num: usize,
    ) -> Result<Vec<P::G2Affine>, SerializationError>
    where
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        (0..num)
            .map(|_| P::g2_from_reader(&mut reader))
            .collect::<Result<Vec<_>, SerializationError>>()
    }
}
