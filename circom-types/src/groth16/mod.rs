pub mod witness;
pub mod z_key;

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

#[cfg(test)]
pub(crate) mod test_utils {
    macro_rules! to_g1_bls12_381 {
        ($x: expr, $y: expr) => {
            <ark_bls12_381::Bls12_381 as Pairing>::G1Affine::new(
                ark_bls12_381::Fq::from_str($x).unwrap(),
                ark_bls12_381::Fq::from_str($y).unwrap(),
            )
        };
    }
    macro_rules! to_g2_bls12_381 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {
            <ark_bls12_381::Bls12_381 as Pairing>::G2Affine::new(
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($x1).unwrap(),
                    ark_bls12_381::Fq::from_str($x2).unwrap(),
                ),
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($y1).unwrap(),
                    ark_bls12_381::Fq::from_str($y2).unwrap(),
                ),
            )
        };
    }
    macro_rules! to_g1_bn254 {
        ($x: expr, $y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    macro_rules! to_g2_bn254 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {
            <ark_bn254::Bn254 as Pairing>::G2Affine::new(
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($x1).unwrap(),
                    ark_bn254::Fq::from_str($x2).unwrap(),
                ),
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($y1).unwrap(),
                    ark_bn254::Fq::from_str($y2).unwrap(),
                ),
            )
        };
    }
    pub(crate) use to_g1_bls12_381;
    pub(crate) use to_g1_bn254;
    pub(crate) use to_g2_bls12_381;
    pub(crate) use to_g2_bn254;
}
