//Copyright (c) 2021 Georgios Konstantopoulos
//
//Permission is hereby granted, free of charge, to any
//person obtaining a copy of this software and associated
//documentation files (the "Software"), to deal in the
//Software without restriction, including without
//limitation the rights to use, copy, modify, merge,
//publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software
//is furnished to do so, subject to the following
//conditions:
//
//The above copyright notice and this permission notice
//shall be included in all copies or substantial portions
//of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//IN CONNECTION WITH THE SOFTWARE O THE USE OR OTHER
//DEALINGS IN THE SOFTWARE.R

//! This module provides the [`R1CS`] type which implements [`R1CS::from_reader`] for parsing the R1CS file format used by circom.
//! Inspired by <https://github.com/arkworks-rs/circom-compat/blob/170b10fc9ed182b5f72ecf379033dda023d0bf07/src/circom/r1cs_reader.rs>
use ark_ff::PrimeField;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Error, ErrorKind};
use thiserror::Error;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::io::{Read, Seek, SeekFrom};

use std::collections::HashMap;

use crate::{
    reader_utils::{self, InvalidHeaderError},
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};

const R1CS_HEADER: &str = "r1cs";
const MAX_VERSION: u32 = 1;
type Result<T> = std::result::Result<T, R1CSParserError>;

//TODO maybe write something better that is not so convoluted to access
pub(crate) type Constraints<P> = (ConstraintVec<P>, ConstraintVec<P>, ConstraintVec<P>);
pub(crate) type ConstraintVec<P> = Vec<(usize, <P as Pairing>::ScalarField)>;

/// Error type describing errors during parsing R1CS files
#[derive(Debug, Error)]
pub enum R1CSParserError {
    /// Error during serialization
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    /// Error during IO operations (reading/opening file, etc.)
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Error describing that the version of the file is not supported for parsing
    #[error("Max supported version is {0}, but got {1}")]
    VersionNotSupported(u32, u32),
    /// Error during reading circom file header
    #[error(transparent)]
    WrongHeader(#[from] InvalidHeaderError),
    /// Error describing that the ScalarField from curve does not match in witness file
    #[error("ScalarField from curve does not match in witness file")]
    WrongScalarField,
}

/// Struct representing a R1CS file produced by circom that implements [`R1CS::from_reader`] for parsing the R1CS file format used by circom.
#[derive(Clone, Debug)]
pub struct R1CS<P: Pairing> {
    /// Number of public inputs
    pub num_inputs: usize,
    /// Number of auxiliary variables
    pub num_aux: usize,
    /// Number of variables
    pub num_variables: usize,
    /// Constraints
    pub constraints: Vec<Constraints<P>>,
    /// Mapping from wire to label
    pub wire_mapping: Vec<usize>,
    /// Number of public outputs
    pub n_pub_out: u32,
    /// Number of public inputs
    pub n_pub_in: u32,
    /// Number of private inputs
    pub n_prv_in: u32,
    /// Number of labels
    pub n_labels: u64,
    /// Number of constraints
    pub n_constraints: usize,
}

impl<P: Pairing + CircomArkworksPairingBridge> R1CS<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Parses an [`R1CS`] file from a reader and returns [`R1CSParserError`] on failure
    pub fn from_reader<R: Read + Seek>(mut reader: R) -> Result<Self> {
        reader_utils::read_header(&mut reader, R1CS_HEADER)?;
        let version = reader.read_u32::<LittleEndian>()?;
        if version != MAX_VERSION {
            return Err(R1CSParserError::VersionNotSupported(MAX_VERSION, version));
        }
        let num_sections = reader.read_u32::<LittleEndian>()?;

        // todo: handle sec_size correctly
        // section type -> file offset
        let mut sec_offsets = HashMap::<u32, u64>::new();
        let mut sec_sizes = HashMap::<u32, u64>::new();

        // get file offset of each section
        for _ in 0..num_sections {
            let sec_type = reader.read_u32::<LittleEndian>()?;
            let sec_size = reader.read_u64::<LittleEndian>()?;
            let offset = reader.stream_position()?;
            sec_offsets.insert(sec_type, offset);
            sec_sizes.insert(sec_type, sec_size);
            reader.seek(SeekFrom::Current(sec_size as i64))?;
        }

        let header_type = 1;
        let constraint_type = 2;
        let wire2label_type = 3;

        let header_offset = sec_offsets.get(&header_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section offset for header type found",
            )
        });

        reader.seek(SeekFrom::Start(*header_offset?))?;

        let header_size = sec_sizes.get(&header_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section size for header type found",
            )
        });

        let field_size =
            usize::try_from(reader.read_u32::<LittleEndian>()?).expect("u32 fits into usize");
        if field_size != P::ScalarField::SERIALIZED_BYTE_SIZE {
            return Err(R1CSParserError::WrongScalarField);
        }

        if *header_size? != 32 + field_size as u64 {
            return Err(R1CSParserError::WrongScalarField);
        }

        let q = <P::ScalarField as PrimeField>::BigInt::deserialize_uncompressed(&mut reader)?;
        let modulus = P::ScalarField::MODULUS;
        if q != modulus {
            return Err(R1CSParserError::WrongScalarField);
        }

        let num_variables =
            usize::try_from(reader.read_u32::<LittleEndian>()?).expect("u32 fits into usize");
        let n_pub_out = reader.read_u32::<LittleEndian>()?;
        let n_pub_in = reader.read_u32::<LittleEndian>()?;
        let n_prv_in = reader.read_u32::<LittleEndian>()?;
        let n_labels = reader.read_u64::<LittleEndian>()?;
        let n_constraints =
            usize::try_from(reader.read_u32::<LittleEndian>()?).expect("u32 fits into usize");

        let constraint_offset = sec_offsets.get(&constraint_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section offset for constraint type found",
            )
        });

        reader.seek(SeekFrom::Start(*constraint_offset?))?;

        let constraints = read_constraints::<&mut R, P>(&mut reader, n_constraints)?;

        let wire2label_offset = sec_offsets.get(&wire2label_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section offset for wire2label type found",
            )
        });

        reader.seek(SeekFrom::Start(*wire2label_offset?))?;

        let wire2label_size = sec_sizes.get(&wire2label_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section size for wire2label type found",
            )
        })?;

        let wire_mapping = read_map(&mut reader, *wire2label_size, num_variables)?;

        let num_inputs = (1 + n_pub_in + n_pub_out) as usize;
        let num_aux = num_variables - num_inputs;
        Ok(R1CS {
            num_aux,
            num_inputs,
            num_variables,
            constraints,
            wire_mapping: wire_mapping.iter().map(|e| *e as usize).collect(),
            n_pub_out,
            n_pub_in,
            n_prv_in,
            n_labels,
            n_constraints,
        })
    }
}

fn read_constraint_vec<R: Read, P: Pairing + CircomArkworksPairingBridge>(
    mut reader: R,
) -> Result<ConstraintVec<P>>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    let n_vec = reader.read_u32::<LittleEndian>()? as usize;
    let mut vec = Vec::with_capacity(n_vec);
    for _ in 0..n_vec {
        vec.push((
            reader.read_u32::<LittleEndian>()? as usize,
            P::ScalarField::from_reader(&mut reader)?,
        ));
    }
    Ok(vec)
}

fn read_constraints<R: Read, P: Pairing + CircomArkworksPairingBridge>(
    mut reader: R,
    n_constraints: usize,
) -> Result<Vec<Constraints<P>>>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    // todo check section size
    let mut vec = Vec::with_capacity(n_constraints);
    for _ in 0..n_constraints {
        vec.push((
            read_constraint_vec::<&mut R, P>(&mut reader)?,
            read_constraint_vec::<&mut R, P>(&mut reader)?,
            read_constraint_vec::<&mut R, P>(&mut reader)?,
        ));
    }
    Ok(vec)
}

fn read_map<R: Read>(mut reader: R, size: u64, n_wires: usize) -> Result<Vec<u64>> {
    if size != u64::try_from(n_wires).expect("usize fits into u64") * 8 {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Invalid map section size",
        ))?;
    }
    let mut vec = Vec::with_capacity(n_wires);
    for _ in 0..n_wires {
        vec.push(reader.read_u64::<LittleEndian>()?);
    }
    if vec[0] != 0 {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Wire 0 should always be mapped to 0",
        ))?;
    }
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    use std::{fs::File, str::FromStr};

    #[test]
    fn test_bls_12_381_mult2() {
        let r1cs_file = File::open("../test_vectors/bls12_381/multiplier2.r1cs").unwrap();
        let r1cs = R1CS::<Bls12_381>::from_reader(r1cs_file).unwrap();
        assert_eq!(r1cs.num_inputs, 2);
        assert_eq!(r1cs.num_aux, 2);
        assert_eq!(r1cs.num_variables, 4);
        assert_eq!(r1cs.n_pub_out, 1);
        assert_eq!(r1cs.n_pub_in, 0);
        assert_eq!(r1cs.n_prv_in, 2);
        assert_eq!(r1cs.n_labels, 0x0004);
        assert_eq!(r1cs.n_constraints, 1);

        assert_eq!(r1cs.constraints.len(), 1);
        assert_eq!(r1cs.constraints[0].0.len(), 1);
        assert_eq!(r1cs.constraints[0].0[0].0, 2);
        assert_eq!(
            r1cs.constraints[0].0[0].1,
            ark_bls12_381::Fr::from_str(
                "52435875175126190479447740508185965837690552500527637822603658699938581184512"
            )
            .unwrap()
        );
        assert_eq!(r1cs.wire_mapping, vec![0, 1, 2, 3]);
    }
    #[test]
    fn test_bn254_mult2() {
        let r1cs_file = File::open("../test_vectors/bn254/multiplier2/multiplier2.r1cs").unwrap();
        let r1cs = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        assert_eq!(r1cs.num_inputs, 2);
        assert_eq!(r1cs.num_aux, 2);
        assert_eq!(r1cs.num_variables, 4);
        assert_eq!(r1cs.n_pub_out, 1);
        assert_eq!(r1cs.n_pub_in, 0);
        assert_eq!(r1cs.n_prv_in, 2);
        assert_eq!(r1cs.n_labels, 0x0004);
        assert_eq!(r1cs.n_constraints, 1);

        assert_eq!(r1cs.constraints.len(), 1);
        assert_eq!(r1cs.constraints[0].0.len(), 1);
        assert_eq!(r1cs.constraints[0].0[0].0, 2);
        assert_eq!(
            r1cs.constraints[0].0[0].1,
            ark_bn254::Fr::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495616"
            )
            .unwrap()
        );
        assert_eq!(r1cs.wire_mapping, vec![0, 1, 2, 3]);
    }
}
