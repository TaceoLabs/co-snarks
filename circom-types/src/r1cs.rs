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

//!Inspired by <https://github.com/arkworks-rs/circom-compat/blob/170b10fc9ed182b5f72ecf379033dda023d0bf07/src/circom/r1cs_reader.rs>
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
pub type Constraints<P> = (ConstraintVec<P>, ConstraintVec<P>, ConstraintVec<P>);
pub type ConstraintVec<P> = Vec<(usize, <P as Pairing>::ScalarField)>;

#[derive(Debug, Error)]
pub enum R1CSParserError {
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Max supported version is {0}, but got {1}")]
    VersionNotSupported(u32, u32),
    #[error(transparent)]
    WrongHeader(#[from] InvalidHeaderError),
    #[error("ScalarField from curve does not match in witness file")]
    WrongScalarField,
}

#[derive(Clone, Debug)]
pub struct R1CS<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraints<P>>,
    pub wire_mapping: Vec<usize>,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_labels: u64,
    pub n_constraints: usize,
}

impl<P: Pairing + CircomArkworksPairingBridge> R1CS<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
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

fn read_constraints<R: Read, E: Pairing + CircomArkworksPairingBridge>(
    mut reader: R,
    n_constraints: usize,
) -> Result<Vec<Constraints<E>>>
where
    E::BaseField: CircomArkworksPrimeFieldBridge,
    E::ScalarField: CircomArkworksPrimeFieldBridge,
{
    // todo check section size
    let mut vec = Vec::with_capacity(n_constraints);
    for _ in 0..n_constraints {
        vec.push((
            read_constraint_vec::<&mut R, E>(&mut reader)?,
            read_constraint_vec::<&mut R, E>(&mut reader)?,
            read_constraint_vec::<&mut R, E>(&mut reader)?,
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
    use ark_std::io::{BufReader, Cursor};
    use hex_literal::hex;

    use std::str::FromStr;

    #[test]
    fn test_bls_12_381_mult2() {
        let r1cs_bytes = hex!("723163730100000003000000020000007800000000000000010000000200000000000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed7301000000030000000100000000000000000000000000000000000000000000000000000000000000010000000100000000000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed730100000040000000000000002000000001000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73040000000100000000000000020000000400000000000000010000000300000020000000000000000000000000000000010000000000000002000000000000000300000000000000");
        let reader = BufReader::new(Cursor::new(&r1cs_bytes[..]));
        let r1cs = R1CS::<Bls12_381>::from_reader(reader).unwrap();
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
        let r1cs_bytes = hex!("7231637301000000030000000200000078000000000000000100000002000000000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430010000000300000001000000000000000000000000000000000000000000000000000000000000000100000001000000000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e643001000000400000000000000020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430040000000100000000000000020000000400000000000000010000000300000020000000000000000000000000000000010000000000000002000000000000000300000000000000");
        let reader = BufReader::new(Cursor::new(&r1cs_bytes[..]));
        let r1cs = R1CS::<Bn254>::from_reader(reader).unwrap();
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

    #[test]
    fn test_bn254_sample() {
        let data = hex_literal::hex!(
            "
        72316373
        01000000
        03000000
        01000000 40000000 00000000
        20000000
        010000f0 93f5e143 9170b979 48e83328 5d588181 b64550b8 29a031e1 724e6430
        07000000
        01000000
        02000000
        03000000
        e8030000 00000000
        03000000
        02000000 88020000 00000000
        02000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 14000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 0C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        00000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 07000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        01000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        04000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        03000000 2C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        00000000
        01000000
        06000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 0B000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        01000000
        06000000 58020000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 38000000 00000000
        00000000 00000000
        03000000 00000000
        0a000000 00000000
        0b000000 00000000
        0c000000 00000000
        0f000000 00000000
        44010000 00000000
    "
        );

        let reader = BufReader::new(Cursor::new(&data[..]));
        let r1cs = R1CS::<Bn254>::from_reader(reader).unwrap();
        assert_eq!(r1cs.num_inputs, 4);
        assert_eq!(r1cs.num_aux, 3);
        assert_eq!(r1cs.num_variables, 7);
        assert_eq!(r1cs.n_pub_out, 1);
        assert_eq!(r1cs.n_pub_in, 2);
        assert_eq!(r1cs.n_prv_in, 3);
        assert_eq!(r1cs.n_labels, 0x03e8);
        assert_eq!(r1cs.n_constraints, 3);

        assert_eq!(r1cs.constraints.len(), 3);
        assert_eq!(r1cs.constraints[0].0.len(), 2);
        assert_eq!(r1cs.constraints[0].0[0].0, 5);
        assert_eq!(r1cs.constraints[0].0[0].1, ark_bn254::Fr::from(3));
        assert_eq!(r1cs.constraints[2].1[0].0, 0);
        assert_eq!(r1cs.constraints[2].1[0].1, ark_bn254::Fr::from(6));
        assert_eq!(r1cs.constraints[1].2.len(), 0);

        assert_eq!(r1cs.wire_mapping, vec![0, 3, 10, 11, 12, 15, 324]);
    }
}
