use crate::{HonkProofError, HonkProofResult};
use ark_ff::PrimeField;
use num_bigint::BigUint;

pub struct Serialize<F: PrimeField> {
    phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> Serialize<F> {
    const NUM_64_LIMBS: u32 = F::MODULUS_BIT_SIZE.div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;
    const VEC_LEN_BYTES: u32 = 4;

    pub fn from_buffer(buf: &[u8], size_included: bool) -> HonkProofResult<Vec<F>> {
        let size = buf.len();
        let mut offset = 0;

        // Check sizes
        let num_elements = if size_included {
            let num_elements =
                (size - Self::VEC_LEN_BYTES as usize) / Self::FIELDSIZE_BYTES as usize;
            if num_elements * Self::FIELDSIZE_BYTES as usize + Self::VEC_LEN_BYTES as usize != size
            {
                return Err(HonkProofError::InvalidProofLength);
            }

            let read_num_elements = Self::read_u32(buf, &mut offset);
            if read_num_elements != num_elements as u32 {
                return Err(HonkProofError::InvalidProofLength);
            }
            num_elements
        } else {
            let num_elements = size / Self::FIELDSIZE_BYTES as usize;
            if num_elements * Self::FIELDSIZE_BYTES as usize != size {
                return Err(HonkProofError::InvalidProofLength);
            }
            num_elements
        };

        // Read data
        let mut res = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            res.push(Self::read_field_element(buf, &mut offset));
        }
        debug_assert_eq!(offset, size);
        Ok(res)
    }

    pub fn to_buffer(buf: &[F], include_size: bool) -> Vec<u8> {
        let total_size = buf.len() as u32 * Self::FIELDSIZE_BYTES
            + if include_size { Self::VEC_LEN_BYTES } else { 0 };

        let mut res = Vec::with_capacity(total_size as usize);
        if include_size {
            Self::write_u32(&mut res, buf.len() as u32);
        }
        for el in buf.iter().cloned() {
            Self::write_field_element(&mut res, el);
        }
        debug_assert_eq!(res.len(), total_size as usize);
        res
    }

    pub(crate) fn read_u8(buf: &[u8], offset: &mut usize) -> u8 {
        const BYTES: usize = 1;
        let res = buf[*offset];
        *offset += BYTES;
        res
    }

    pub(crate) fn read_u32(buf: &[u8], offset: &mut usize) -> u32 {
        const BYTES: usize = 4;
        let res = u32::from_be_bytes(buf[*offset..*offset + BYTES].try_into().unwrap());
        *offset += BYTES;
        res
    }

    pub(crate) fn read_u64(buf: &[u8], offset: &mut usize) -> u64 {
        const BYTES: usize = 8;
        let res = u64::from_be_bytes(buf[*offset..*offset + BYTES].try_into().unwrap());
        *offset += BYTES;
        res
    }

    pub(crate) fn write_u8(buf: &mut Vec<u8>, val: u8) {
        buf.push(val);
    }

    pub(crate) fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend(val.to_be_bytes());
    }

    pub(crate) fn write_u64(buf: &mut Vec<u8>, val: u64) {
        buf.extend(val.to_be_bytes());
    }

    pub(crate) fn write_field_element(buf: &mut Vec<u8>, el: F) {
        let prev_len = buf.len();
        let el = el.into_bigint(); // Gets rid of montgomery form

        for data in el.as_ref().iter().rev().cloned() {
            Self::write_u64(buf, data);
        }

        debug_assert_eq!(buf.len() - prev_len, Self::FIELDSIZE_BYTES as usize);
    }

    pub fn read_field_element(buf: &[u8], offset: &mut usize) -> F {
        let mut bigint: BigUint = Default::default();

        for _ in 0..Self::NUM_64_LIMBS {
            let data = Self::read_u64(buf, offset);
            bigint <<= 64;
            bigint += data;
        }

        F::from(bigint)
    }
}
