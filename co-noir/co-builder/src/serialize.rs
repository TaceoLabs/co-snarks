use crate::{HonkProofError, HonkProofResult, TranscriptFieldType, prelude::HonkCurve};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;

pub struct Serialize<F: Field> {
    phantom: std::marker::PhantomData<F>,
}

pub struct SerializeC<C: CurveGroup> {
    phantom: std::marker::PhantomData<C>,
}

pub struct SerializeP<P: Pairing> {
    phantom: std::marker::PhantomData<P>,
}

impl<F: Field> Serialize<F> {
    const NUM_64_LIMBS: u32 = <F::BasePrimeField as PrimeField>::MODULUS_BIT_SIZE.div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;
    const VEC_LEN_BYTES: u32 = 4;

    // TODO maybe change to impl Read?
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

    pub(crate) fn field_size() -> usize {
        Self::FIELDSIZE_BYTES as usize * F::extension_degree() as usize
    }

    pub fn to_buffer(buf: &[F], include_size: bool) -> Vec<u8> {
        let total_size = buf.len() as u32 * Self::field_size() as u32
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

    pub fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend(val.to_be_bytes());
    }

    pub(crate) fn write_u64(buf: &mut Vec<u8>, val: u64) {
        buf.extend(val.to_be_bytes());
    }

    pub fn write_field_element(buf: &mut Vec<u8>, el: F) {
        let prev_len = buf.len();
        for el in el.to_base_prime_field_elements() {
            let el = el.into_bigint(); // Gets rid of montgomery form

            for data in el.as_ref().iter().rev().cloned() {
                Self::write_u64(buf, data);
            }

            debug_assert_eq!(
                buf.len() - prev_len,
                Self::FIELDSIZE_BYTES as usize * F::extension_degree() as usize
            );
        }
    }

    pub fn read_field_element(buf: &[u8], offset: &mut usize) -> F {
        let mut fields = Vec::with_capacity(F::extension_degree() as usize);

        for _ in 0..F::extension_degree() {
            let mut bigint: BigUint = Default::default();
            for _ in 0..Self::NUM_64_LIMBS {
                let data = Self::read_u64(buf, offset);
                bigint <<= 64;
                bigint += data;
            }
            fields.push(F::BasePrimeField::from(bigint));
        }

        F::from_base_prime_field_elems(fields).expect("Should work")
    }
}

impl<C: CurveGroup> SerializeC<C> {
    const NUM_64_LIMBS: u32 =
        <<C::Config as CurveConfig>::BaseField as Field>::BasePrimeField::MODULUS_BIT_SIZE
            .div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;
    const GROUPSIZE_BYTES: u32 = Self::FIELDSIZE_BYTES * 2; // Times extension degree

    pub fn group_size() -> usize {
        Self::GROUPSIZE_BYTES as usize * C::BaseField::extension_degree() as usize
    }

    pub fn write_group_element(buf: &mut Vec<u8>, el: &C::Affine, write_x_first: bool) {
        let prev_len = buf.len();

        if el.is_zero() {
            for _ in 0..Self::FIELDSIZE_BYTES * 2 {
                buf.push(255);
            }
        } else {
            let (x, y) = el.xy().unwrap_or_default();
            if write_x_first {
                Serialize::write_field_element(buf, x);
                Serialize::write_field_element(buf, y);
            } else {
                Serialize::write_field_element(buf, y);
                Serialize::write_field_element(buf, x);
            }
        }

        debug_assert_eq!(buf.len() - prev_len, Self::FIELDSIZE_BYTES as usize * 2);
    }
}

impl<P: HonkCurve<TranscriptFieldType>> SerializeP<P> {
    const NUM_64_LIMBS: u32 = P::BaseField::MODULUS_BIT_SIZE.div_ceil(64);
    pub const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;

    pub fn write_g1_element(buf: &mut Vec<u8>, el: &P::G1Affine, write_x_first: bool) {
        SerializeC::<P::G1>::write_group_element(buf, el, write_x_first);
    }

    pub fn read_g1_element(buf: &[u8], offset: &mut usize, read_x_first: bool) -> P::G1Affine {
        if buf.iter().all(|&x| x == 255) {
            *offset += Self::FIELDSIZE_BYTES as usize * 2;
            return P::G1Affine::zero();
        }

        let first = Serialize::<P::BaseField>::read_field_element(buf, offset);
        let second = Serialize::<P::BaseField>::read_field_element(buf, offset);

        if read_x_first {
            P::g1_affine_from_xy(first, second)
        } else {
            P::g1_affine_from_xy(second, first)
        }
    }
}
