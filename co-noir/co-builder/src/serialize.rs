use crate::{TranscriptFieldType, prelude::HonkCurve};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ff::{Field, PrimeField};
use noir_types::SerializeF;

pub struct SerializeC<C: CurveGroup> {
    phantom: std::marker::PhantomData<C>,
}

pub struct SerializeP<P: CurveGroup> {
    phantom: std::marker::PhantomData<P>,
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
                SerializeF::write_field_element(buf, x);
                SerializeF::write_field_element(buf, y);
            } else {
                SerializeF::write_field_element(buf, y);
                SerializeF::write_field_element(buf, x);
            }
        }

        debug_assert_eq!(buf.len() - prev_len, Self::FIELDSIZE_BYTES as usize * 2);
    }
}

impl<P: HonkCurve<TranscriptFieldType>> SerializeP<P> {
    const NUM_64_LIMBS: u32 = P::BaseField::MODULUS_BIT_SIZE.div_ceil(64);
    pub const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;

    pub fn write_g1_element(buf: &mut Vec<u8>, el: &P::Affine, write_x_first: bool) {
        SerializeC::<P>::write_group_element(buf, el, write_x_first);
    }

    pub fn read_g1_element(buf: &[u8], offset: &mut usize, read_x_first: bool) -> P::Affine {
        if buf[*offset..*offset + Self::FIELDSIZE_BYTES as usize * 2]
            .iter()
            .all(|&x| x == 255)
        {
            *offset += Self::FIELDSIZE_BYTES as usize * 2;
            return P::Affine::zero();
        }
        let first = SerializeF::<P::BaseField>::read_field_element(buf, offset);
        let second = SerializeF::<P::BaseField>::read_field_element(buf, offset);

        if read_x_first {
            P::g1_affine_from_xy(first, second)
        } else {
            P::g1_affine_from_xy(second, first)
        }
    }
}
