use std::any::Any;

use crate::crs::ProverCrs;
use crate::honk_proof::{HonkProofError, HonkProofResult};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, Zero};
use eyre::Error;
use mpc_core::gadgets;
use num_bigint::BigUint;
use std::array;

pub struct Utils {}

impl Utils {
    pub fn field_from_hex_string<F: PrimeField>(str: &str) -> Result<F, Error> {
        Ok(gadgets::field_from_hex_string(str)?)
    }

    pub fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        ark_ff::batch_inversion(coeffs);
    }

    pub fn batch_normalize<C: CurveGroup>(elements: &[C::Affine]) -> Vec<C::Affine> {
        let projective_elements: Vec<C> = elements.iter().map(|e| e.into_group()).collect();
        C::normalize_batch(&projective_elements)
    }
    pub fn commit<P: CurveGroup>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P> {
        Self::msm::<P>(poly, crs.monomials.as_slice())
    }

    pub fn msm<P: CurveGroup>(poly: &[P::ScalarField], crs: &[P::Affine]) -> HonkProofResult<P> {
        if poly.len() > crs.len() {
            return Err(HonkProofError::CrsTooSmall);
        }
        Ok(P::msm_unchecked(crs, poly))
    }

    pub fn get_msb32(inp: u32) -> u32 {
        inp.ilog2()
    }

    pub fn round_up_power_2(inp: usize) -> usize {
        let lower_bound = 1usize << Self::get_msb64(inp as u64);
        if lower_bound == inp || lower_bound == 1 {
            inp
        } else {
            lower_bound * 2
        }
    }

    pub fn get_msb64(inp: u64) -> u32 {
        inp.ilog2()
    }

    pub fn get_base_powers<const BASE: u64, const NUM_SLICES: usize>() -> [BigUint; NUM_SLICES] {
        let mut output: [BigUint; NUM_SLICES] = array::from_fn(|_| BigUint::one());
        let base = BigUint::from(BASE);
        let mask = (BigUint::from(1u64) << 256) - BigUint::one();

        for i in 1..NUM_SLICES {
            let tmp = &output[i - 1] * &base;
            output[i] = tmp & &mask;
        }

        output
    }

    pub fn map_into_sparse_form<const BASE: u64>(input: u64) -> BigUint {
        let mut out: BigUint = BigUint::zero();
        let base_powers = Self::get_base_powers::<BASE, 32>();

        for (i, base_power) in base_powers.iter().enumerate() {
            let sparse_bit = (input >> i) & 1;
            if sparse_bit != 0 {
                out += base_power;
            }
        }
        out
    }

    pub fn downcast<A: 'static, B: 'static>(a: &A) -> Option<&B> {
        (a as &dyn Any).downcast_ref::<B>()
    }

    // Rounds a number to the nearest multiple of 8
    pub fn round_to_nearest_mul_8(num_bits: u32) -> u32 {
        let remainder = num_bits % 8;
        if remainder == 0 {
            return num_bits;
        }

        num_bits + 8 - remainder
    }

    // Rounds the number of bits to the nearest byte
    pub fn round_to_nearest_byte(num_bits: u32) -> u32 {
        Self::round_to_nearest_mul_8(num_bits) / 8
    }

    /**
     * Viewing `this` u256 as a bit string, and counting bits from 0, slices a substring.
     * @returns the u256 equal to the substring of bits from (and including) the `start`-th bit, to (but excluding) the
     * `end`-th bit of `this`.
     */
    pub fn slice_u256(value: &BigUint, start: u64, end: u64) -> BigUint {
        if end <= start {
            return BigUint::zero();
        }
        let range = end - start;
        let mask = if range == 256 {
            (BigUint::from(1u64) << 256) - BigUint::one()
        } else {
            (BigUint::one() << range) - BigUint::one()
        };
        (value >> start) & mask
    }

    pub fn map_from_sparse_form<const BASE: u64>(input: BigUint) -> u64 {
        let mut target = input;
        let mut output = 0u64;

        let bases = Self::get_base_powers::<BASE, 32>();

        for i in (0..32).rev() {
            let base_power = &bases[i];
            let mut prev_threshold = BigUint::zero();
            for j in 1..BASE + 1 {
                let threshold = &prev_threshold + base_power;
                if target < threshold {
                    let bit = ((j - 1) & 1) != 0;
                    if bit {
                        output += 1 << i;
                    }
                    if j > 1 {
                        target -= prev_threshold;
                    }
                    break;
                }
                prev_threshold = threshold;
            }
        }

        output
    }
}
