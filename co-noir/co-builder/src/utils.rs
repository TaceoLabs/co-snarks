use crate::{crs::ProverCrs, HonkProofError, HonkProofResult};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{One, PrimeField};
use eyre::Error;
use mpc_core::gadgets;
use num_bigint::BigUint;

pub struct Utils {}

impl Utils {
    pub fn field_from_hex_string<F: PrimeField>(str: &str) -> Result<F, Error> {
        Ok(gadgets::field_from_hex_string(str)?)
    }

    pub fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        ark_ff::batch_inversion(coeffs);
    }

    pub fn commit<P: Pairing>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P::G1> {
        Self::msm::<P>(poly, crs.monomials.as_slice())
    }

    pub fn msm<P: Pairing>(poly: &[P::ScalarField], crs: &[P::G1Affine]) -> HonkProofResult<P::G1> {
        if poly.len() > crs.len() {
            return Err(HonkProofError::CrsTooSmall);
        }
        Ok(P::G1::msm_unchecked(crs, poly))
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

    pub fn rotate64(value: u64, rotation: u64) -> u64 {
        if rotation != 0 {
            (value >> rotation) | (value << (64 - rotation))
        } else {
            value
        }
    }

    pub fn rotate32(value: u32, rotation: u32) -> u32 {
        if rotation != 0 {
            (value >> rotation) | (value << (32 - rotation))
        } else {
            value
        }
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
    pub fn slice_u256(value: BigUint, start: u64, end: u64) -> BigUint {
        let range = end - start;
        let mask = if range == 256 {
            (BigUint::from(1u64) << 256) - BigUint::one()
        } else {
            (BigUint::one() << range) - BigUint::one()
        };
        (value >> start) & mask
    }
}
