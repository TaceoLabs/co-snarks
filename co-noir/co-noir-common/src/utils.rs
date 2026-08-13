use std::any::Any;

use crate::crs::ProverCrs;
use crate::honk_proof::{HonkProofError, HonkProofResult};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, Zero};
use eyre::Error;
use mpc_core::gadgets;
use mpc_core::uint::{U256, UintBackend};
use num_bigint::BigUint;

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
        Ok(mpc_core::msm::msm_unchecked::<P>(crs, poly))
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

    pub fn get_base_powers<const BASE: u64, const NUM_SLICES: usize>() -> [U256; NUM_SLICES] {
        let mut output = [U256::one(); NUM_SLICES];
        let base = U256::from(BASE);

        // `*` on `U256` wraps mod 2^256, which is what the explicit 256-bit
        // mask used to do.
        for i in 1..NUM_SLICES {
            output[i] = output[i - 1] * base;
        }

        output
    }

    pub fn map_into_sparse_form<const BASE: u64>(input: u64) -> U256 {
        let mut out = U256::zero();
        let base_powers = Self::get_base_powers::<BASE, 32>();

        for (i, base_power) in base_powers.iter().enumerate() {
            let sparse_bit = (input >> i) & 1;
            if sparse_bit != 0 {
                out += *base_power;
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
    pub fn slice_u256(value: &U256, start: u64, end: u64) -> U256 {
        if end <= start {
            return U256::zero();
        }
        let range = (end - start) as usize;
        // Shifts on `U256` saturate to zero, matching `BigUint >> start`.
        let sliced = *value >> start as usize;
        if range >= U256::BITS {
            sliced
        } else {
            sliced & U256::mask(range)
        }
    }

    pub fn map_from_sparse_form<const BASE: u64>(input: U256) -> u64 {
        let mut target = input;
        let mut output = 0u64;

        let bases = Self::get_base_powers::<BASE, 32>();

        for i in (0..32).rev() {
            let base_power = &bases[i];
            let mut prev_threshold = U256::zero();
            for j in 1..BASE + 1 {
                let threshold = prev_threshold + *base_power;
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

    // The two helpers below bridge the bigfield/biggroup emulation, whose
    // `NUM_LIMBS * LIMB_SIZE` product exceeds 256 bits (4 x 68 = 272), so they
    // stay on `BigUint` until that gadget gets a wider fixed-width backend.

    pub fn field_limbs_to_biguint<F: PrimeField, const NUM_LIMBS: usize, const LIMB_SIZE: usize>(
        limbs: &[F; NUM_LIMBS],
    ) -> BigUint {
        let mut result = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            let limb_value: BigUint = limb.into_bigint().into();
            result += limb_value << (i * LIMB_SIZE);
        }
        result
    }

    pub fn biguint_to_field_limbs<F: PrimeField, const NUM_LIMBS: usize, const LIMB_SIZE: usize>(
        value: &BigUint,
    ) -> [F; NUM_LIMBS] {
        let mut limbs = [F::zero(); NUM_LIMBS];
        let limb_mask = (BigUint::one() << LIMB_SIZE) - BigUint::one();

        for (i, item) in limbs.iter_mut().enumerate().take(NUM_LIMBS) {
            let limb_value = (value >> (i * LIMB_SIZE)) & &limb_mask;
            *item = F::from(limb_value);
        }

        limbs
    }
}
