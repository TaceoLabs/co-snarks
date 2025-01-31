use crate::{crs::ProverCrs, HonkProofError, HonkProofResult};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::PrimeField;
use eyre::Error;
use mpc_core::gadgets;

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
}
