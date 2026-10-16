#![warn(clippy::iter_over_hash_type)]

pub(crate) mod decider;
pub(crate) mod oink;
pub mod prelude;
pub(crate) mod types;
pub(crate) mod ultra_prover;
pub(crate) mod ultra_verifier;

use ark_ff::PrimeField;
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

pub const NUM_ALPHAS: usize = decider::relations::NUM_SUBRELATIONS - 1;
pub use co_noir_common::constants::{
    CONST_PROOF_SIZE_LOG_N, NUM_LIBRA_COMMITMENTS, NUM_SMALL_IPA_EVALUATIONS,
    NUM_SMALL_IPA_OPENING_CLAIMS, SMALL_IPA_CLAIM_COMMITMENT_INDICES,
};

pub struct Utils {}

impl Utils {
    pub fn get_msb32(inp: u32) -> u32 {
        co_noir_common::utils::Utils::get_msb32(inp)
    }

    pub fn round_up_power_2(inp: usize) -> usize {
        co_noir_common::utils::Utils::round_up_power_2(inp)
    }

    pub fn get_msb64(inp: u64) -> u32 {
        co_noir_common::utils::Utils::get_msb64(inp)
    }

    fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        co_noir_common::utils::Utils::batch_invert(coeffs);
    }

    pub fn commit<P: HonkCurve<TranscriptFieldType>>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P> {
        co_noir_common::utils::Utils::commit(poly, crs)
    }

    pub fn msm<P: HonkCurve<TranscriptFieldType>>(
        poly: &[P::ScalarField],
        crs: &[P::Affine],
    ) -> HonkProofResult<P> {
        co_noir_common::utils::Utils::msm::<P>(poly, crs)
    }
}
