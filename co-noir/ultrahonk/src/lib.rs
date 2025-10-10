#![warn(clippy::iter_over_hash_type)]
pub mod decider;
pub mod oink;
pub(crate) mod plain_flavours;
pub mod plain_prover_flavour;
pub mod prelude;
pub(crate) mod types;
pub(crate) mod ultra_prover;
pub(crate) mod ultra_verifier;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_proof::HonkProofResult;

/// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
/// AZTEC TODO(<https://github.com/AztecProtocol/barretenberg/issues/1046>): Remove the need for const sized proofs
pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
// For ZK Flavors: the number of the commitments required by Libra and SmallSubgroupIPA.
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
pub const NUM_SMALL_IPA_EVALUATIONS: usize = 4;
// Upper bound on the number of claims produced GeminiProver:
// - Each fold polynomial is opened at two points, the number of resulting claims is bounded by 2*CONST_PROOF_SIZE_LOG_N
// - The interleaving trick needed for Translator adds 2 extra claims
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
pub const NUM_GEMINI_CLAIMS: usize = 2 * CONST_PROOF_SIZE_LOG_N + 2;
// The interleaving trick needed for Translator adds 2 extra claims to Gemini fold claims
// TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
pub const NUM_INTERLEAVING_CLAIMS: u32 = 2;

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

    pub fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        co_noir_common::utils::Utils::batch_invert(coeffs);
    }

    pub fn commit<P: CurveGroup>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P> {
        co_noir_common::utils::Utils::commit(poly, crs)
    }

    pub fn msm<P: CurveGroup>(poly: &[P::ScalarField], crs: &[P::Affine]) -> HonkProofResult<P> {
        co_noir_common::utils::Utils::msm::<P>(poly, crs)
    }
}
