pub(crate) mod decider;
pub(crate) mod honk_curve;
pub(crate) mod oink;
pub mod parse;
pub(crate) mod poseidon2;
pub(crate) mod prover;
pub(crate) mod sponge_hasher;
mod transcript;
pub(crate) mod types;

pub use parse::{acir_format::AcirFormat, builder::UltraCircuitBuilder};
pub use prover::UltraHonk;
pub use types::{HonkProof, ProvingKey};

use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::PrimeField;
use itertools::izip;
use prover::{HonkProofError, HonkProofResult};
use types::ProverCrs;

// from http://supertech.csail.mit.edu/papers/debruijn.pdf
pub(crate) fn get_msb32(inp: u32) -> u8 {
    const MULTIPLY_DE_BRUIJNI_BIT_POSIITION: [u8; 32] = [
        0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7,
        19, 27, 23, 6, 26, 5, 4, 31,
    ];

    let mut v = inp | (inp >> 1);
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;

    MULTIPLY_DE_BRUIJNI_BIT_POSIITION[((v.wrapping_mul(0x07C4ACDD)) >> 27) as usize]
}

pub(crate) fn get_msb64(inp: u64) -> u8 {
    const DE_BRUIJNI_SEQUENCE: [u8; 64] = [
        0, 47, 1, 56, 48, 27, 2, 60, 57, 49, 41, 37, 28, 16, 3, 61, 54, 58, 35, 52, 50, 42, 21, 44,
        38, 32, 29, 23, 17, 11, 4, 62, 46, 55, 26, 59, 40, 36, 15, 53, 34, 51, 20, 43, 31, 22, 10,
        45, 25, 39, 14, 33, 19, 30, 9, 24, 13, 18, 8, 12, 7, 6, 5, 63,
    ];

    let mut t = inp | (inp >> 1);
    t |= t >> 2;
    t |= t >> 4;
    t |= t >> 8;
    t |= t >> 16;
    t |= t >> 32;

    DE_BRUIJNI_SEQUENCE[((t.wrapping_mul(0x03F79D71B4CB0A89)) >> 58) as usize]
}

pub(crate) const NUM_ALPHAS: usize = decider::relations::NUM_SUBRELATIONS - 1;
// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub(crate) const N_MAX: usize = 1 << 25;

fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
    // This better?
    // for inv in coeffs.iter_mut() {
    //     inv.inverse_in_place();
    // }

    // Assumes that all elements are invertible
    let n = coeffs.len();
    let mut temporaries = Vec::with_capacity(n);
    let mut skipped = Vec::with_capacity(n);
    let mut acc = F::one();
    for c in coeffs.iter() {
        temporaries.push(acc);
        if c.is_zero() {
            skipped.push(true);
            continue;
        }
        acc *= c;
        skipped.push(false);
    }

    acc.inverse_in_place().unwrap();

    for (c, t, skipped) in izip!(
        coeffs.iter_mut(),
        temporaries.into_iter(),
        skipped.into_iter()
    )
    .rev()
    {
        if !skipped {
            let tmp = t * acc;
            acc *= &*c;
            *c = tmp;
        }
    }
}

fn commit<P: Pairing>(poly: &[P::ScalarField], crs: &ProverCrs<P>) -> HonkProofResult<P::G1> {
    if poly.len() > crs.monomials.len() {
        return Err(HonkProofError::CrsTooSmall);
    }
    Ok(P::G1::msm_unchecked(&crs.monomials, poly))
}
