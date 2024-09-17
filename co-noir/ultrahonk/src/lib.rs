pub(crate) mod decider;
pub mod honk_curve;
pub(crate) mod oink;
pub(crate) mod parse;
pub(crate) mod poseidon2;
pub mod prover;
pub(crate) mod sponge_hasher;
mod transcript;
mod types;

use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::PrimeField;
use prover::{HonkProofError, HonkProofResult};
use types::ProverCrs;

// from http://supertech.csail.mit.edu/papers/debruijn.pdf
pub(crate) fn get_msb(inp: u32) -> u8 {
    const MULTIPLY_DE_BRUIJNI_BIT_POSIITION: [u8; 32] = [
        0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7,
        19, 27, 23, 6, 26, 5, 4, 31,
    ];

    let mut v = inp | (inp >> 1);
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;

    MULTIPLY_DE_BRUIJNI_BIT_POSIITION[((v * 0x07C4ACDD) >> 27) as usize]
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
    let mut acc = F::one();
    for c in coeffs.iter() {
        temporaries.push(acc);
        debug_assert!(!c.is_zero());
        acc *= c;
    }

    acc.inverse_in_place().unwrap();

    for (c, t) in coeffs.iter_mut().zip(temporaries.into_iter()) {
        let tmp = t * acc;
        acc *= &*c;
        *c = tmp;
    }
}

fn commit<P: Pairing>(poly: &[P::ScalarField], crs: &ProverCrs<P>) -> HonkProofResult<P::G1> {
    if poly.len() > crs.monomials.len() {
        return Err(HonkProofError::CrsTooSmall);
    }
    Ok(P::G1::msm_unchecked(&crs.monomials, poly))
}
