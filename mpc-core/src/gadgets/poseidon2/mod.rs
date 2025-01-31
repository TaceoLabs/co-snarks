//! Poseidon2
//!
//! This module contains implementations of the Poseidon2 permutation.

pub(crate) mod poseidon2_bn254;
pub(crate) mod poseidon2_params;
pub(crate) mod poseidon2_permutation;
pub(crate) mod rep3;
pub(crate) mod shamir;

pub use poseidon2_bn254::POSEIDON2_BN254_T4_PARAMS;
pub use poseidon2_params::Poseidon2Params;
pub use poseidon2_permutation::Poseidon2;

/// A struct holding data required for preprocessing the Sbox of the Poseidon2 permutation.
#[derive(Clone, Debug, Default)]
pub struct Poseidon2Precomputations<F> {
    pub(crate) r: Vec<F>,
    pub(crate) r2: Vec<F>,
    pub(crate) r3: Vec<F>,
    pub(crate) r4: Vec<F>,
    pub(crate) r5: Vec<F>,
    pub(crate) offset: usize,
}

impl<F> Poseidon2Precomputations<F> {
    pub(crate) fn get(&self, offset: usize) -> (&F, &F, &F, &F, &F) {
        let r = &self.r[offset];
        let r2 = &self.r2[offset];
        let r3 = &self.r3[offset];
        let r4 = &self.r4[offset];
        let r5 = &self.r5[offset];
        (r, r2, r3, r4, r5)
    }
}
