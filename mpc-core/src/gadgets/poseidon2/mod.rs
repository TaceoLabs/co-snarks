//! Poseidon2
//!
//! This module contains implementations of the Poseidon2 permutation.

pub(crate) mod poseidon2_bn254_t16;
pub(crate) mod poseidon2_bn254_t2;
pub(crate) mod poseidon2_bn254_t3;
pub(crate) mod poseidon2_bn254_t4;
pub(crate) mod poseidon2_circom_accelerator;
pub(crate) mod poseidon2_params;
pub(crate) mod poseidon2_permutation;
pub(crate) mod rep3;
pub(crate) mod shamir;

pub use poseidon2_bn254_t4::POSEIDON2_BN254_T4_PARAMS;
pub use poseidon2_circom_accelerator::CircomTraceBatchedHasher;
pub use poseidon2_circom_accelerator::CircomTracePlainHasher;
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
    /// Returns the precomputations at a given offset.
    pub fn get(&self, offset: usize) -> (&F, &F, &F, &F, &F) {
        debug_assert!(offset < self.r.len());
        let r = &self.r[offset];
        let r2 = &self.r2[offset];
        let r3 = &self.r3[offset];
        let r4 = &self.r4[offset];
        let r5 = &self.r5[offset];
        (r, r2, r3, r4, r5)
    }

    /// Returns the precomputed r value at a given offset.
    pub fn get_r(&self, offset: usize) -> &F {
        debug_assert!(offset < self.r.len());
        &self.r[offset]
    }

    /// Returns the current offset
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Adds increment to the current offset.
    pub fn increment_offset(&mut self, increment: usize) {
        self.offset += increment;
    }

    /// Returns whether the precomputations have been consumed.
    pub fn consumed(&self) -> bool {
        debug_assert_eq!(self.r.len(), self.r2.len());
        debug_assert_eq!(self.r.len(), self.r3.len());
        debug_assert_eq!(self.r.len(), self.r4.len());
        debug_assert_eq!(self.r.len(), self.r5.len());
        self.offset >= self.r.len()
    }
}
