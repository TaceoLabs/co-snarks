use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::marker::PhantomData;

use crate::uint::FieldUint;

/// Replicated binary share backed by the field's fixed-width uint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3UintShare<F: FieldUint> {
    /// Share of this party
    pub a: F::Uint,
    /// Share of the prev party
    pub b: F::Uint,
    pub(crate) phantom: PhantomData<F>,
}

impl<F: FieldUint> Default for Rep3UintShare<F> {
    fn default() -> Self {
        Self::zero_share()
    }
}

impl<F: FieldUint> Rep3UintShare<F> {
    /// Constructs the type from two additive shares.
    pub fn new(a: F::Uint, b: F::Uint) -> Self {
        Self {
            a,
            b,
            phantom: PhantomData,
        }
    }

    /// Constructs a zero share.
    pub fn zero_share() -> Self {
        Self {
            a: F::Uint::from(0u64),
            b: F::Uint::from(0u64),
            phantom: PhantomData,
        }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (F::Uint, F::Uint) {
        (self.a, self.b)
    }

    /// Computes `self ^ rhs`, XORing the public mask `rhs` onto both
    /// additive shares.
    ///
    /// This is a method rather than a `BitXor<F::Uint>` operator impl: since
    /// `F::Uint` is an associated-type projection, implementing
    /// `BitXor<F::Uint>` generically over `F: FieldUint` would conflict with
    /// the `BitXor<Self>` impl above under Rust's coherence rules (the
    /// compiler cannot prove `F::Uint` is never equal to `Self` while `F` is
    /// still a free type variable), and this needs to stay usable from fully
    /// generic code (unlike a per-concrete-backend-width workaround, which
    /// would force every generic caller to add an explicit
    /// `where Rep3UintShare<F>: BitXor<F::Uint, ...>` bound).
    pub fn xor_mask(&self, rhs: &F::Uint) -> Self {
        Self {
            a: self.a ^ *rhs,
            b: self.b ^ *rhs,
            phantom: PhantomData,
        }
    }

    /// In-place version of [`Self::xor_mask`].
    pub fn xor_mask_assign(&mut self, rhs: &F::Uint) {
        self.a ^= *rhs;
        self.b ^= *rhs;
    }

    /// Computes `self & rhs`, ANDing the public mask `rhs` onto both
    /// additive shares. See [`Self::xor_mask`] for why this is a method
    /// rather than a `BitAnd<F::Uint>` operator impl.
    pub fn and_mask(&self, rhs: &F::Uint) -> Self {
        Self {
            a: self.a & *rhs,
            b: self.b & *rhs,
            phantom: PhantomData,
        }
    }

    /// In-place version of [`Self::and_mask`].
    pub fn and_mask_assign(&mut self, rhs: &F::Uint) {
        self.a &= *rhs;
        self.b &= *rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rep3_uint_share_ops() {
        type F = ark_bn254::Fr;
        type U = <F as FieldUint>::Uint;
        let x = Rep3UintShare::<F>::new(U::from(0b1100u64), U::from(0b1010u64));
        let y = Rep3UintShare::<F>::new(U::from(0b0101u64), U::from(0b0011u64));
        let z = x ^ y;
        assert_eq!(z.ab(), (U::from(0b1001u64), U::from(0b1001u64)));
        let m = x.and_mask(&U::from(0b0100u64));
        assert_eq!(m.ab(), (U::from(0b0100u64), U::from(0u64)));
        assert_eq!((x << 1).ab(), (U::from(0b11000u64), U::from(0b10100u64)));
        assert_eq!((x >> 2).ab(), (U::from(0b11u64), U::from(0b10u64)));
    }
}
