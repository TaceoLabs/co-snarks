use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::marker::PhantomData;

use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::uint::FieldUint;

/// This type represents a packed vector of replicated shared bits. Each additively shared vector is represented as [BigUint]. Thus, this type contains two [BigUint]s.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3BigUintShare<F: PrimeField> {
    /// Share of this party
    pub a: BigUint,
    /// Share of the prev party
    pub b: BigUint,
    pub(crate) phantom: PhantomData<F>,
}

impl<F: PrimeField> Default for Rep3BigUintShare<F> {
    fn default() -> Self {
        Self::zero_share()
    }
}

impl<F: PrimeField> Rep3BigUintShare<F> {
    /// Constructs the type from two additive shares.
    pub fn new(a: BigUint, b: BigUint) -> Self {
        Self {
            a,
            b,
            phantom: PhantomData,
        }
    }

    /// Constructs a zero share.
    pub fn zero_share() -> Self {
        Self {
            a: BigUint::ZERO,
            b: BigUint::ZERO,
            phantom: PhantomData,
        }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (BigUint, BigUint) {
        (self.a, self.b)
    }
}

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
        let m = x & U::from(0b0100u64);
        assert_eq!(m.ab(), (U::from(0b0100u64), U::from(0u64)));
        assert_eq!((x << 1).ab(), (U::from(0b11000u64), U::from(0b10100u64)));
        assert_eq!((x >> 2).ab(), (U::from(0b11u64), U::from(0b10u64)));
    }
}
