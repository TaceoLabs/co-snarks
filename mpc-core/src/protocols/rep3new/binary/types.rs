use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::marker::PhantomData;

use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::traits::SecretShared;

/// This type represents a packed vector of replicated shared bits. Each additively shared vector is represented as [BigUint]. Thus, this type contains two [BigUint]s.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3BigUintShare<F: PrimeField> {
    pub(crate) a: BigUint,
    pub(crate) b: BigUint,
    pub(crate) phantom: PhantomData<F>,
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

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (BigUint, BigUint) {
        (self.a, self.b)
    }
}
impl<F: PrimeField> SecretShared for Rep3BigUintShare<F> {
    fn zero_share() -> Self {
        Self {
            a: BigUint::ZERO,
            b: BigUint::ZERO,
            phantom: PhantomData,
        }
    }
}
