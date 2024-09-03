use num_bigint::BigUint;

/// This type represents a packed vector of replicated shared bits. Each additively shared vector is represented as [BigUint]. Thus, this type contains two [BigUint]s.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rep3BigUintShare {
    pub(crate) a: BigUint,
    pub(crate) b: BigUint,
}

impl Rep3BigUintShare {
    /// Constructs the type from two additive shares.
    pub fn new(a: BigUint, b: BigUint) -> Self {
        Self { a, b }
    }

    pub fn zero_share() -> Self {
        Self {
            a: BigUint::ZERO,
            b: BigUint::ZERO,
        }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (BigUint, BigUint) {
        (self.a, self.b)
    }
}
