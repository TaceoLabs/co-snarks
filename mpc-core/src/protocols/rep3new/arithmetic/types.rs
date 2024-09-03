use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::protocols::rep3::{id::PartyID, rngs::Rep3CorrelatedRng};

/// This type represents a replicated shared value. Since a replicated share of a field element contains additive shares of two parties, this type contains two field elements.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3PrimeFieldShare<F: PrimeField> {
    pub(crate) a: F,
    pub(crate) b: F,
}

/// This type represents a vector of replicated shared value. Since a replicated share of a field element contains additive shares of two parties, this type contains two vectors of field elements.
#[derive(Debug, Clone, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3PrimeFieldShareVec<F: PrimeField> {
    pub(crate) a: Vec<F>,
    pub(crate) b: Vec<F>,
}

impl<F: PrimeField> Rep3PrimeFieldShare<F> {
    /// Constructs the type from two additive shares.
    pub fn new(a: F, b: F) -> Self {
        Self { a, b }
    }

    pub(super) fn zero_share() -> Self {
        Self {
            a: F::zero(),
            b: F::zero(),
        }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (F, F) {
        (self.a, self.b)
    }

    pub(crate) fn double(&mut self) {
        self.a.double_in_place();
        self.b.double_in_place();
    }

    pub(super) fn rand(rngs: &mut Rep3CorrelatedRng) -> Self {
        let (a, b) = rngs.rand.random_fes();
        Self::new(a, b)
    }

    /// Promotes a public field element to a replicated share by setting the additive share of the party with id=0 and leaving all other shares to be 0. Thus, the replicated shares of party 0 and party 1 are set.
    pub fn promote_from_trivial(val: &F, id: PartyID) -> Self {
        match id {
            PartyID::ID0 => Self::new(*val, F::zero()),
            PartyID::ID1 => Self::new(F::zero(), *val),
            PartyID::ID2 => Self::zero_share(),
        }
    }
}

impl<F: PrimeField> Rep3PrimeFieldShareVec<F> {
    /// Constructs the type from two vectors of additive shares.
    pub fn new(a: Vec<F>, b: Vec<F>) -> Self {
        Self { a, b }
    }

    /// Unwraps the type into two vectors of additive shares.
    pub fn get_ab(self) -> (Vec<F>, Vec<F>) {
        (self.a, self.b)
    }

    /// Checks whether the wrapped vectors are empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.a.is_empty(), self.b.is_empty());
        self.a.is_empty()
    }

    /// Returns the length of the wrapped vectors.
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        self.a.len()
    }

    /// Promotes a vector of public field elements to a vector of replicated shares by setting the additive shares of the party with id=0 and leaving all other shares to be 0. Thus, the replicated shares of party 0 and party 1 are set.
    pub fn promote_from_trivial(val: &[F], id: PartyID) -> Self {
        let len = val.len();

        match id {
            PartyID::ID0 => {
                let a = val.to_vec();
                let b = vec![F::zero(); len];
                Self { a, b }
            }
            PartyID::ID1 => {
                let a = vec![F::zero(); len];
                let b = val.to_vec();
                Self { a, b }
            }
            PartyID::ID2 => {
                let a = vec![F::zero(); len];
                let b = vec![F::zero(); len];
                Self { a, b }
            }
        }
    }
}
