use acir::AcirField;

use super::id::PartyID;

//TODO maybe merge this with the VM type? Can be generic over F and then either use AcirField or PrimeField
/// This type represents the basic type of the coACVM. Thus, it can represent either public or shared values.
#[derive(Clone, Debug)]
pub enum Rep3AcvmType<F: AcirField> {
    /// Represents a publicly known value
    Public(F),
    /// Represents a secret-shared value
    Shared(Rep3AcirFieldShare<F>),
    /// Represents a secret-shared binary value. This type is currently not utilized
    BitShared,
}

// THIS IS COPIED FROM [Rep3PrimeFieldShare]! WE NEED TO UNIFY THIS.
/// This type represents a replicated shared value. Since a replicated share of a field element contains additive shares of two parties, this type contains two field elements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rep3AcirFieldShare<F: AcirField> {
    pub(crate) a: F,
    pub(crate) b: F,
}

impl<F: AcirField> Default for Rep3AcvmType<F> {
    fn default() -> Self {
        Rep3AcvmType::Public(F::zero())
    }
}

impl<F: AcirField> Default for Rep3AcirFieldShare<F> {
    fn default() -> Self {
        Self {
            a: F::zero(),
            b: F::zero(),
        }
    }
}

impl<F: AcirField> Rep3AcirFieldShare<F> {
    /// Constructs the type from two additive shares.
    pub fn new(a: F, b: F) -> Self {
        Self { a, b }
    }

    /// Unwraps the type into two additive shares.
    pub fn ab(self) -> (F, F) {
        (self.a, self.b)
    }

    //pub(crate) fn double(&mut self) {
    //    self.a.double_in_place();
    //    self.b.double_in_place();
    //}

    /// Promotes a public field element to a replicated share by setting the additive share of the party with id=0 and leaving all other shares to be 0. Thus, the replicated shares of party 0 and party 1 are set.
    pub fn promote_from_trivial(val: &F, id: PartyID) -> Self {
        match id {
            PartyID::ID0 => Rep3AcirFieldShare::new(*val, F::zero()),
            PartyID::ID1 => Rep3AcirFieldShare::new(F::zero(), *val),
            PartyID::ID2 => Rep3AcirFieldShare::default(),
        }
    }
}

impl<F: AcirField> std::fmt::Display for Rep3AcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rep3AcvmType::Public(field) => f.write_str(&format!("PUBLIC ({field})")),
            Rep3AcvmType::Shared(share) => {
                f.write_str(&format!("SHARED (a: {}, b: {})", share.a, share.b))
            }
            Rep3AcvmType::BitShared => f.write_str("BIT_SHARED (TODO)"),
        }
    }
}

impl<F: AcirField> std::ops::Add for Rep3AcirFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: AcirField> std::ops::Add<&Rep3AcirFieldShare<F>> for Rep3AcirFieldShare<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: AcirField> std::ops::Add<&Rep3AcirFieldShare<F>> for &'_ Rep3AcirFieldShare<F> {
    type Output = Rep3AcirFieldShare<F>;

    fn add(self, rhs: &Rep3AcirFieldShare<F>) -> Self::Output {
        Rep3AcirFieldShare::<F> {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl<F: AcirField> std::ops::AddAssign<&Rep3AcirFieldShare<F>> for Rep3AcirFieldShare<F> {
    fn add_assign(&mut self, rhs: &Self) {
        self.a += rhs.a;
        self.b += rhs.b;
    }
}

impl<F: AcirField> std::ops::Sub for Rep3AcirFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: AcirField> std::ops::Sub<&Rep3AcirFieldShare<F>> for Rep3AcirFieldShare<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: AcirField> std::ops::SubAssign<&Rep3AcirFieldShare<F>> for Rep3AcirFieldShare<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.a -= rhs.a;
        self.b -= rhs.b;
    }
}

impl<F: AcirField> std::ops::Sub<&Rep3AcirFieldShare<F>> for &'_ Rep3AcirFieldShare<F> {
    type Output = Rep3AcirFieldShare<F>;

    fn sub(self, rhs: &Rep3AcirFieldShare<F>) -> Self::Output {
        Rep3AcirFieldShare::<F> {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl<F: AcirField> std::ops::Mul for Rep3AcirFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: Self) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: AcirField> std::ops::Mul<&Rep3AcirFieldShare<F>> for Rep3AcirFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: &Self) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: AcirField> std::ops::Mul<&Rep3AcirFieldShare<F>> for &'_ Rep3AcirFieldShare<F> {
    type Output = F;

    // Local part of mul only
    fn mul(self, rhs: &Rep3AcirFieldShare<F>) -> Self::Output {
        self.a * rhs.a + self.a * rhs.b + self.b * rhs.a
    }
}

impl<F: AcirField> std::ops::Mul<&F> for &'_ Rep3AcirFieldShare<F> {
    type Output = Rep3AcirFieldShare<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        Self::Output {
            a: self.a * *rhs,
            b: self.b * *rhs,
        }
    }
}

impl<F: AcirField> From<F> for Rep3AcvmType<F> {
    fn from(value: F) -> Self {
        Rep3AcvmType::Public(value)
    }
}

impl<F: AcirField> std::ops::Mul<F> for Rep3AcirFieldShare<F> {
    type Output = Rep3AcirFieldShare<F>;

    fn mul(self, rhs: F) -> Self::Output {
        Self::Output {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: AcirField> std::ops::Neg for Rep3AcirFieldShare<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            a: -self.a,
            b: -self.b,
        }
    }
}
impl<F: AcirField> std::ops::Neg for &Rep3AcirFieldShare<F> {
    type Output = Rep3AcirFieldShare<F>;

    fn neg(self) -> Self::Output {
        Rep3AcirFieldShare::<F> {
            a: -self.a,
            b: -self.b,
        }
    }
}
