//! This module implements the [`Rep3AcvmType`]. At the moment, this is necessary
//! because Noir doesn't use the PrimeField trait but the AcirField trait. Therefore,
//! we have to re-implement everything. We do not like that.
//!
//! THIS WILL ALMOST CERTAINLY GET AN OVERHAUL. There is so much duplicated code.

use std::io;

use acir::AcirField;
use eyre::bail;

use crate::traits::LookupTableProvider;

use super::{id::PartyID, network::Rep3Network, Rep3Protocol};

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

impl<F: AcirField> Rep3AcvmType<F> {
    /// combines the three shares into one. Inverse operation of share.
    ///
    /// # Returns
    /// The reconstructed element. If the "types" of the three shares do not match
    /// (e.g., Public and two are Shared), we return an Error.
    pub fn combine_elements(a: Self, b: Self, c: Self) -> eyre::Result<F> {
        match (a, b, c) {
            (Self::Public(a), Self::Public(b), Self::Public(c)) => {
                if a == b && b == c {
                    Ok(a)
                } else {
                    bail!("combine ACVM type did not work! Not matching public values")
                }
            }
            (Self::Shared(a), Self::Shared(b), Self::Shared(c)) => {
                Ok(super::utils::combine_acir_element(a, b, c))
            }
            _ => unimplemented!(),
        }
    }
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

    fn add_with_public<N: Rep3Network>(network: &N, public: F, shared: &Self) -> Self {
        let mut res = shared.to_owned();
        match network.get_id() {
            PartyID::ID0 => res.a += public,
            PartyID::ID1 => res.b += public,
            PartyID::ID2 => {}
        }
        res
    }

    fn inv<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, shared: &Self) -> io::Result<Self> {
        let (a, b) = party.rngs.rand.random_acir_fes();
        let random = Self { a, b };
        let tmp = party.mul_acir_field(shared, &random)?;
        let y = party.open_acir_field(&tmp)?;
        if y.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of inverse in MPC: cannot compute inverse of zero",
            ));
        }
        let y_inv = y.inverse();
        Ok(random * y_inv)
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

impl<F: AcirField> std::ops::Neg for Rep3AcvmType<F> {
    type Output = Rep3AcvmType<F>;

    fn neg(self) -> Self::Output {
        match self {
            Rep3AcvmType::Public(a) => Rep3AcvmType::Public(-a),
            Rep3AcvmType::Shared(a) => Rep3AcvmType::Shared(-a),
            Rep3AcvmType::BitShared => unimplemented!("bit share not implemented"),
        }
    }
}

impl<F: AcirField> Rep3AcvmType<F> {
    pub(super) fn add<N: Rep3Network>(network: &N, lhs: Self, rhs: Self) -> Self {
        match (lhs, rhs) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b)) => Rep3AcvmType::Public(a + b),
            (Rep3AcvmType::Public(a), Rep3AcvmType::Shared(b)) => {
                Rep3AcvmType::Shared(Rep3AcirFieldShare::add_with_public(network, a, &b))
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Public(b)) => {
                Rep3AcvmType::Shared(Rep3AcirFieldShare::add_with_public(network, b, &a))
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b)) => Rep3AcvmType::Shared(a + b),
            (_, _) => todo!("BitShared add not yet implemented"),
        }
    }

    pub(super) fn add_with_public<N: Rep3Network>(network: &N, a: F, b: Self) -> Self {
        match b {
            Rep3AcvmType::Public(public) => Rep3AcvmType::Public(public + a),
            Rep3AcvmType::Shared(shared) => {
                Rep3AcvmType::Shared(Rep3AcirFieldShare::add_with_public(network, a, &shared))
            }
            Rep3AcvmType::BitShared => todo!("bitshared not implemented at the moment"),
        }
    }

    pub(super) fn mul<N: Rep3Network>(
        party: &mut Rep3Protocol<F, N>,
        a: Self,
        b: Self,
    ) -> io::Result<Self> {
        let res = match (a, b) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b)) => Rep3AcvmType::Public(a * b),
            (Rep3AcvmType::Public(a), Rep3AcvmType::Shared(b)) => Rep3AcvmType::Shared(&b * &a),
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Public(b)) => Rep3AcvmType::Shared(&a * &b),
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b)) => {
                Rep3AcvmType::Shared(party.mul_acir_field(&a, &b)?)
            }
            (_, _) => todo!("BitShared mul not yet implemented"),
        };
        Ok(res)
    }

    pub(super) fn mul_with_public(a: F, b: Self) -> Self {
        match b {
            Rep3AcvmType::Public(public) => Rep3AcvmType::Public(public * a),
            Rep3AcvmType::Shared(shared) => Rep3AcvmType::Shared(&shared * &a),
            Rep3AcvmType::BitShared => unimplemented!("bit share not implemented"),
        }
    }

    pub(super) fn div<N: Rep3Network>(
        party: &mut Rep3Protocol<F, N>,
        num: Self,
        den: Self,
    ) -> io::Result<Self> {
        let inverse = Self::inv(party, den)?;
        Self::mul(party, num, inverse)
    }

    pub(super) fn inv<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self) -> io::Result<Self> {
        let res = match a {
            Rep3AcvmType::Public(a) => Rep3AcvmType::Public(a.inverse()),
            Rep3AcvmType::Shared(a) => {
                Rep3AcvmType::Shared(Rep3AcirFieldShare::<F>::inv(party, &a)?)
            }
            Rep3AcvmType::BitShared => unimplemented!("bit share not implemented"),
        };
        Ok(res)
    }
}

impl<F: AcirField, N: Rep3Network> Rep3Protocol<F, N> {
    fn mul_acir_field(
        &mut self,
        a: &Rep3AcirFieldShare<F>,
        b: &Rep3AcirFieldShare<F>,
    ) -> io::Result<Rep3AcirFieldShare<F>> {
        let local_a = a * b + self.rngs.rand.masking_acir_field_element::<F>();
        let bytes_a = local_a.to_be_bytes();
        self.network.send_next(bytes_a)?;
        let local_b_bytes: Vec<u8> = self.network.recv_prev()?;
        Ok(Rep3AcirFieldShare {
            a: local_a,
            b: F::from_be_bytes_reduce(&local_b_bytes),
        })
    }

    fn open_acir_field(&mut self, a: &Rep3AcirFieldShare<F>) -> std::io::Result<F> {
        let bytes = a.b.to_be_bytes();
        self.network.send_next(bytes)?;
        let bytes = self.network.recv_prev::<Vec<u8>>()?;
        let c = F::from_be_bytes_reduce(&bytes);
        Ok(a.a + a.b + c)
    }
}

impl<F: AcirField, N: Rep3Network> LookupTableProvider<Rep3AcvmType<F>> for Rep3Protocol<F, N> {
    type LUT = ();

    fn init_lut(&mut self, _values: Vec<Rep3AcvmType<F>>) -> Self::LUT {
        todo!()
    }

    fn get_from_lut(&mut self, _index: &Rep3AcvmType<F>, _lut: &Self::LUT) -> Rep3AcvmType<F> {
        todo!()
    }

    fn write_to_lut(
        &mut self,
        _index: Rep3AcvmType<F>,
        _value: Rep3AcvmType<F>,
        _lut: &mut Self::LUT,
    ) {
        todo!()
    }
}
