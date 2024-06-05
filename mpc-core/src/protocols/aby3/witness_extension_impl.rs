use super::{network::Aby3Network, Aby3PrimeFieldShare, Aby3Protocol};
use crate::{
    protocols::plain::PlainDriver,
    traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol},
};
use ark_ff::PrimeField;
use eyre::{bail, Result};

#[derive(Clone)]
pub enum Aby3VmType<F: PrimeField> {
    Public(F),
    Shared(Aby3PrimeFieldShare<F>),
    BitShared,
}

impl<F: PrimeField> From<Aby3VmType<F>> for Aby3PrimeFieldShare<F> {
    fn from(vm_type: Aby3VmType<F>) -> Self {
        match vm_type {
            Aby3VmType::Shared(share) => share,
            _ => panic!("Cannot convert to share"),
        }
    }
}

impl<F: PrimeField> Default for Aby3VmType<F> {
    fn default() -> Self {
        Self::Public(F::default())
    }
}

impl<F: PrimeField> std::fmt::Debug for Aby3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(arg0) => f.debug_tuple("Public").field(arg0).finish(),
            Self::Shared(arg0) => f.debug_tuple("Shared").field(arg0).finish(),
            Self::BitShared => write!(f, "BitShared"),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for Aby3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Aby3VmType::Public(field) => f.write_str(&format!("PUBLIC ({field})")),
            Aby3VmType::Shared(share) => {
                f.write_str(&format!("SHARED (a: {}, b: {})", share.a, share.b))
            }
            Aby3VmType::BitShared => f.write_str("BIT_SHARED (TODO)"),
        }
    }
}

impl<F: PrimeField> Aby3VmType<F> {
    fn add<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_add(a, b))
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.add_with_public(&a, &b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.add_with_public(&b, &a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => Aby3VmType::Shared(party.add(&a, &b)),
            (_, _) => todo!("BitShared not yet implemented"),
        }
    }

    fn sub<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_sub(a, b))
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.add_with_public(&a, &-b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.add_with_public(&-b, &a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => Aby3VmType::Shared(party.sub(&a, &b)),
            (_, _) => todo!("BitShared not yet implemented"),
        }
    }

    fn mul<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_mul(a, b)?)
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.mul_with_public(&a, &b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.mul_with_public(&b, &a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.mul(&a, &b)?)
            }
            (_, _) => todo!("BitShared not yet implemented"),
        };
        Ok(res)
    }

    fn neg<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self) -> Self {
        match a {
            Aby3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_neg(a))
            }
            Aby3VmType::Shared(a) => Aby3VmType::Shared(party.neg(&a)),
            _ => todo!("BitShared not yet implemented"),
        }
    }

    // Implemented as a * b^-1
    fn div<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_div(a, b)?)
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                let b_inv = party.inv(&b)?;
                Aby3VmType::Shared(party.mul_with_public(&a, &b_inv))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                let b_inv = b.inverse().unwrap();
                Aby3VmType::Shared(party.mul_with_public(&b_inv, &a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let b_inv = party.inv(&b)?;
                Aby3VmType::Shared(party.mul(&a, &b_inv)?)
            }
            (_, _) => todo!("BitShared not implemented"),
        };
        Ok(res)
    }

    fn int_div<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_int_div(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn lt<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_lt(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn le<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_le(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn gt<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_gt(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn ge<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_ge(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn eq<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_eq(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn neq<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_neq(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn shift_l<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_shift_l(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn shift_r<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_shift_r(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bool_and<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bool_and(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bit_and<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bit_and(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bit_xor<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bit_xor(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bit_or<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bit_or(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn is_zero<N: Aby3Network>(_party: &Aby3Protocol<F, N>, a: Self) -> bool {
        match a {
            Aby3VmType::Public(a) => {
                let plain = PlainDriver::default();
                plain.is_zero(a)
            }
            _ => todo!("Shared not implemented"),
        }
    }

    fn to_index<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self) -> Result<F> {
        match a {
            Aby3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                plain.vm_open(a)
            }
            Aby3VmType::Shared(a) => Ok(party.open(&a)?),
            _ => todo!("Shared not implemented"),
        }
    }
}

impl<F: PrimeField> From<Aby3PrimeFieldShare<F>> for Aby3VmType<F> {
    fn from(value: Aby3PrimeFieldShare<F>) -> Self {
        Aby3VmType::Shared(value)
    }
}

impl<F: PrimeField, N: Aby3Network> CircomWitnessExtensionProtocol<F> for Aby3Protocol<F, N> {
    type VmType = Aby3VmType<F>;

    fn vm_add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::add(self, a, b)
    }
    fn vm_sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::sub(self, a, b)
    }
    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::mul(self, a, b)
    }
    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType {
        Self::VmType::neg(self, a)
    }

    fn vm_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::div(self, a, b)
    }

    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::int_div(self, a, b)
    }

    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::lt(self, a, b)
    }

    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::le(self, a, b)
    }

    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::gt(self, a, b)
    }

    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::ge(self, a, b)
    }

    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::eq(self, a, b)
    }

    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        Self::VmType::neq(self, a, b)
    }

    fn vm_shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::shift_r(self, a, b)
    }

    fn vm_shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::shift_l(self, a, b)
    }

    fn vm_bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::bool_and(self, a, b)
    }

    fn vm_bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::bit_xor(self, a, b)
    }

    fn vm_bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::bit_or(self, a, b)
    }

    fn vm_bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::bit_and(self, a, b)
    }

    fn is_zero(&self, a: Self::VmType) -> bool {
        Self::VmType::is_zero(self, a)
    }

    fn vm_open(&mut self, a: Self::VmType) -> Result<F> {
        Self::VmType::to_index(self, a)
    }

    fn vm_to_share(&self, a: Self::VmType) -> Self::FieldShare {
        match a {
            Aby3VmType::Public(a) => self.promote_to_trivial_share(a),
            Aby3VmType::Shared(share) => share,
            Aby3VmType::BitShared => todo!("BitShared not yet implemented"),
        }
    }
}
