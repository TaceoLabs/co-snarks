use super::{fieldshare::GSZPrimeFieldShare, network::GSZNetwork, GSZProtocol};
use crate::{
    protocols::plain::PlainDriver,
    traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol},
};
use ark_ff::PrimeField;
use eyre::{bail, Result};

#[derive(Clone)]
pub enum GSZVmType<F: PrimeField> {
    Public(F),
    Shared(GSZPrimeFieldShare<F>),
    BitShared,
}

impl<F: PrimeField> Default for GSZVmType<F> {
    fn default() -> Self {
        Self::Public(F::default())
    }
}

impl<F: PrimeField> std::fmt::Debug for GSZVmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(arg0) => f.debug_tuple("Public").field(arg0).finish(),
            Self::Shared(arg0) => f.debug_tuple("Shared").field(arg0).finish(),
            Self::BitShared => write!(f, "BitShared"),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for GSZVmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GSZVmType::Public(field) => f.write_str(&format!("PUBLIC ({field})")),
            GSZVmType::Shared(share) => f.write_str(&format!("SHARED ({})", share.a)),
            GSZVmType::BitShared => f.write_str("BIT_SHARED (TODO)"),
        }
    }
}

impl<F: PrimeField> GSZVmType<F> {
    fn add<N: GSZNetwork>(party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_add(a, b))
            }
            (GSZVmType::Public(a), GSZVmType::Shared(b)) => {
                GSZVmType::Shared(party.add_with_public(&a, &b))
            }
            (GSZVmType::Shared(a), GSZVmType::Public(b)) => {
                GSZVmType::Shared(party.add_with_public(&b, &a))
            }
            (GSZVmType::Shared(a), GSZVmType::Shared(b)) => GSZVmType::Shared(party.add(&a, &b)),
            (_, _) => todo!("BitShared not yet implemented"),
        }
    }

    fn sub<N: GSZNetwork>(party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_sub(a, b))
            }
            (GSZVmType::Public(a), GSZVmType::Shared(b)) => {
                GSZVmType::Shared(party.add_with_public(&a, &-b))
            }
            (GSZVmType::Shared(a), GSZVmType::Public(b)) => {
                GSZVmType::Shared(party.add_with_public(&-b, &a))
            }
            (GSZVmType::Shared(a), GSZVmType::Shared(b)) => GSZVmType::Shared(party.sub(&a, &b)),
            (_, _) => todo!("BitShared not yet implemented"),
        }
    }

    fn mul<N: GSZNetwork>(party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_mul(a, b)?)
            }
            (GSZVmType::Public(a), GSZVmType::Shared(b)) => {
                GSZVmType::Shared(party.mul_with_public(&a, &b))
            }
            (GSZVmType::Shared(a), GSZVmType::Public(b)) => {
                GSZVmType::Shared(party.mul_with_public(&b, &a))
            }
            (GSZVmType::Shared(a), GSZVmType::Shared(b)) => GSZVmType::Shared(party.mul(&a, &b)?),
            (_, _) => todo!("BitShared not yet implemented"),
        };
        Ok(res)
    }

    fn neg<N: GSZNetwork>(party: &mut GSZProtocol<F, N>, a: Self) -> Self {
        match a {
            GSZVmType::Public(a) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_neg(a))
            }
            GSZVmType::Shared(a) => GSZVmType::Shared(party.neg(&a)),
            _ => todo!("BitShared not yet implemented"),
        }
    }

    // Implemented as a * b^-1
    fn div<N: GSZNetwork>(party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_div(a, b)?)
            }
            (GSZVmType::Public(a), GSZVmType::Shared(b)) => {
                let b_inv = party.inv(&b)?;
                GSZVmType::Shared(party.mul_with_public(&a, &b_inv))
            }
            (GSZVmType::Shared(a), GSZVmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                let b_inv = b.inverse().unwrap();
                GSZVmType::Shared(party.mul_with_public(&b_inv, &a))
            }
            (GSZVmType::Shared(a), GSZVmType::Shared(b)) => {
                let b_inv = party.inv(&b)?;
                GSZVmType::Shared(party.mul(&a, &b_inv)?)
            }
            (_, _) => todo!("BitShared not implemented"),
        };
        Ok(res)
    }

    fn int_div<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_int_div(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn lt<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_lt(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn le<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_le(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn gt<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_gt(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn ge<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_ge(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn eq<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_eq(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn neq<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_neq(a, b))
            }
            (_, _) => todo!("Shared not implemented"),
        }
    }

    fn shift_l<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_shift_l(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn shift_r<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_shift_r(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bool_and<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_bool_and(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bit_and<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_bit_and(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bit_xor<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_bit_xor(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn bit_or<N: GSZNetwork>(_party: &mut GSZProtocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (GSZVmType::Public(a), GSZVmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                GSZVmType::Public(plain.vm_bit_or(a, b)?)
            }
            (_, _) => todo!("Shared not implemented"),
        };
        Ok(res)
    }

    fn is_zero<N: GSZNetwork>(_party: &GSZProtocol<F, N>, a: Self) -> bool {
        match a {
            GSZVmType::Public(a) => {
                let plain = PlainDriver::default();
                plain.is_zero(a)
            }
            _ => todo!("Shared not implemented"),
        }
    }

    fn to_index<N: GSZNetwork>(_party: &GSZProtocol<F, N>, a: Self) -> F {
        match a {
            GSZVmType::Public(a) => {
                let plain = PlainDriver::default();
                plain.vm_open(a)
            }
            _ => todo!("Shared not implemented"),
        }
    }
}

impl<F: PrimeField, N: GSZNetwork> CircomWitnessExtensionProtocol<F> for GSZProtocol<F, N> {
    type VmType = GSZVmType<F>;

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

    fn vm_open(&self, a: Self::VmType) -> F {
        Self::VmType::to_index(self, a)
    }
}
