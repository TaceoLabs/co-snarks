use super::{network::Aby3Network, Aby3PrimeFieldShare, Aby3Protocol, IoResult};
use crate::traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol};
use ark_ff::PrimeField;

pub enum Aby3VmType<F: PrimeField> {
    Public(F),
    Shared(Aby3PrimeFieldShare<F>),
}

impl<F: PrimeField> Aby3VmType<F> {
    fn add<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => Aby3VmType::Public(a + b),
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.add_with_public(&a, &b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.add_with_public(&b, &a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => Aby3VmType::Shared(party.add(&a, &b)),
        }
    }

    fn sub<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => Aby3VmType::Public(a - b),
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.add_with_public(&a, &-b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.add_with_public(&b, &-a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => Aby3VmType::Shared(party.sub(&a, &b)),
        }
    }

    fn mul<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> IoResult<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => Aby3VmType::Public(a * b),
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.mul_with_public(&a, &b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.mul_with_public(&b, &a))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.mul(&a, &b)?)
            }
        };
        Ok(res)
    }

    fn neg<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self) -> Self {
        match a {
            Aby3VmType::Public(a) => Aby3VmType::Public(-a),
            Aby3VmType::Shared(a) => Aby3VmType::Shared(party.neg(&a)),
        }
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
    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> IoResult<Self::VmType> {
        Self::VmType::mul(self, a, b)
    }
    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType {
        Self::VmType::neg(self, a)
    }
}
