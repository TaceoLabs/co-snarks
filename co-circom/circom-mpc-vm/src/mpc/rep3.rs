use ark_ff::PrimeField;
use mpc_core::protocols::{
    rep3::network::Rep3Network,
    rep3new::{network::IoContext, Rep3BigUintShare, Rep3PrimeFieldShare},
};

use super::VmCircomWitnessExtension;

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;
type BinaryShare = Rep3BigUintShare;

#[derive(Clone)]
pub enum Rep3VmType<F: PrimeField> {
    Public(F),
    Arithmetic(ArithmeticShare<F>),
    Binary(BinaryShare),
}

impl<F: PrimeField> From<F> for Rep3VmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ArithmeticShare<F>> for Rep3VmType<F> {
    fn from(value: ArithmeticShare<F>) -> Self {
        Self::Arithmetic(value)
    }
}

impl<F: PrimeField> Default for Rep3VmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

pub struct Rep3Driver<N: Rep3Network> {
    io_context: IoContext<N>,
}

impl<N: Rep3Network> Rep3Driver<N> {
    pub fn new(network: N) -> std::io::Result<Self> {
        Ok(Self {
            io_context: IoContext::init(network)?,
        })
    }
}

impl<F: PrimeField, N: Rep3Network> VmCircomWitnessExtension<F> for Rep3Driver<N> {
    type ArithmeticShare = ArithmeticShare<F>;

    type BinaryShare = BinaryShare;

    type VmType = Rep3VmType<F>;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn mul(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn sqrt(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn neg(&mut self, a: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bool_not(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> eyre::Result<bool> {
        todo!()
    }

    fn is_shared(&mut self, a: &Self::VmType) -> eyre::Result<bool> {
        todo!()
    }

    fn to_index(&mut self, a: Self::VmType) -> eyre::Result<usize> {
        todo!()
    }

    fn open(&mut self, a: Self::VmType) -> eyre::Result<F> {
        todo!()
    }

    fn to_share(&self, a: Self::VmType) -> Self::ArithmeticShare {
        todo!()
    }

    fn public_one(&self) -> Self::VmType {
        todo!()
    }

    fn public_zero(&self) -> Self::VmType {
        todo!()
    }
}

impl<F: PrimeField> std::fmt::Debug for Rep3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Arithmetic(share) => f.debug_tuple("Arithmetic").field(share).finish(),
            Self::Binary(binary) => f.debug_tuple("Binary").field(binary).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for Rep3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.write_str(&format!("Public ({field})")),
            Self::Arithmetic(arithmetic) => {
                let (a, b) = arithmetic.clone().ab();
                f.write_str(&format!("Arithmetic (a: {}, b: {})", a, b))
            }
            Self::Binary(binary) => {
                let (a, b) = binary.clone().ab();
                f.write_str(&format!("Binary (a: {}, b: {})", a, b))
            }
        }
    }
}
