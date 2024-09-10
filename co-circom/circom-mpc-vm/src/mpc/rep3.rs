use std::io;

use ark_ff::{One, PrimeField};
use eyre::{bail, eyre};
use mpc_core::protocols::rep3new::{
    arithmetic, binary, conversion,
    network::{IoContext, Rep3Network},
    Rep3BigUintShare, Rep3PrimeFieldShare,
};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

use super::{
    plain::{to_usize, CircomPlainVmWitnessExtension},
    VmCircomWitnessExtension,
};
use tokio::runtime::{self};

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;
type BinaryShare<F> = Rep3BigUintShare<F>;

#[derive(Clone)]
pub enum Rep3VmType<F: PrimeField> {
    Public(F),
    Arithmetic(ArithmeticShare<F>),
    Binary(BinaryShare<F>),
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

impl<F: PrimeField> From<BinaryShare<F>> for Rep3VmType<F> {
    fn from(value: BinaryShare<F>) -> Self {
        Self::Binary(value)
    }
}

impl<F: PrimeField> Default for Rep3VmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

pub struct CircomRep3VmWitnessExtension<F: PrimeField, N: Rep3Network> {
    io_context: IoContext<N>,
    runtime: runtime::Runtime,
    plain: CircomPlainVmWitnessExtension<F>,
}

impl<F: PrimeField, N: Rep3Network> CircomRep3VmWitnessExtension<F, N> {
    pub fn from_network(network: N) -> io::Result<Self> {
        let runtime = runtime::Builder::new_current_thread().build()?;
        let io_context = runtime.block_on(IoContext::init(network))?;
        Ok(Self {
            io_context,
            runtime,
            plain: CircomPlainVmWitnessExtension::default(),
        })
    }

    /// Normally F is split into positive and negative numbers in the range [0, p/2] and [p/2 + 1, p)
    /// However, for comparisons, we want the negative numbers to be "lower" than the positive ones.
    /// Therefore we shift the input by p/2 + 1 to the left, which results in a mapping of [negative, 0, positive] into F.
    /// We can then compare the numbers as if they were unsigned.
    /// While this could be done easier by just comparing the numbers as BigInt, we do it this way because this is easier to replicate in MPC later.
    #[inline(always)]
    fn val(&mut self, z: ArithmeticShare<F>) -> ArithmeticShare<F> {
        let modulus: BigUint = F::MODULUS.into();
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        let p_half_plus_one = F::from(modulus / two + one);
        arithmetic::sub_shared_by_public(z, p_half_plus_one, self.io_context.id)
    }
}

impl<F: PrimeField, N: Rep3Network> VmCircomWitnessExtension<F>
    for CircomRep3VmWitnessExtension<F, N>
{
    type ArithmeticShare = ArithmeticShare<F>;

    type BinaryShare = BinaryShare<F>;

    type VmType = Rep3VmType<F>;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.add(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::add_public(a, b, self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::add(a, b).into())
            }
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                Ok(arithmetic::add_public(a, b, self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(arithmetic::add(a, b).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(arithmetic::add(a, b).into())
            }
        }
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.sub(a, b)?.into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::sub_shared_by_public(a, b, self.io_context.id).into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::sub_shared_by_public(b, a, self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::sub(a, b).into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(arithmetic::sub_shared_by_public(b, a, self.io_context.id).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                Ok(arithmetic::sub_shared_by_public(a, b, self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(arithmetic::sub(a, b).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                Ok(arithmetic::sub(a, b).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(arithmetic::sub(a, b).into())
            }
        }
    }

    fn mul(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.mul(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::mul_public(a, b).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => Ok(
                futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?.into(),
            ),
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                Ok(arithmetic::mul_public(a, b).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(
                    futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                Ok(
                    futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?
                        .into(),
                )
            }
        }
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.div(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let b = futures::executor::block_on(arithmetic::inv(b, &mut self.io_context))?;
                Ok(arithmetic::mul_public(b, a).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                Ok(arithmetic::mul_public(a, b.inverse().unwrap()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let b = futures::executor::block_on(arithmetic::inv(b, &mut self.io_context))?;
                Ok(
                    futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                let b = futures::executor::block_on(arithmetic::inv(b, &mut self.io_context))?;
                Ok(arithmetic::mul_public(b, a).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                Ok(arithmetic::mul_public(a, b.inverse().unwrap()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                let b = futures::executor::block_on(arithmetic::inv(b, &mut self.io_context))?;
                Ok(
                    futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Binary(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(arithmetic::inv(b, &mut self.io_context))?;
                Ok(
                    futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                let b = futures::executor::block_on(arithmetic::inv(b, &mut self.io_context))?;
                Ok(
                    futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?
                        .into(),
                )
            }
        }
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.int_div(a, b)?.into()),
            _ => todo!("Shared int_div not implemented"),
        }
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.pow(a, b)?.into()),
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.pow(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    return Ok(Rep3VmType::Public(F::one()));
                }
                Ok(
                    futures::executor::block_on(arithmetic::pow_public(
                        a,
                        b,
                        &mut self.io_context,
                    ))?
                    .into(),
                )
            }
            _ => todo!("pow with shared exponent not implemented"),
        }
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.modulo(a, b)?.into()),
            (_, _) => todo!("Shared mod not implemented"),
        }
    }

    fn sqrt(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.sqrt(a)?.into()),
            Rep3VmType::Arithmetic(a) => {
                let sqrt = futures::executor::block_on(arithmetic::sqrt(a, &mut self.io_context))?;
                // Correction to give the result closest to 0
                // I.e., 2 * is_pos * sqrt - sqrt
                let is_pos = futures::executor::block_on(arithmetic::ge_public(
                    sqrt,
                    F::zero(),
                    &mut self.io_context,
                ))?;
                let mut mul = futures::executor::block_on(arithmetic::mul(
                    sqrt,
                    is_pos,
                    &mut self.io_context,
                ))?;
                mul.double();
                mul -= sqrt;
                Ok(mul.into())
            }
            Rep3VmType::Binary(a) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.sqrt(a.into())
            }
        }
    }

    fn neg(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.neg(a)?.into()),
            Rep3VmType::Arithmetic(a) => Ok(arithmetic::neg(a).into()),
            Rep3VmType::Binary(a) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                Ok(arithmetic::neg(a).into())
            }
        }
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.lt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::gt_public(b, a, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::lt_public(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(futures::executor::block_on(arithmetic::lt(a, b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.lt(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.lt(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.lt(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.lt(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.lt(a.into(), b.into())
            }
        }
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.le(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::ge_public(b, a, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::le_public(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(futures::executor::block_on(arithmetic::le(a, b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.le(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.le(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.le(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.le(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.le(a.into(), b.into())
            }
        }
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.gt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::lt_public(b, a, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::gt_public(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(futures::executor::block_on(arithmetic::gt(a, b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.gt(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.gt(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.gt(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.gt(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.gt(a.into(), b.into())
            }
        }
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.ge(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::le_public(b, a, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(
                    futures::executor::block_on(arithmetic::ge_public(a, b, &mut self.io_context))?
                        .into(),
                )
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(futures::executor::block_on(arithmetic::ge(a, b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.ge(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.ge(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.ge(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.ge(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.ge(a.into(), b.into())
            }
        }
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.eq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => Ok(
                futures::executor::block_on(arithmetic::eq_public(a, b, &mut self.io_context))?
                    .into(),
            ),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(futures::executor::block_on(arithmetic::eq(a, b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.eq(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.eq(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.eq(a.into(), b.into())
            }
        }
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.neq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => Ok(
                futures::executor::block_on(arithmetic::neq_public(a, b, &mut self.io_context))?
                    .into(),
            ),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => Ok(
                futures::executor::block_on(arithmetic::neq(a, b, &mut self.io_context))?.into(),
            ),
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.neq(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.neq(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.neq(a.into(), b.into())
            }
        }
    }

    fn shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.shift_r(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(_))
            | (Rep3VmType::Public(a), Rep3VmType::Binary(_)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Rep3VmType::Public(F::zero()));
                }
                todo!("Shared shift_right (public by shared) not implemented");
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                // some special casing
                if b == F::zero() {
                    return Ok(Rep3VmType::Arithmetic(a));
                }
                // TODO: check bounds of b
                let shift = usize::try_from(b.into_bigint().as_mut()[0]).unwrap();
                let bits = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                let res = &bits >> shift;
                // TODO remove conv back to arith?
                let res = futures::executor::block_on(conversion::b2a(&res, &mut self.io_context))?;
                Ok(res.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                // some special casing
                if b == F::zero() {
                    return Ok(Rep3VmType::Binary(a));
                }
                // TODO: check bounds of b
                let shift = usize::try_from(b.into_bigint().as_mut()[0]).unwrap();
                let res = a >> shift;
                Ok(res.into())
            }
            (_, _) => todo!("Shared shift_right not implemented"),
        }
    }

    fn shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.shift_l(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let b = futures::executor::block_on(conversion::a2b(b, &mut self.io_context))?;
                self.shift_l(a.into(), b.into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Binary(b)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Rep3VmType::Public(F::zero()));
                }

                // TODO: check for overflows
                // This case is equivalent to a*2^b
                // Strategy: limit size of b to k bits
                // bit-decompose b into bits b_i
                let bit_shares = b;
                let individual_bit_shares = (0..8)
                    .map(|i| {
                        let bit = Rep3BigUintShare::new(
                            (bit_shares.a.clone() >> i) & BigUint::one(),
                            (bit_shares.b.clone() >> i) & BigUint::one(),
                        );
                        futures::executor::block_on(conversion::b2a(&bit, &mut self.io_context))
                    })
                    .collect::<Result<Vec<_>, std::io::Error>>()?;
                // v_i = 2^2^i * <b_i> + 1 - <b_i>
                let mut vs: Vec<_> = individual_bit_shares
                    .into_iter()
                    .enumerate()
                    .map(|(i, b_i)| {
                        let two = F::from(2u64);
                        let two_to_two_to_i = two.pow([2u64.pow(i as u32)]);
                        let v = arithmetic::mul_public(b_i, two_to_two_to_i);
                        let v = arithmetic::add_public(v, F::one(), self.io_context.id);
                        arithmetic::sub(v, b_i)
                    })
                    .collect();

                // v = \prod v_i
                // TODO: This should be done in a multiplication tree
                let mut v = vs.pop().unwrap();
                for v_i in vs {
                    v = futures::executor::block_on(arithmetic::mul(v, v_i, &mut self.io_context))?;
                }
                // TODO could use try_fold from futures::stream
                // let last = vs.pop().unwrap();
                // let v = futures::executor::block_on(
                //     futures::stream::iter(vs.into_iter().map(|v| Ok(v)))
                //         .try_fold(last, |a, b| async move {
                //             arithmetic::mul(a, b, &mut self.io_context).await
                //         }),
                // )?;
                let res = arithmetic::mul_public(v, a);
                Ok(res.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                // some special casing
                if b == F::zero() {
                    return Ok(Rep3VmType::Arithmetic(a));
                }
                // TODO: handle overflows
                // This case is equivalent to a*2^b
                // TODO: assert b < 256?
                let shift = F::from(2u64).pow([b.into_bigint().as_mut()[0]]);
                Ok(arithmetic::mul_public(a, shift).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                // some special casing
                if b == F::zero() {
                    return Ok(Rep3VmType::Binary(a));
                }
                // TODO: check bounds of b
                let shift = usize::try_from(b.into_bigint().as_mut()[0]).unwrap();
                let res = a << shift;
                Ok(res.into())
            }
            (_, _) => todo!("Shared shift_right not implemented"),
        }
    }

    fn bool_not(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.bool_not(a)?.into()),
            Rep3VmType::Arithmetic(a) => {
                let neg_a = arithmetic::neg(a);
                let not_a = arithmetic::add_public(neg_a, F::one(), self.io_context.id);
                Ok(not_a.into())
            }
            Rep3VmType::Binary(a) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.bool_not(a.into())
            }
        }
    }

    fn bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bool_and(a, b)?.into()),
            (a, b) => self.mul(a, b),
        }
    }

    fn bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bool_or(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let mul = arithmetic::mul_public(a, b);
                let add = arithmetic::add_public(a, b, self.io_context.id);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let mul = futures::executor::block_on(arithmetic::mul(a, b, &mut self.io_context))?;
                let add = arithmetic::add(a, b);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.bool_or(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.bool_or(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::b2a(&b, &mut self.io_context))?;
                self.bool_or(a.into(), b.into())
            }
        }
    }

    fn cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> eyre::Result<Self::VmType> {
        match (cond, truthy, falsy) {
            (Rep3VmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() {
                    Ok(truthy)
                } else {
                    Ok(falsy)
                }
            }
            (Rep3VmType::Arithmetic(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy.clone())?;
                let d = self.mul(cond.into(), b_min_a)?;
                self.add(falsy, d)
            }
            (Rep3VmType::Binary(cond), truthy, falsy) => {
                let cond =
                    futures::executor::block_on(conversion::b2a(&cond, &mut self.io_context))?;
                self.cmux(cond.into(), truthy, falsy)
            }
        }
    }

    fn bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_xor(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                Ok(binary::xor_public(&a, b.into_bigint().into(), self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::a2b(b, &mut self.io_context))?;
                Ok(binary::xor(&a, &b).into())
            }
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                Ok(binary::xor_public(&a, b.into_bigint().into(), self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                Ok(binary::xor(&a, &b).into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => Ok(binary::xor(&a, &b).into()),
        }
    }

    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_or(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                self.bit_or(a.into(), b.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::a2b(b, &mut self.io_context))?;
                self.bit_or(a.into(), b.into())
            }
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                Ok(binary::or_public(&a, b.into_bigint().into(), self.io_context.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                self.bit_or(a.into(), b.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                Ok(futures::executor::block_on(binary::or(&a, &b, &mut self.io_context))?.into())
            }
        }
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_and(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                Ok(binary::and_with_public(&a, b.into_bigint().into()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                let b = futures::executor::block_on(conversion::a2b(b, &mut self.io_context))?;
                Ok(futures::executor::block_on(binary::and(&a, &b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Public(b), Rep3VmType::Binary(a))
            | (Rep3VmType::Binary(a), Rep3VmType::Public(b)) => {
                Ok(binary::and_with_public(&a, b.into_bigint().into()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Binary(b))
            | (Rep3VmType::Binary(b), Rep3VmType::Arithmetic(a)) => {
                let a = futures::executor::block_on(conversion::a2b(a, &mut self.io_context))?;
                Ok(futures::executor::block_on(binary::and(&a, &b, &mut self.io_context))?.into())
            }
            (Rep3VmType::Binary(a), Rep3VmType::Binary(b)) => {
                Ok(futures::executor::block_on(binary::and(&a, &b, &mut self.io_context))?.into())
            }
        }
    }

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> eyre::Result<bool> {
        if !allow_secret_inputs && self.is_shared(&a)? {
            bail!("allow_secret_inputs is false and input is shared");
        }
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.is_zero(a, allow_secret_inputs)?),
            Rep3VmType::Arithmetic(a) => Ok(futures::executor::block_on(arithmetic::is_zero(
                a,
                &mut self.io_context,
            ))?),
            Rep3VmType::Binary(a) => {
                let a = futures::executor::block_on(conversion::b2a(&a, &mut self.io_context))?;
                self.is_zero(a.into(), allow_secret_inputs)
            }
        }
    }

    fn is_shared(&mut self, a: &Self::VmType) -> eyre::Result<bool> {
        match a {
            Rep3VmType::Public(_) => Ok(false),
            Rep3VmType::Arithmetic(_) => Ok(true),
            Rep3VmType::Binary(_) => Ok(true),
        }
    }

    fn to_index(&mut self, a: Self::VmType) -> eyre::Result<usize> {
        if let Rep3VmType::Public(a) = a {
            Ok(to_usize!(a))
        } else {
            bail!("ToIndex called on shared value!")
        }
    }

    fn open(&mut self, a: Self::VmType) -> eyre::Result<F> {
        match a {
            Rep3VmType::Public(a) => Ok(a),
            Rep3VmType::Arithmetic(a) => Ok(futures::executor::block_on(arithmetic::open(
                a,
                &mut self.io_context,
            ))?),
            Rep3VmType::Binary(a) => {
                Ok(futures::executor::block_on(binary::open(&a, &mut self.io_context))?.into())
            }
        }
    }

    fn to_share(&self, a: Self::VmType) -> Self::ArithmeticShare {
        match a {
            Rep3VmType::Public(a) => arithmetic::promote_to_trivial_share(self.io_context.id, a),
            Rep3VmType::Arithmetic(a) => a,
            Rep3VmType::Binary(_) => todo!("BitShared not yet implemented"),
        }
    }

    fn public_one(&self) -> Self::VmType {
        F::one().into()
    }

    fn public_zero(&self) -> Self::VmType {
        F::zero().into()
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
                let (a, b) = arithmetic.ab();
                f.write_str(&format!("Arithmetic (a: {}, b: {})", a, b))
            }
            Self::Binary(binary) => {
                let (a, b) = binary.clone().ab();
                f.write_str(&format!("Binary (a: {}, b: {})", a, b))
            }
        }
    }
}
