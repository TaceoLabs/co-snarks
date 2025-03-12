use super::{
    plain::{to_usize, CircomPlainVmWitnessExtension},
    VmCircomWitnessExtension,
};
use crate::mpc_vm::VMConfig;
use ark_ff::{One, PrimeField};
use eyre::{bail, eyre};
use itertools::Itertools;
use mpc_core::{
    protocols::rep3::{
        arithmetic::{self, promote_to_trivial_share},
        binary,
        conversion::{self, bit_inject_many},
        network::{self},
        Rep3PrimeFieldShare, Rep3State,
    },
    Fork,
};
use mpc_engine::{MpcEngine, Network};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;

/// This type represents a public, arithmetic share, or binary share type used in the co-cricom MPC-VM
#[derive(Clone)]
pub enum Rep3VmType<F: PrimeField> {
    /// The public variant
    Public(F),
    /// The arithemtic share variant
    Arithmetic(ArithmeticShare<F>),
    // /// The binary share variant
    // Binary(BinaryShare<F>),
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

pub struct CircomRep3VmWitnessExtension<'a, F: PrimeField, N: Network> {
    id: usize,
    engine: &'a MpcEngine<N>,
    state0: Rep3State,
    state1: Rep3State,
    plain: CircomPlainVmWitnessExtension<F>,
}

impl<'a, F: PrimeField, N: Network + 'static> CircomRep3VmWitnessExtension<'a, F, N> {
    pub fn new(engine: &'a MpcEngine<N>, mut state: Rep3State) -> eyre::Result<Self> {
        let state1 = state.fork(0)?;
        Ok(Self {
            id: engine.id(),
            engine,
            state0: state,
            state1,
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
        arithmetic::sub_shared_by_public(z, p_half_plus_one, self.id)
    }
}

impl<F: PrimeField, N: Network + 'static> VmCircomWitnessExtension<F>
    for CircomRep3VmWitnessExtension<'_, F, N>
{
    type ArithmeticShare = ArithmeticShare<F>;

    type VmType = Rep3VmType<F>;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.add(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::add_public(a, b, self.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::add(a, b).into())
            }
        }
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.sub(a, b)?.into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::sub_shared_by_public(a, b, self.id).into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::sub_public_by_shared(a, b, self.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
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
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => Ok(self
                .engine
                .install_net(|net| arithmetic::mul(a, b, net, &mut self.state0))?
                .into()),
        }
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.div(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let b = self
                    .engine
                    .install_net(|net| arithmetic::inv(b, net, &mut self.state0))?;
                Ok(arithmetic::mul_public(b, a).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                Ok(arithmetic::mul_public(a, b.inverse().unwrap()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => Ok(self
                .engine
                .install_net(|net| {
                    let b = arithmetic::inv(b, net, &mut self.state0)?;
                    arithmetic::mul(a, b, net, &mut self.state0)
                })?
                .into()),
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
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    return Ok(Rep3VmType::Public(F::one()));
                }
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::pow_public(a, b, net, &mut self.state0))?
                    .into())
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
                self.engine.install_net(|net| {
                    let sqrt = arithmetic::sqrt(a, net, &mut self.state0)?;
                    // Correction to give the result closest to 0
                    // I.e., 2 * is_pos * sqrt - sqrt
                    let sqrt_val = self.val(sqrt);
                    let zero_val = self.plain.val(F::zero());
                    let is_pos = arithmetic::ge_public(sqrt_val, zero_val, net, &mut self.state0)?;
                    let mut mul = arithmetic::mul(sqrt, is_pos, net, &mut self.state0)?;
                    mul.double_in_place();
                    mul -= sqrt;
                    Ok(mul.into())
                })
            }
        }
    }

    fn neg(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.neg(a)?.into()),
            Rep3VmType::Arithmetic(a) => Ok(arithmetic::neg(a).into()),
        }
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.lt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::ge_public(b, a, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::lt_public(a, b, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::lt(a, b, net, &mut self.state0))?
                    .into())
            }
        }
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.le(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::gt_public(b, a, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::le_public(a, b, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::le(a, b, net, &mut self.state0))?
                    .into())
            }
        }
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.gt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::le_public(b, a, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::gt_public(a, b, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::gt(a, b, net, &mut self.state0))?
                    .into())
            }
        }
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.ge(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::lt_public(b, a, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::ge_public(a, b, net, &mut self.state0))?
                    .into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(self
                    .engine
                    .install_net(|net| arithmetic::ge(a, b, net, &mut self.state0))?
                    .into())
            }
        }
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.eq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => Ok(self
                .engine
                .install_net(|net| arithmetic::eq_public(a, b, net, &mut self.state0))?
                .into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => Ok(self
                .engine
                .install_net(|net| arithmetic::eq(a, b, net, &mut self.state0))?
                .into()),
        }
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.neq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => Ok(self
                .engine
                .install_net(|net| arithmetic::neq_public(a, b, net, &mut self.state0))?
                .into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => Ok(self
                .engine
                .install_net(|net| arithmetic::neq(a, b, net, &mut self.state0))?
                .into()),
        }
    }

    fn shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.shift_r(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(_)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Rep3VmType::Public(F::zero()));
                }
                todo!("Shared shift_right (public by shared) not implemented");
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => self.engine.install_net(|net| {
                let bits = conversion::a2b_selector(a, net, &mut self.state0)?;
                let result = conversion::b2a_selector(
                    &binary::shift_r_public(&bits, b),
                    net,
                    &mut self.state0,
                )?;
                Ok(result.into())
            }),
            (_, _) => todo!("Shared shift_right not implemented"),
        }
    }

    fn shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.shift_l(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                // some special casing
                if a == F::zero() {
                    Ok(Rep3VmType::Public(F::zero()))
                } else {
                    self.engine.install_net(|net| {
                        let b = conversion::a2b_selector(b, net, &mut self.state0)?;
                        let res = binary::shift_l_public_by_shared(a, &b, net, &mut self.state0)?;
                        Ok(res.into())
                    })
                }
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::pow_2_public(a, b).into())
            }
            (_, _) => todo!("Shared shift_right not implemented"),
        }
    }

    fn bool_not(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.bool_not(a)?.into()),
            Rep3VmType::Arithmetic(a) => {
                let neg_a = arithmetic::neg(a);
                let not_a = arithmetic::add_public(neg_a, F::one(), self.id);
                Ok(not_a.into())
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
                let add = arithmetic::add_public(a, b, self.id);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let mul = self
                    .engine
                    .install_net(|net| arithmetic::mul(a, b, net, &mut self.state0))?;
                let add = arithmetic::add(a, b);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
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
        }
    }

    fn bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_xor(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                self.engine.install_net(|net| {
                    let a = conversion::a2b_selector(a, net, &mut self.state0)?;
                    let binary = binary::xor_public(&a, &b.into_bigint().into(), self.id);
                    Ok(conversion::b2a_selector(&binary, net, &mut self.state0)?.into())
                })
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = self.engine.join_net(
                    |net| conversion::a2b_selector(a, net, &mut self.state0),
                    |net| conversion::a2b_selector(b, net, &mut self.state1),
                );
                let binary = binary::xor(&a?, &b?);
                let result = self
                    .engine
                    .install_net(|net| conversion::b2a_selector(&binary, net, &mut self.state0))?;
                Ok(result.into())
            }
        }
    }

    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_or(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                self.engine.install_net(|net| {
                    let a = conversion::a2b_selector(a, net, &mut self.state0)?;
                    let binary = binary::or_public(&a, &b.into_bigint().into(), self.id);
                    let result = conversion::b2a_selector(&binary, net, &mut self.state0)?;
                    Ok(result.into())
                })
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = self.engine.join_net(
                    |net| conversion::a2b_selector(a, net, &mut self.state0),
                    |net| conversion::a2b_selector(b, net, &mut self.state1),
                );
                let result = self.engine.install_net(|net| {
                    let binary = binary::or(&a?, &b?, net, &mut self.state0)?;
                    conversion::b2a_selector(&binary, net, &mut self.state0)
                })?;
                Ok(result.into())
            }
        }
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_and(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                self.engine.install_net(|net| {
                    let a = conversion::a2b_selector(a, net, &mut self.state0)?;
                    let binary = binary::and_with_public(&a, &b.into_bigint().into());
                    let result = conversion::b2a_selector(&binary, net, &mut self.state0)?;
                    Ok(result.into())
                })
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = self.engine.join_net(
                    |net| conversion::a2b_selector(a, net, &mut self.state0),
                    |net| conversion::a2b_selector(b, net, &mut self.state1),
                );
                let result = self.engine.install_net(|net| {
                    let binary = binary::and(&a?, &b?, net, &mut self.state0)?;
                    conversion::b2a_selector(&binary, net, &mut self.state0)
                })?;
                Ok(result.into())
            }
        }
    }

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> eyre::Result<bool> {
        if !allow_secret_inputs && self.is_shared(&a)? {
            bail!("allow_secret_inputs is false and input is shared");
        }
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.is_zero(a, allow_secret_inputs)?),
            Rep3VmType::Arithmetic(a) => Ok(self
                .engine
                .install_net(|net| arithmetic::is_zero(a, net, &mut self.state0))?),
        }
    }

    fn is_shared(&mut self, a: &Self::VmType) -> eyre::Result<bool> {
        match a {
            Rep3VmType::Public(_) => Ok(false),
            Rep3VmType::Arithmetic(_) => Ok(true),
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
            Rep3VmType::Arithmetic(a) => self.engine.install_net(|net| arithmetic::open(a, net)),
        }
    }

    fn to_share(&mut self, a: Self::VmType) -> eyre::Result<Self::ArithmeticShare> {
        match a {
            Rep3VmType::Public(a) => Ok(arithmetic::promote_to_trivial_share(self.id, a)),
            Rep3VmType::Arithmetic(a) => Ok(a),
        }
    }

    fn public_one(&self) -> Self::VmType {
        F::one().into()
    }

    fn public_zero(&self) -> Self::VmType {
        F::zero().into()
    }

    fn compare_vm_config(&mut self, config: &VMConfig) -> eyre::Result<()> {
        let ser = bincode::serialize(&config)?;
        let rcv: Vec<u8> = self.engine.install_net(|net| {
            network::send_next(net, ser)?;
            network::recv_prev(net)
        })?;
        let deser = bincode::deserialize(&rcv)?;
        if config != &deser {
            bail!("VM Config does not match: {:?} != {:?}", config, deser);
        }

        Ok(())
    }

    fn num2bits(&mut self, a: Self::VmType, bits: usize) -> eyre::Result<Vec<Self::VmType>> {
        match a {
            Rep3VmType::Public(a) => Ok(self
                .plain
                .num2bits(a, bits)?
                .into_iter()
                .map(Into::into)
                .collect()),
            Rep3VmType::Arithmetic(a) => self.engine.install_net(|net| {
                let a_bits = conversion::a2b_selector(a, net, &mut self.state0)?;
                let a_bits_split = (0..bits)
                    .map(|i| (&a_bits >> i) & BigUint::one())
                    .collect_vec();
                Ok(bit_inject_many(&a_bits_split, net, &mut self.state0)?
                    .into_iter()
                    .map(Into::into)
                    .collect())
            }),
        }
    }

    fn addbits(
        &mut self,
        a: Vec<Self::VmType>,
        b: Vec<Self::VmType>,
    ) -> eyre::Result<(Vec<Self::VmType>, Self::VmType)> {
        assert!(a.len() == b.len());
        let bitlen = a.len();
        assert!(bitlen < F::MODULUS_BIT_SIZE as usize - 1);
        let a = a.into_iter().map(|x| match x {
            Rep3VmType::Public(x) => promote_to_trivial_share(self.id, x),
            Rep3VmType::Arithmetic(x) => x,
        });
        let b = b.into_iter().map(|x| match x {
            Rep3VmType::Public(x) => promote_to_trivial_share(self.id, x),
            Rep3VmType::Arithmetic(x) => x,
        });

        let a_sum = a.fold(Rep3PrimeFieldShare::zero_share(), |acc, x| acc + acc + x);
        let b_sum = b.fold(Rep3PrimeFieldShare::zero_share(), |acc, x| acc + acc + x);

        let sum = a_sum + b_sum;

        let mut result = self.engine.install_net(|net| {
            let sum_bits = conversion::a2b_selector(sum, net, &mut self.state0)?;
            let individual_bits = (0..bitlen + 1)
                .map(|i| (&sum_bits >> i) & BigUint::one())
                .collect_vec();
            bit_inject_many(&individual_bits, net, &mut self.state0)
        })?;
        let carry = result.pop().unwrap();
        result.reverse();
        Ok((result.into_iter().map(Into::into).collect(), carry.into()))
    }
}

impl<F: PrimeField> std::fmt::Debug for Rep3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Arithmetic(share) => f.debug_tuple("Arithmetic").field(share).finish(),
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
        }
    }
}
