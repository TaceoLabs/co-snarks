use super::{
    VmCircomWitnessExtension,
    plain::{CircomPlainVmWitnessExtension, to_usize},
};
use crate::mpc_vm::VMConfig;
use ark_ff::{One, PrimeField};
use co_circom_types::Rep3InputType;
use eyre::bail;
use itertools::Itertools;
use mpc_core::{
    MpcState,
    gadgets::poseidon2::Poseidon2,
    protocols::rep3::{
        Rep3PrimeFieldShare, Rep3State,
        arithmetic::{self, promote_to_trivial_share},
        binary,
        conversion::{self, A2BType, bit_inject_many},
        id::PartyID,
        network::Rep3NetworkExt,
        yao,
    },
};
use mpc_net::Network;
use num_bigint::BigUint;

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;

/// This type represents a public, arithmetic share, or binary share type used in the co-cricom MPC-VM
#[derive(Clone)]
pub enum Rep3VmType<F: PrimeField> {
    /// The public variant
    Public(F),
    /// The arithmetic share variant
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

impl<F: PrimeField> From<Rep3InputType<F>> for Rep3VmType<F> {
    fn from(value: Rep3InputType<F>) -> Self {
        match value {
            Rep3InputType::Public(public) => Self::Public(public),
            Rep3InputType::Shared(shared) => Self::Arithmetic(shared),
        }
    }
}

impl<F: PrimeField> Default for Rep3VmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

pub struct CircomRep3VmWitnessExtension<'a, F: PrimeField, N: Network> {
    id: PartyID,
    net0: &'a N,
    net1: &'a N,
    state0: Rep3State,
    state1: Rep3State,
    plain: CircomPlainVmWitnessExtension<F>,
}

impl<'a, F: PrimeField, N: Network> CircomRep3VmWitnessExtension<'a, F, N> {
    pub fn new(net0: &'a N, net1: &'a N, a2b_type: A2BType) -> eyre::Result<Self> {
        let mut state0 = Rep3State::new(net0, a2b_type)?;
        let state1 = state0.fork(0)?;
        Ok(Self {
            id: state0.id,
            net0,
            net1,
            state0,
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

impl<F: PrimeField, N: Network> VmCircomWitnessExtension<F>
    for CircomRep3VmWitnessExtension<'_, F, N>
{
    type Public = F;

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
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::mul(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.div(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let b = arithmetic::inv(b, self.net0, &mut self.state0)?;
                Ok(arithmetic::mul_public(b, a).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                Ok(arithmetic::mul_public(a, b.inverse().unwrap()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let b = arithmetic::inv(b, self.net0, &mut self.state0)?;
                Ok(arithmetic::mul(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.int_div(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div_by_shared(a, b, self.net0, &mut self.state0)?;
                Ok(divided.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let divisor: BigUint = b.into();
                let divided = if divisor.count_ones() == 1 {
                    // is power-of-2
                    let divisor_bit = divisor.bits() as usize - 1;
                    yao::field_int_div_power_2(a, self.net0, &mut self.state0, divisor_bit)?
                } else {
                    yao::field_int_div_by_public(a, b, self.net0, &mut self.state0)?
                };
                Ok(divided.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div(a, b, self.net0, &mut self.state0)?;
                Ok(divided.into())
            }
        }
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.pow(a, b)?.into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    return Ok(Rep3VmType::Public(F::one()));
                }
                Ok(arithmetic::pow_public(a, b, self.net0, &mut self.state0)?.into())
            }
            _ => todo!("pow with shared exponent not implemented"),
        }
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.modulo(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div_by_shared(a, b, self.net0, &mut self.state0)?;
                let mul = arithmetic::mul(divided, b, self.net0, &mut self.state0)?;
                let result = arithmetic::sub_public_by_shared(a, mul, self.id);
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let divisor: BigUint = b.into();
                let result = if divisor.count_ones() == 1 {
                    // is power-of-2
                    let divisor_bit = divisor.bits() as usize - 1;
                    yao::field_mod_power_2(a, self.net0, &mut self.state0, divisor_bit)?
                } else {
                    let divided = yao::field_int_div_by_public(a, b, self.net0, &mut self.state0)?;
                    let mul = arithmetic::mul_public(divided, b);
                    arithmetic::sub(a, mul)
                };
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div(a, b, self.net0, &mut self.state0)?;
                let mul = arithmetic::mul(divided, b, self.net0, &mut self.state0)?;
                let result = arithmetic::sub(a, mul);
                Ok(result.into())
            }
        }
    }

    fn sqrt(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.sqrt(a)?.into()),
            Rep3VmType::Arithmetic(a) => {
                let sqrt = arithmetic::sqrt(a, self.net0, &mut self.state0)?;
                // Correction to give the result closest to 0
                // I.e., 2 * is_pos * sqrt - sqrt
                let sqrt_val = self.val(sqrt);
                let zero_val = self.plain.val(F::zero());
                let is_pos =
                    arithmetic::ge_public(sqrt_val, zero_val, self.net0, &mut self.state0)?;
                let mut mul = arithmetic::mul(sqrt, is_pos, self.net0, &mut self.state0)?;
                mul.double_in_place();
                mul -= sqrt;
                Ok(mul.into())
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
                Ok(arithmetic::ge_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(arithmetic::lt_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(arithmetic::lt(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.le(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(arithmetic::gt_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(arithmetic::le_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(arithmetic::le(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.gt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(arithmetic::le_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(arithmetic::gt_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(arithmetic::gt(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.ge(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.val(a);
                let b = self.val(b);
                Ok(arithmetic::lt_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.val(a);
                let b = self.plain.val(b);
                Ok(arithmetic::ge_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.val(a);
                let b = self.val(b);
                Ok(arithmetic::ge(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.eq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::eq_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::eq(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.neq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::neq_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::neq(a, b, self.net0, &mut self.state0)?.into())
            }
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
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let bits = conversion::a2b_selector(a, self.net0, &mut self.state0)?;
                let result = conversion::b2a_selector(
                    &binary::shift_r_public(&bits, b),
                    self.net0,
                    &mut self.state0,
                )?;
                Ok(result.into())
            }
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
                    let b = conversion::a2b_selector(b, self.net0, &mut self.state0)?;
                    let res = binary::shift_l_public_by_shared(a, &b, self.net0, &mut self.state0)?;
                    Ok(res.into())
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
                let mul = arithmetic::mul(a, b, self.net0, &mut self.state0)?;
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
                if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
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
                let a = conversion::a2b_selector(a, self.net0, &mut self.state0)?;
                let binary = binary::xor_public(&a, &b.into_bigint().into(), self.id);
                Ok(conversion::b2a_selector(&binary, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = mpc_net::join(
                    || conversion::a2b_selector(a, self.net0, &mut self.state0),
                    || conversion::a2b_selector(b, self.net1, &mut self.state1),
                );
                let binary = binary::xor(&a?, &b?);
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(result.into())
            }
        }
    }

    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_or(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = conversion::a2b_selector(a, self.net0, &mut self.state0)?;
                let binary = binary::or_public(&a, &b.into_bigint().into(), self.id);
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = mpc_net::join(
                    || conversion::a2b_selector(a, self.net0, &mut self.state0),
                    || conversion::a2b_selector(b, self.net1, &mut self.state1),
                );
                let binary = binary::or(&a?, &b?, self.net0, &mut self.state0)?;
                Ok(conversion::b2a_selector(&binary, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_and(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = conversion::a2b_selector(a, self.net0, &mut self.state0)?;
                let binary = binary::and_with_public(&a, &b.into_bigint().into());
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = mpc_net::join(
                    || conversion::a2b_selector(a, self.net0, &mut self.state0),
                    || conversion::a2b_selector(b, self.net1, &mut self.state1),
                );
                let binary = binary::and(&a?, &b?, self.net0, &mut self.state0)?;
                Ok(conversion::b2a_selector(&binary, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> eyre::Result<bool> {
        if !allow_secret_inputs && self.is_shared(&a)? {
            bail!("allow_secret_inputs is false and input is shared");
        }
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.is_zero(a, allow_secret_inputs)?),
            Rep3VmType::Arithmetic(a) => Ok(arithmetic::is_zero(a, self.net0, &mut self.state0)?),
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
            Rep3VmType::Arithmetic(a) => arithmetic::open(a, self.net0),
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
        self.net0.send_next(ser)?;
        let recv: Vec<u8> = self.net0.recv_prev()?;
        let deser = bincode::deserialize(&recv)?;
        if config != &deser {
            eyre::bail!("VM Config does not match: {:?} != {:?}", config, deser);
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
            Rep3VmType::Arithmetic(a) => {
                let a_bits = conversion::a2b_selector(a, self.net0, &mut self.state0)?;
                let a_bits_split = (0..bits)
                    .map(|i| (&a_bits >> i) & BigUint::one())
                    .collect_vec();
                Ok(bit_inject_many(&a_bits_split, self.net0, &mut self.state0)?
                    .into_iter()
                    .map(Into::into)
                    .collect())
            }
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

        let sum_bits = conversion::a2b_selector(sum, self.net0, &mut self.state0)?;
        let individual_bits = (0..bitlen + 1)
            .map(|i| (&sum_bits >> i) & BigUint::one())
            .collect_vec();
        let mut result = bit_inject_many(&individual_bits, self.net0, &mut self.state0)?;
        let carry = result.pop().unwrap();
        result.reverse();
        Ok((result.into_iter().map(Into::into).collect(), carry.into()))
    }

    fn log(&mut self, a: Self::VmType, allow_leaky_logs: bool) -> eyre::Result<String> {
        match a {
            Rep3VmType::Public(public) => self.plain.log(public, allow_leaky_logs),
            Rep3VmType::Arithmetic(share) => {
                if allow_leaky_logs {
                    let field = arithmetic::open(share, self.net0)?;
                    Ok(field.to_string())
                } else {
                    Ok("secret".to_string())
                }
            }
        }
    }

    fn poseidon2_accelerator<const T: usize>(
        &mut self,
        inputs: Vec<Self::VmType>,
    ) -> eyre::Result<(Vec<Self::VmType>, Vec<Self::VmType>)> {
        if inputs
            .iter()
            .any(|x| matches!(x, Rep3VmType::Arithmetic(_)))
        {
            let inputs_len = inputs.len();
            let poseidon = Poseidon2::<_, T, 5>::default();
            let mut precomp = poseidon.precompute_rep3(inputs_len, self.net0, &mut self.state0)?;

            // We promote all inputs to arithmetic shares here
            let mut iter = inputs.into_iter();
            let mut state: [Rep3PrimeFieldShare<F>; T] = std::array::from_fn(|_| {
                match iter
                    .next()
                    .expect("poseidon2_accelerator: not enough inputs")
                {
                    Rep3VmType::Public(x) => promote_to_trivial_share(self.id, x),
                    Rep3VmType::Arithmetic(x) => x,
                }
            });

            let trace = poseidon.rep3_permutation_in_place_with_precomputation_intermediate(
                &mut state,
                &mut precomp,
                self.net0,
            )?;

            let outputs = state.into_iter().map(Rep3VmType::Arithmetic).collect_vec();
            let trace = trace.into_iter().map(Rep3VmType::Arithmetic).collect_vec();

            Ok((outputs, trace))
        } else {
            self.plain
                .poseidon2_accelerator::<T>(
                    inputs
                        .into_iter()
                        .map(|x| match x {
                            Rep3VmType::Public(x) => x,
                            _ => unreachable!(),
                        })
                        .collect(),
                )
                .map(|(outs, trace)| {
                    (
                        outs.into_iter().map(Rep3VmType::Public).collect(),
                        trace.into_iter().map(Rep3VmType::Public).collect(),
                    )
                })
        }
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
                f.write_str(&format!("Arithmetic (a: {a}, b: {b})"))
            }
        }
    }
}
