//! Rep3 (3-party replicated secret sharing) driver: `VmType = `[`Rep3VmType`].
//!
//! Port of the old `circom-mpc-vm/src/mpc/rep3.rs` onto the by-reference [`VmDriver`]
//! trait. Every scalar op matches on `(Public, Public)`/`(Public, Arithmetic)`/
//! `(Arithmetic, Public)`/`(Arithmetic, Arithmetic)` operand pairs, delegating the
//! all-public case to an embedded [`PlainDriver`] and every other case to the
//! corresponding `mpc_core::protocols::rep3` gadget.
use crate::driver::VmDriver;
use crate::drivers::plain::PlainDriver;
use crate::program::VMConfig;
use ark_ff::PrimeField;
use co_circom_types::Rep3InputType;
use eyre::{Result, bail};
use mpc_core::MpcState;
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State,
    arithmetic::{self, promote_to_trivial_share},
    binary,
    conversion::{self, A2BType},
    id::PartyID,
    network::Rep3NetworkExt,
    yao,
};
use mpc_net::Network;
use num_bigint::BigUint;

/// This type represents a public or arithmetically-shared value used in the Rep3
/// driver. Mirrors old `circom-mpc-vm::mpc::rep3::Rep3VmType`.
#[derive(Clone)]
pub enum Rep3VmType<F: PrimeField> {
    /// The public variant.
    Public(F),
    /// The arithmetic share variant.
    Arithmetic(Rep3PrimeFieldShare<F>),
}

impl<F: PrimeField> From<F> for Rep3VmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<Rep3PrimeFieldShare<F>> for Rep3VmType<F> {
    fn from(value: Rep3PrimeFieldShare<F>) -> Self {
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

impl<F: PrimeField> std::fmt::Debug for Rep3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Arithmetic(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

/// Rep3 protocol driver for the register VM.
///
/// Holds two independent `(network, state)` pairs — `0`/`1` — so that operations
/// needing two concurrent conversions (e.g. `bit_xor` on two shared operands) can run
/// them on separate connections via [`mpc_net::join`] instead of serializing them on a
/// single network.
pub struct Rep3Driver<'a, F: PrimeField, N: Network> {
    id: PartyID,
    net0: &'a N,
    net1: &'a N,
    state0: Rep3State,
    state1: Rep3State,
    plain: PlainDriver<F>,
    /// Cached `(p + 1) / 2` signed-comparison boundary (see
    /// [`PlainDriver::negative_one_boundary`]), reused to shift arithmetic shares the
    /// same way plain values are shifted.
    negative_one: F,
}

impl<'a, F: PrimeField, N: Network> Rep3Driver<'a, F, N> {
    /// Creates a new [`Rep3Driver`], performing the Rep3 setup handshake (correlated
    /// randomness) over `net0` and forking a second state for `net1`.
    pub fn new(net0: &'a N, net1: &'a N, a2b_type: A2BType) -> Result<Self> {
        let mut state0 = Rep3State::new(net0, a2b_type)?;
        let state1 = state0.fork(0)?;
        let plain = PlainDriver::default();
        let negative_one = plain.negative_one_boundary();
        Ok(Self {
            id: state0.id,
            net0,
            net1,
            state0,
            state1,
            plain,
            negative_one,
        })
    }

    /// Shifts a share by `(p + 1) / 2`, the arithmetic-share counterpart of
    /// [`PlainDriver::signed_shift`]: comparisons shift both operands this way so that
    /// ordinary (unsigned) comparison implements circom's signed semantics.
    #[inline(always)]
    fn shifted(&self, z: Rep3PrimeFieldShare<F>) -> Rep3PrimeFieldShare<F> {
        arithmetic::sub_shared_by_public(z, self.negative_one, self.id)
    }
}

impl<F: PrimeField, N: Network> VmDriver<F> for Rep3Driver<'_, F, N> {
    type Public = F;
    type ArithmeticShare = Rep3PrimeFieldShare<F>;
    type VmType = Rep3VmType<F>;

    fn add(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.add(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::add_public(*a, *b, self.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::add(*a, *b).into())
            }
        }
    }

    fn sub(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.sub(a, b)?.into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::sub_shared_by_public(*a, *b, self.id).into())
            }
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::sub_public_by_shared(*a, *b, self.id).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::sub(*a, *b).into())
            }
        }
    }

    fn mul(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.mul(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::mul_public(*a, *b).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::mul(*a, *b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.div(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let b = arithmetic::inv(*b, self.net0, &mut self.state0)?;
                Ok(arithmetic::mul_public(b, *a).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                Ok(arithmetic::mul_public(*a, b.inverse().unwrap()).into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let b = arithmetic::inv(*b, self.net0, &mut self.state0)?;
                Ok(arithmetic::mul(*a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn int_div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.int_div(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div_by_shared(*a, *b, self.net0, &mut self.state0)?;
                Ok(divided.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let divisor: BigUint = (*b).into();
                let divided = if divisor.count_ones() == 1 {
                    // is power-of-2
                    let divisor_bit = divisor.bits() as usize - 1;
                    yao::field_int_div_power_2(*a, self.net0, &mut self.state0, divisor_bit)?
                } else {
                    yao::field_int_div_by_public(*a, *b, self.net0, &mut self.state0)?
                };
                Ok(divided.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div(*a, *b, self.net0, &mut self.state0)?;
                Ok(divided.into())
            }
        }
    }

    fn pow(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.pow(a, b)?.into()),
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    return Ok(Rep3VmType::Public(F::one()));
                }
                Ok(arithmetic::pow_public(*a, *b, self.net0, &mut self.state0)?.into())
            }
            _ => bail!("pow with shared exponent not implemented"),
        }
    }

    fn modulo(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.modulo(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div_by_shared(*a, *b, self.net0, &mut self.state0)?;
                let mul = arithmetic::mul(divided, *b, self.net0, &mut self.state0)?;
                let result = arithmetic::sub_public_by_shared(*a, mul, self.id);
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let divisor: BigUint = (*b).into();
                let result = if divisor.count_ones() == 1 {
                    // is power-of-2
                    let divisor_bit = divisor.bits() as usize - 1;
                    yao::field_mod_power_2(*a, self.net0, &mut self.state0, divisor_bit)?
                } else {
                    let divided =
                        yao::field_int_div_by_public(*a, *b, self.net0, &mut self.state0)?;
                    let mul = arithmetic::mul_public(divided, *b);
                    arithmetic::sub(*a, mul)
                };
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let divided = yao::field_int_div(*a, *b, self.net0, &mut self.state0)?;
                let mul = arithmetic::mul(divided, *b, self.net0, &mut self.state0)?;
                let result = arithmetic::sub(*a, mul);
                Ok(result.into())
            }
        }
    }

    fn neg(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.neg(a)?.into()),
            Rep3VmType::Arithmetic(a) => Ok(arithmetic::neg(*a).into()),
        }
    }

    fn lt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.lt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.signed_shift(a);
                let b = self.shifted(*b);
                Ok(arithmetic::ge_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.shifted(*a);
                let b = self.plain.signed_shift(b);
                Ok(arithmetic::lt_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.shifted(*a);
                let b = self.shifted(*b);
                Ok(arithmetic::lt(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn le(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.le(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.signed_shift(a);
                let b = self.shifted(*b);
                Ok(arithmetic::gt_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.shifted(*a);
                let b = self.plain.signed_shift(b);
                Ok(arithmetic::le_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.shifted(*a);
                let b = self.shifted(*b);
                Ok(arithmetic::le(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn gt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.gt(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.signed_shift(a);
                let b = self.shifted(*b);
                Ok(arithmetic::le_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.shifted(*a);
                let b = self.plain.signed_shift(b);
                Ok(arithmetic::gt_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.shifted(*a);
                let b = self.shifted(*b);
                Ok(arithmetic::gt(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn ge(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.ge(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.plain.signed_shift(a);
                let b = self.shifted(*b);
                Ok(arithmetic::lt_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = self.shifted(*a);
                let b = self.plain.signed_shift(b);
                Ok(arithmetic::ge_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let a = self.shifted(*a);
                let b = self.shifted(*b);
                Ok(arithmetic::ge(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn eq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.eq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::eq_public(*a, *b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::eq(*a, *b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn neq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.neq(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::neq_public(*a, *b, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::neq(*a, *b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn shift_r(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.shift_r(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(_)) => {
                // some special casing
                if a.is_zero() {
                    return Ok(Rep3VmType::Public(F::zero()));
                }
                bail!("Shared shift_right (public by shared) not implemented");
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let bits = conversion::a2b_selector(*a, self.net0, &mut self.state0)?;
                let result = conversion::b2a_selector(
                    &binary::shift_r_public(&bits, *b),
                    self.net0,
                    &mut self.state0,
                )?;
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(_), Rep3VmType::Arithmetic(_)) => {
                bail!("Shared shift_right not implemented")
            }
        }
    }

    fn shift_l(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.shift_l(a, b)?.into()),
            (Rep3VmType::Public(a), Rep3VmType::Arithmetic(b)) => {
                // some special casing
                if a.is_zero() {
                    Ok(Rep3VmType::Public(F::zero()))
                } else {
                    let b = conversion::a2b_selector(*b, self.net0, &mut self.state0)?;
                    let res =
                        binary::shift_l_public_by_shared(*a, &b, self.net0, &mut self.state0)?;
                    Ok(res.into())
                }
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                Ok(arithmetic::pow_2_public(*a, *b).into())
            }
            (Rep3VmType::Arithmetic(_), Rep3VmType::Arithmetic(_)) => {
                bail!("Shared shift_left not implemented")
            }
        }
    }

    fn bool_not(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.bool_not(a)?.into()),
            Rep3VmType::Arithmetic(a) => {
                let neg_a = arithmetic::neg(*a);
                let not_a = arithmetic::add_public(neg_a, F::one(), self.id);
                Ok(not_a.into())
            }
        }
    }

    fn bool_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bool_and(a, b)?.into()),
            _ => self.mul(a, b),
        }
    }

    fn bool_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bool_or(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let mul = arithmetic::mul_public(*a, *b);
                let add = arithmetic::add_public(*a, *b, self.id);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let mul = arithmetic::mul(*a, *b, self.net0, &mut self.state0)?;
                let add = arithmetic::add(*a, *b);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
        }
    }

    fn bit_xor(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_xor(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = conversion::a2b_selector(*a, self.net0, &mut self.state0)?;
                let binary = binary::xor_public(&a, &b.into_bigint().into(), self.id);
                Ok(conversion::b2a_selector(&binary, self.net0, &mut self.state0)?.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = mpc_net::join(
                    || conversion::a2b_selector(*a, self.net0, &mut self.state0),
                    || conversion::a2b_selector(*b, self.net1, &mut self.state1),
                );
                let binary = binary::xor(&a?, &b?);
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(result.into())
            }
        }
    }

    fn bit_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_or(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = conversion::a2b_selector(*a, self.net0, &mut self.state0)?;
                let binary = binary::or_public(&a, &b.into_bigint().into(), self.id);
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = mpc_net::join(
                    || conversion::a2b_selector(*a, self.net0, &mut self.state0),
                    || conversion::a2b_selector(*b, self.net1, &mut self.state1),
                );
                let binary = binary::or(&a?, &b?, self.net0, &mut self.state0)?;
                Ok(conversion::b2a_selector(&binary, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn bit_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => Ok(self.plain.bit_and(a, b)?.into()),
            (Rep3VmType::Public(b), Rep3VmType::Arithmetic(a))
            | (Rep3VmType::Arithmetic(a), Rep3VmType::Public(b)) => {
                let a = conversion::a2b_selector(*a, self.net0, &mut self.state0)?;
                let binary = binary::and_with_public(&a, &b.into_bigint().into());
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(result.into())
            }
            (Rep3VmType::Arithmetic(a), Rep3VmType::Arithmetic(b)) => {
                let (a, b) = mpc_net::join(
                    || conversion::a2b_selector(*a, self.net0, &mut self.state0),
                    || conversion::a2b_selector(*b, self.net1, &mut self.state1),
                );
                let binary = binary::and(&a?, &b?, self.net0, &mut self.state0)?;
                Ok(conversion::b2a_selector(&binary, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn cmux(
        &mut self,
        cond: &Self::VmType,
        truthy: &Self::VmType,
        falsy: &Self::VmType,
    ) -> Result<Self::VmType> {
        match cond {
            Rep3VmType::Public(cond) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() {
                    Ok(truthy.clone())
                } else {
                    Ok(falsy.clone())
                }
            }
            Rep3VmType::Arithmetic(cond) => {
                let cond = Rep3VmType::Arithmetic(*cond);
                let b_min_a = self.sub(truthy, falsy)?;
                let d = self.mul(&cond, &b_min_a)?;
                self.add(falsy, &d)
            }
        }
    }

    fn is_zero(&mut self, a: &Self::VmType, allow_secret_inputs: bool) -> Result<bool> {
        if !allow_secret_inputs && self.is_shared(a)? {
            bail!("allow_secret_inputs is false and input is shared");
        }
        match a {
            Rep3VmType::Public(a) => self.plain.is_zero(a, allow_secret_inputs),
            Rep3VmType::Arithmetic(a) => arithmetic::is_zero(*a, self.net0, &mut self.state0),
        }
    }

    fn is_shared(&self, a: &Self::VmType) -> Result<bool> {
        Ok(matches!(a, Rep3VmType::Arithmetic(_)))
    }

    fn to_index(&mut self, a: &Self::VmType) -> Result<usize> {
        match a {
            Rep3VmType::Public(a) => self.plain.to_index(a),
            Rep3VmType::Arithmetic(_) => bail!("ToIndex called on shared value!"),
        }
    }

    fn open(&mut self, a: &Self::VmType) -> Result<Self::Public> {
        match a {
            Rep3VmType::Public(a) => Ok(*a),
            Rep3VmType::Arithmetic(a) => arithmetic::open(*a, self.net0),
        }
    }

    fn to_share(&mut self, a: &Self::VmType) -> Result<Self::ArithmeticShare> {
        match a {
            Rep3VmType::Public(a) => Ok(promote_to_trivial_share(self.id, *a)),
            Rep3VmType::Arithmetic(a) => Ok(*a),
        }
    }

    fn public_one(&self) -> Self::VmType {
        Rep3VmType::Public(F::one())
    }

    fn public_zero(&self) -> Self::VmType {
        Rep3VmType::Public(F::zero())
    }

    fn public_from(&self, f: F) -> Self::VmType {
        Rep3VmType::Public(f)
    }

    fn compare_vm_config(&mut self, config: &VMConfig) -> Result<()> {
        let ser = bincode::serialize(&config)?;
        self.net0.send_next(ser)?;
        let recv: Vec<u8> = self.net0.recv_prev()?;
        let deser = bincode::deserialize(&recv)?;
        if config != &deser {
            bail!("VM Config does not match: {:?} != {:?}", config, deser);
        }
        Ok(())
    }

    fn log(&mut self, a: &Self::VmType, allow_leaky_logs: bool) -> Result<String> {
        match a {
            Rep3VmType::Public(public) => self.plain.log(public, allow_leaky_logs),
            Rep3VmType::Arithmetic(share) => {
                if allow_leaky_logs {
                    let field = arithmetic::open(*share, self.net0)?;
                    Ok(field.to_string())
                } else {
                    Ok("secret".to_string())
                }
            }
        }
    }

    fn sqrt(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => Ok(self.plain.sqrt(a)?.into()),
            Rep3VmType::Arithmetic(a) => {
                let sqrt = arithmetic::sqrt(*a, self.net0, &mut self.state0)?;
                // Correction to give the result closest to 0
                // I.e., 2 * is_pos * sqrt - sqrt
                let sqrt_val = self.shifted(sqrt);
                let zero_val = self.plain.signed_shift(&F::zero());
                let is_pos =
                    arithmetic::ge_public(sqrt_val, zero_val, self.net0, &mut self.state0)?;
                let mut mul = arithmetic::mul(sqrt, is_pos, self.net0, &mut self.state0)?;
                mul.double_in_place();
                mul -= sqrt;
                Ok(mul.into())
            }
        }
    }
}
