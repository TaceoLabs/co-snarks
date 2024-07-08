//! # Rep3 Witness Extension
//!
//! This module contains the type used by the MPC-VM during witness extension and handles all required MPC implementations.

use super::{network::Rep3Network, Rep3PrimeFieldShare, Rep3Protocol};
use crate::{
    protocols::{plain::PlainDriver, rep3::a2b::Rep3BigUintShare},
    to_usize,
    traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol},
};
use ark_ff::{One, PrimeField};
use eyre::{bail, eyre, Result};
use num_bigint::BigUint;
use num_traits::Zero;

use num_traits::cast::ToPrimitive;

/// This type represents the basic type of the MPC-VM. Thus, it can represent either public or shared values.
#[derive(Clone)]
pub enum Rep3VmType<F: PrimeField> {
    /// Represents a publicly known value
    Public(F),
    /// Represents a secret-shared value
    Shared(Rep3PrimeFieldShare<F>),
    /// Represents a secret-shared binary value. This type is currently not utilized
    BitShared,
}

impl<F: PrimeField> From<Rep3VmType<F>> for Rep3PrimeFieldShare<F> {
    fn from(vm_type: Rep3VmType<F>) -> Self {
        match vm_type {
            Rep3VmType::Shared(share) => share,
            _ => panic!("Cannot convert to share"),
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
            Self::Public(arg0) => f.debug_tuple("Public").field(arg0).finish(),
            Self::Shared(arg0) => f.debug_tuple("Shared").field(arg0).finish(),
            Self::BitShared => write!(f, "BitShared"),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for Rep3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rep3VmType::Public(field) => f.write_str(&format!("PUBLIC ({field})")),
            Rep3VmType::Shared(share) => {
                f.write_str(&format!("SHARED (a: {}, b: {})", share.a, share.b))
            }
            Rep3VmType::BitShared => f.write_str("BIT_SHARED (TODO)"),
        }
    }
}

fn val<F: PrimeField, N: Rep3Network>(
    z: Rep3PrimeFieldShare<F>,
    party: &mut Rep3Protocol<F, N>,
) -> Rep3PrimeFieldShare<F> {
    let modulus: BigUint = F::MODULUS.into();
    let one = BigUint::one();
    let two = BigUint::from(2u64);
    let p_half_plus_one = F::from(modulus / two + one);
    party.add_with_public(&-p_half_plus_one, &z)
}

impl<F: PrimeField> Rep3VmType<F> {
    fn add<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_add(a, b))
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                Rep3VmType::Shared(party.add_with_public(&a, &b))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                Rep3VmType::Shared(party.add_with_public(&b, &a))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => Rep3VmType::Shared(party.add(&a, &b)),
            (_, _) => todo!("BitShared add not yet implemented"),
        }
    }

    fn sub<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Self {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_sub(a, b))
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                Rep3VmType::Shared(party.add_with_public(&a, &-b))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                Rep3VmType::Shared(party.add_with_public(&-b, &a))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => Rep3VmType::Shared(party.sub(&a, &b)),
            (_, _) => todo!("BitShared sub not yet implemented"),
        }
    }

    fn mul<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_mul(a, b)?)
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                Rep3VmType::Shared(party.mul_with_public(&a, &b))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                Rep3VmType::Shared(party.mul_with_public(&b, &a))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                Rep3VmType::Shared(party.mul(&a, &b)?)
            }
            (_, _) => todo!("BitShared mul not yet implemented"),
        };
        Ok(res)
    }

    fn neg<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self) -> Self {
        match a {
            Rep3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_neg(a))
            }
            Rep3VmType::Shared(a) => Rep3VmType::Shared(party.neg(&a)),
            _ => todo!("BitShared neg not yet implemented"),
        }
    }

    // Implemented as a * b^-1
    fn div<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_div(a, b)?)
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                let b_inv = party.inv(&b)?;
                Rep3VmType::Shared(party.mul_with_public(&a, &b_inv))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    bail!("Cannot invert zero");
                }
                let b_inv = b.inverse().unwrap();
                Rep3VmType::Shared(party.mul_with_public(&b_inv, &a))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                let b_inv = party.inv(&b)?;
                Rep3VmType::Shared(party.mul(&a, &b_inv)?)
            }
            (_, _) => todo!("BitShared div not implemented"),
        };
        Ok(res)
    }

    fn pow<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_pow(a, b)?)
            }
            (Rep3VmType::Shared(mut a), Rep3VmType::Public(b)) => {
                if b.is_zero() {
                    return Ok(Rep3VmType::Public(F::one()));
                }
                // TODO: are negative exponents allowed in circom?
                let mut res = party.promote_to_trivial_share(F::one());
                let mut b: BigUint = b.into_bigint().into();
                while !b.is_zero() {
                    if b.bit(0) {
                        b -= 1u64;
                        res = party.mul(&res, &a)?;
                    }
                    a = party.mul(&a, &a)?;
                    b >>= 1;
                }
                res = party.mul(&res, &a)?;
                Rep3VmType::Shared(res)
            }
            (_, _) => todo!("Shared pow not implemented"),
        };
        Ok(res)
    }

    fn sqrt<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self) -> Result<Self> {
        match a {
            Rep3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                Ok(Rep3VmType::Public(plain.vm_sqrt(a)?))
            }
            Rep3VmType::Shared(a) => {
                let sqrt = party.sqrt(&a)?;
                // Correction to give the result closest to 0
                // I.e., 2 * is_pos * sqrt - sqrt
                let is_pos = if let Rep3VmType::Shared(x) = Self::ge(
                    party,
                    Rep3VmType::Shared(sqrt.to_owned()),
                    Rep3VmType::Public(F::zero()),
                )? {
                    x
                } else {
                    unreachable!()
                };
                let mut mul = party.mul(&sqrt, &is_pos)?;
                mul.double();
                mul -= &sqrt;

                Ok(Rep3VmType::Shared(mul))
            }
            _ => todo!("BitShared sqrt not yet implemented"),
        }
    }

    fn modulo<N: Rep3Network>(_party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_mod(a, b)?)
            }
            (_, _) => todo!("Shared mod not implemented"),
        };
        Ok(res)
    }

    fn int_div<N: Rep3Network>(_party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_int_div(a, b)?)
            }
            (_, _) => todo!("Shared int_div not implemented"),
        };
        Ok(res)
    }

    fn lt<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        // a < b is equivalent to !(a >= b)
        let ge = Rep3VmType::ge(party, a, b)?;
        party.vm_bool_not(ge)
    }

    fn le<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        // a <= b is equivalent to b >= a
        Rep3VmType::ge(party, b, a)
    }

    fn gt<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        // a > b is equivalent to !(a <= b)
        let le = Rep3VmType::le(party, a, b)?;
        party.vm_bool_not(le)
    }

    fn ge<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let mut plain = PlainDriver::default();
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                Ok(Rep3VmType::Public(plain.vm_ge(a, b)?))
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                let a = plain.val(a);
                let b = val(b, party);
                let bit = party.unsigned_ge_const_lhs(a, b)?;
                Ok(Rep3VmType::Shared(party.bit_inject(bit)?))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                let a = val(a, party);
                let b = plain.val(b);
                let bit = party.unsigned_ge_const_rhs(a, b)?;
                Ok(Rep3VmType::Shared(party.bit_inject(bit)?))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                let a = val(a, party);
                let b = val(b, party);
                let bit = party.unsigned_ge(a, b)?;
                Ok(Rep3VmType::Shared(party.bit_inject(bit)?))
            }
            (_, _) => todo!("BitShared GE not implemented"),
        }
    }

    fn eq<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Rep3VmType::Public(plain.vm_eq(a, b)?))
            }
            (Rep3VmType::Public(b), Rep3VmType::Shared(a))
            | (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => eq_public(party, a, b),
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                let eq = party.sub(&a, &b);
                is_zero(party, eq)
            }
            (_, _) => todo!("Shared EQ not implemented"),
        }
    }

    fn neq<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Rep3VmType::Public(plain.vm_neq(a, b)?))
            }
            (Rep3VmType::Public(b), Rep3VmType::Shared(a))
            | (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                let eq = eq_public(party, a, b)?;
                match eq {
                    Rep3VmType::Public(eq) => Ok(Rep3VmType::Public(F::one() - eq)),
                    Rep3VmType::Shared(eq) => {
                        let neg_a = party.neg(&eq);
                        let result = party.add_with_public(&F::one(), &neg_a);
                        Ok(Rep3VmType::Shared(result))
                    }
                    _ => unreachable!(),
                }
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                let eq = party.sub(&a, &b);
                let is_zero = is_zero(party, eq)?;
                match is_zero {
                    Rep3VmType::Public(eq) => Ok(Rep3VmType::Public(F::one() - eq)),
                    Rep3VmType::Shared(eq) => {
                        Ok(Rep3VmType::Shared(party.add_with_public(&-F::one(), &eq)))
                    }
                    _ => unreachable!(),
                }
            }
            (_, _) => todo!("Shared NEQ not implemented"),
        }
    }

    fn shift_r<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_shift_r(a, b)?)
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(_b)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Rep3VmType::Public(F::zero()));
                }
                todo!("Shared shift_right (public by shared) not implemented");
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                // some special casing
                if b == F::zero() {
                    return Ok(Rep3VmType::Shared(a));
                }
                // TODO: check bounds of b
                let shift = usize::try_from(b.into_bigint().as_mut()[0]).unwrap();
                let bits = party.a2b(&a)?;
                let shifted = &bits >> shift;

                let res = party.b2a(shifted)?;
                Rep3VmType::Shared(res)
            }
            (_, _) => todo!("Shared shift_right not implemented"),
        };
        Ok(res)
    }

    fn shift_l<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        // TODO: The circom handling of shifts can handle "negative" inputs, translating them to other type of shift...
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_shift_l(a, b)?)
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Rep3VmType::Public(F::zero()));
                }
                // TODO: check for overflows
                // This case is equivalent to a*2^b
                // Strategy: limit size of b to k bits
                // bit-decompose b into bits b_i
                let bit_shares = party.a2b(&b)?;
                let individual_bit_shares = (0..8)
                    .map(|i| {
                        let bit = Rep3BigUintShare {
                            a: (bit_shares.a.clone() >> i) & BigUint::one(),
                            b: (bit_shares.b.clone() >> i) & BigUint::one(),
                        };
                        party.b2a(bit)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // v_i = 2^2^i * <b_i> + 1 - <b_i>
                let mut vs: Vec<_> = individual_bit_shares
                    .into_iter()
                    .enumerate()
                    .map(|(i, b_i)| {
                        let two = F::from(2u64);
                        let two_to_two_to_i = two.pow([2u64.pow(i as u32)]);
                        let v = party.mul_with_public(&two_to_two_to_i, &b_i);
                        let v = party.add_with_public(&F::one(), &v);
                        party.sub(&v, &b_i)
                    })
                    .collect();

                // v = \prod v_i
                // TODO: This should be done in a multiplication tree
                let last = vs.pop().unwrap();
                let v = vs.into_iter().try_fold(last, |a, b| party.mul(&a, &b))?;
                let res = party.mul_with_public(&a, &v);
                Rep3VmType::Shared(res)
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                // TODO: handle overflows
                // This case is equivalent to a*2^b
                // TODO: assert b < 256?
                let shift = F::from(2u64).pow([b.into_bigint().as_mut()[0]]);
                Rep3VmType::Shared(party.mul_with_public(&shift, &a))
            }
            (_, _) => todo!("Shared shift_left not implemented"),
        };
        Ok(res)
    }

    fn bool_and<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_bool_and(a, b)?)
            }
            (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => {
                Rep3VmType::Shared(party.mul_with_public(&b, &a))
            }
            (Rep3VmType::Public(a), Rep3VmType::Shared(b)) => {
                Rep3VmType::Shared(party.mul_with_public(&a, &b))
            }
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                Rep3VmType::Shared(party.mul(&a, &b)?)
            }
            (_, _) => todo!("BitShared not implemented"),
        };
        Ok(res)
    }

    fn bool_or<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_bool_or(a, b)?)
            }
            // a + b - a * b
            (Rep3VmType::Shared(a), Rep3VmType::Public(b))
            | (Rep3VmType::Public(b), Rep3VmType::Shared(a)) => {
                let mul = party.mul_with_public(&b, &a);
                let add = party.add_with_public(&b, &a);
                let sub = party.sub(&add, &mul);
                Rep3VmType::Shared(sub)
            }
            // a + b - a * b
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                let mul = party.mul(&a, &b)?;
                let add = party.add(&a, &b);
                let sub = party.sub(&add, &mul);
                Rep3VmType::Shared(sub)
            }
            (_, _) => todo!("BitShared not implemented"),
        };
        Ok(res)
    }

    fn bit_and<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_bit_and(a, b)?)
            }
            (Rep3VmType::Public(b), Rep3VmType::Shared(a))
            | (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => bit_and_public(party, a, b)?,
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                let a_bits = party.a2b(&a)?;
                let b_bits = party.a2b(&b)?;
                let bit_shares = party.and(a_bits, b_bits, F::MODULUS_BIT_SIZE as usize)?;
                let res = party.b2a(bit_shares)?;
                Rep3VmType::Shared(res)
            }
            (_, _) => todo!("BitShared bit_and not implemented"),
        };
        Ok(res)
    }

    fn bit_xor<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_bit_xor(a, b)?)
            }
            (Rep3VmType::Public(b), Rep3VmType::Shared(a))
            | (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => bit_xor_public(party, a, b)?,
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                // TODO: semantics of overflows in bit XOR?
                let a_bits = party.a2b(&a)?;
                let b_bits = party.a2b(&b)?;
                let b = &a_bits ^ &b_bits;
                let res = party.b2a(b)?;
                Rep3VmType::Shared(res)
            }
            (_, _) => todo!("BitShared bit_xor not implemented"),
        };
        Ok(res)
    }

    fn bit_or<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Rep3VmType::Public(a), Rep3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Rep3VmType::Public(plain.vm_bit_or(a, b)?)
            }
            (Rep3VmType::Public(b), Rep3VmType::Shared(a))
            | (Rep3VmType::Shared(a), Rep3VmType::Public(b)) => bit_or_public(party, a, b)?,
            (Rep3VmType::Shared(a), Rep3VmType::Shared(b)) => {
                // TODO: semantics of overflows in bit OR?
                let a_bits = party.a2b(&a)?;
                let b_bits = party.a2b(&b)?;
                let mut xor = &a_bits ^ &b_bits;
                let and = party.and(a_bits, b_bits, F::MODULUS_BIT_SIZE as usize)?;
                xor ^= &and;
                let res = party.b2a(xor)?;
                Rep3VmType::Shared(res)
            }
            (_, _) => todo!("BitShared bit_or not implemented"),
        };
        Ok(res)
    }

    fn is_zero<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self) -> Result<bool> {
        match a {
            Rep3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                plain.is_zero(a, false)
            }
            Rep3VmType::Shared(a) => {
                let res = is_zero(party, a)?;
                match res {
                    Rep3VmType::Public(res) => Ok(res.is_one()),
                    Rep3VmType::Shared(res) => {
                        let x = party.open(&res)?;
                        Ok(x.is_one())
                    }
                    _ => todo!("BitShared is_zero not implemented"),
                }
            }
            _ => todo!("BitShared is_zero not implemented"),
        }
    }

    fn open<N: Rep3Network>(party: &mut Rep3Protocol<F, N>, a: Self) -> Result<F> {
        match a {
            Rep3VmType::Public(a) => Ok(a),
            Rep3VmType::Shared(a) => Ok(party.open(&a)?),
            _ => todo!("BitShared open not implemented"),
        }
    }

    fn to_index<N: Rep3Network>(_party: &mut Rep3Protocol<F, N>, a: Self) -> Result<usize> {
        if let Rep3VmType::Public(a) = a {
            Ok(to_usize!(a))
        } else {
            bail!("ToIndex called on shared value!")
        }
    }
}

impl<F: PrimeField> From<Rep3PrimeFieldShare<F>> for Rep3VmType<F> {
    fn from(value: Rep3PrimeFieldShare<F>) -> Self {
        Rep3VmType::Shared(value)
    }
}

impl<F: PrimeField> From<F> for Rep3VmType<F> {
    fn from(value: F) -> Self {
        Rep3VmType::Public(value)
    }
}

impl<F: PrimeField, N: Rep3Network> CircomWitnessExtensionProtocol<F> for Rep3Protocol<F, N> {
    type VmType = Rep3VmType<F>;

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

    fn vm_pow(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::pow(self, a, b)
    }

    fn vm_sqrt(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::sqrt(self, a)
    }

    fn vm_mod(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::modulo(self, a, b)
    }

    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::int_div(self, a, b)
    }

    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::lt(self, a, b)
    }

    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::le(self, a, b)
    }

    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::gt(self, a, b)
    }

    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::ge(self, a, b)
    }

    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::eq(self, a, b)
    }

    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
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

    fn vm_bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::bool_or(self, a, b)
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

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> Result<bool> {
        if !matches!(a, Rep3VmType::Public(_)) && !allow_secret_inputs {
            bail!("is_zero called on secret inputs when not allowed")
        }
        Self::VmType::is_zero(self, a)
    }

    fn vm_to_index(&mut self, a: Self::VmType) -> Result<usize> {
        Self::VmType::to_index(self, a)
    }

    fn vm_open(&mut self, a: Self::VmType) -> Result<F> {
        Self::VmType::open(self, a)
    }

    fn vm_to_share(&self, a: Self::VmType) -> Self::FieldShare {
        match a {
            Rep3VmType::Public(a) => self.promote_to_trivial_share(a),
            Rep3VmType::Shared(share) => share,
            Rep3VmType::BitShared => todo!("BitShared not yet implemented"),
        }
    }

    fn is_shared(&mut self, a: &Self::VmType) -> Result<bool> {
        match a {
            Rep3VmType::Shared(_) | Rep3VmType::BitShared => Ok(true),
            Rep3VmType::Public(_) => Ok(false),
        }
    }

    fn vm_bool_not(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        match a {
            Rep3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                Ok(Rep3VmType::Public(plain.vm_bool_not(a)?))
            }
            Rep3VmType::Shared(a) => {
                // todo: check if 1? or do a bitextract?
                // todo: make a proper sub_public since this happens often
                let neg_a = self.neg(&a);
                Ok(Rep3VmType::Shared(self.add_with_public(&F::one(), &neg_a)))
            }
            Rep3VmType::BitShared => todo!("BitShared not yet implemented"),
        }
    }

    fn vm_cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> Result<Self::VmType> {
        assert!(
            matches!(cond, Rep3VmType::Shared(_)),
            "ATM we do not call this on non-shared values"
        );
        let b_min_a = self.vm_sub(truthy, falsy.clone());
        let d = self.vm_mul(cond, b_min_a)?;
        Ok(self.vm_add(falsy, d))
    }

    fn public_one(&self) -> Self::VmType {
        Rep3VmType::Public(F::one())
    }
}

fn bit_and_public<N: Rep3Network, F: PrimeField>(
    party: &mut Rep3Protocol<F, N>,
    a: Rep3PrimeFieldShare<F>,
    b: F,
) -> Result<Rep3VmType<F>> {
    if b == F::zero() {
        return Ok(Rep3VmType::Public(F::zero()));
    }
    if b == F::one() {
        // TODO: Special case for b == 1 as lsb-extract
        let bit_shares = party.a2b(&a)?;
        let bit_share = Rep3BigUintShare {
            a: bit_shares.a & BigUint::one(),
            b: bit_shares.b & BigUint::one(),
        };
        let res = party.bit_inject(bit_share)?;
        return Ok(Rep3VmType::Shared(res));
    }
    // generic case
    let bit_shares = party.a2b(&a)?;
    let b_bits: BigUint = b.into_bigint().into();
    let bit_share = Rep3BigUintShare {
        a: bit_shares.a & &b_bits,
        b: bit_shares.b & b_bits,
    };
    let res = party.b2a(bit_share)?;
    Ok(Rep3VmType::Shared(res))
}

fn bit_xor_public<N: Rep3Network, F: PrimeField>(
    party: &mut Rep3Protocol<F, N>,
    a: Rep3PrimeFieldShare<F>,
    b: F,
) -> Result<Rep3VmType<F>> {
    if b == F::zero() {
        return Ok(Rep3VmType::Shared(a));
    }
    // generic case
    let b_bits: BigUint = b.into_bigint().into();
    let bit_shares = party.a2b(&a)?;
    let bit_share = bit_shares.xor_with_public(&b_bits, party.network.get_id());
    let res = party.b2a(bit_share)?;
    Ok(Rep3VmType::Shared(res))
}

fn bit_or_public<N: Rep3Network, F: PrimeField>(
    party: &mut Rep3Protocol<F, N>,
    a: Rep3PrimeFieldShare<F>,
    b: F,
) -> Result<Rep3VmType<F>> {
    if b == F::zero() {
        return Ok(Rep3VmType::Shared(a));
    }
    // generic case
    let b_bits: BigUint = b.into_bigint().into();
    let mut bit_shares = party.a2b(&a)?;
    let xor = bit_shares.xor_with_public(&b_bits, party.network.get_id());
    bit_shares &= &b_bits;
    bit_shares ^= &xor;

    let res = party.b2a(bit_shares)?;
    Ok(Rep3VmType::Shared(res))
}

fn eq_public<N: Rep3Network, F: PrimeField>(
    party: &mut Rep3Protocol<F, N>,
    a: Rep3PrimeFieldShare<F>,
    b: F,
) -> Result<Rep3VmType<F>> {
    let val = party.add_with_public(&-b, &a);
    is_zero(party, val)
}

fn is_zero<N: Rep3Network, F: PrimeField>(
    party: &mut Rep3Protocol<F, N>,
    a: Rep3PrimeFieldShare<F>,
) -> Result<Rep3VmType<F>> {
    let bits = party.a2b(&a)?;
    let is_zero = party.is_zero(bits)?;
    let is_zero_f = party.bit_inject(is_zero)?;
    Ok(Rep3VmType::Shared(is_zero_f))
}
