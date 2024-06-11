use super::{id::PartyID, network::Aby3Network, Aby3PrimeFieldShare, Aby3Protocol};
use crate::{
    protocols::{aby3::a2b::Aby3BigUintShare, plain::PlainDriver},
    traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol},
};
use ark_ff::{One, PrimeField};
use eyre::{bail, Result};
use num_bigint::BigUint;
use num_traits::Zero;

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
        Self::Public(F::zero())
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
            (_, _) => todo!("BitShared add not yet implemented"),
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
            (_, _) => todo!("BitShared sub not yet implemented"),
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
            (_, _) => todo!("BitShared mul not yet implemented"),
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
            _ => todo!("BitShared neg not yet implemented"),
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
            (_, _) => todo!("BitShared div not implemented"),
        };
        Ok(res)
    }

    fn pow<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_pow(a, b)?)
            }
            (Aby3VmType::Shared(mut a), Aby3VmType::Public(b)) => {
                if b.is_zero() {
                    return Ok(Aby3VmType::Public(F::one()));
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
                Aby3VmType::Shared(res)
            }
            (_, _) => todo!("Shared pow not implemented"),
        };
        Ok(res)
    }

    fn modulo<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_mod(a, b)?)
            }
            (_, _) => todo!("Shared mod not implemented"),
        };
        Ok(res)
    }

    fn int_div<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_int_div(a, b)?)
            }
            (_, _) => todo!("Shared int_div not implemented"),
        };
        Ok(res)
    }

    fn lt<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_lt(a, b)?))
            }
            //TODO: THIS IMPLEMENTATION IS NOT SECURE
            //THIS IS JUST A PLACEHOLDER FOR TESTING!!!!!!
            (Aby3VmType::Public(b), Aby3VmType::Shared(a)) => {
                let opened_a = party.open(&a)?;
                if b < opened_a {
                    Ok(Aby3VmType::Shared(party.promote_to_trivial_share(F::one())))
                } else {
                    Ok(Aby3VmType::Shared(
                        party.promote_to_trivial_share(F::zero()),
                    ))
                }
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                let opened_a = party.open(&a)?;
                if opened_a < b {
                    Ok(Aby3VmType::Shared(party.promote_to_trivial_share(F::one())))
                } else {
                    Ok(Aby3VmType::Shared(
                        party.promote_to_trivial_share(F::zero()),
                    ))
                }
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let opened_a = party.open(&a)?;
                let opened_b = party.open(&b)?;
                if opened_a < opened_b {
                    Ok(Aby3VmType::Shared(party.promote_to_trivial_share(F::one())))
                } else {
                    Ok(Aby3VmType::Shared(
                        party.promote_to_trivial_share(F::zero()),
                    ))
                }
            }
            (_, _) => todo!("Shared LT not implemented"),
        }
    }

    fn le<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_le(a, b)?))
            }
            (_, _) => todo!("Shared LE not implemented"),
        }
    }

    fn gt<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_gt(a, b)?))
            }
            (_, _) => todo!("Shared GT not implemented"),
        }
    }

    fn ge<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_ge(a, b)?))
            }
            //TODO: THIS IMPLEMENTATION IS NOT SECURE
            //THIS IS JUST A PLACEHOLDER FOR TESTING!!!!!!
            (Aby3VmType::Public(b), Aby3VmType::Shared(a)) => {
                let opened_a = party.open(&a)?;
                if b >= opened_a {
                    Ok(Aby3VmType::Shared(party.promote_to_trivial_share(F::one())))
                } else {
                    Ok(Aby3VmType::Shared(
                        party.promote_to_trivial_share(F::zero()),
                    ))
                }
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                let opened_a = party.open(&a)?;
                if opened_a >= b {
                    Ok(Aby3VmType::Shared(party.promote_to_trivial_share(F::one())))
                } else {
                    Ok(Aby3VmType::Shared(
                        party.promote_to_trivial_share(F::zero()),
                    ))
                }
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let opened_a = party.open(&a)?;
                let opened_b = party.open(&b)?;
                if opened_a >= opened_b {
                    Ok(Aby3VmType::Shared(party.promote_to_trivial_share(F::one())))
                } else {
                    Ok(Aby3VmType::Shared(
                        party.promote_to_trivial_share(F::zero()),
                    ))
                }
            }
            (_, _) => todo!("Shared GE not implemented"),
        }
    }

    fn eq<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_eq(a, b)?))
            }
            (Aby3VmType::Public(b), Aby3VmType::Shared(a))
            | (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => eq_public(party, a, b),
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let eq = party.sub(&a, &b);
                is_zero(party, eq)
            }
            (_, _) => todo!("Shared EQ not implemented"),
        }
    }

    fn neq<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_neq(a, b)?))
            }
            (Aby3VmType::Public(b), Aby3VmType::Shared(a))
            | (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                let eq = eq_public(party, a, b)?;
                match eq {
                    Aby3VmType::Public(eq) => Ok(Aby3VmType::Public(F::one() - eq)),
                    Aby3VmType::Shared(eq) => {
                        let neg_a = party.neg(&eq);
                        let result = party.add_with_public(&F::one(), &neg_a);
                        Ok(Aby3VmType::Shared(result))
                    }
                    _ => unreachable!(),
                }
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let eq = party.sub(&a, &b);
                let is_zero = is_zero(party, eq)?;
                match is_zero {
                    Aby3VmType::Public(eq) => Ok(Aby3VmType::Public(F::one() - eq)),
                    Aby3VmType::Shared(eq) => {
                        Ok(Aby3VmType::Shared(party.add_with_public(&-F::one(), &eq)))
                    }
                    _ => unreachable!(),
                }
            }
            (_, _) => todo!("Shared NEQ not implemented"),
        }
    }

    fn shift_r<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_shift_r(a, b)?)
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(_b)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Aby3VmType::Public(F::zero()));
                }
                todo!("Shared shift_right (public by shared) not implemented");
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                // some special casing
                if b == F::zero() {
                    return Ok(Aby3VmType::Shared(a));
                }
                // TODO: check bounds of b
                let shift = usize::try_from(b.into_bigint().as_mut()[0]).unwrap();
                let bits = party.a2b(&a)?;
                let shifted = &bits >> shift;

                let res = party.b2a(shifted)?;
                Aby3VmType::Shared(res)
            }
            (_, _) => todo!("Shared shift_right not implemented"),
        };
        Ok(res)
    }

    fn shift_l<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        // TODO: The circom handling of shifts can handle "negative" inputs, translating them to other type of shift...
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_shift_l(a, b)?)
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                // some special casing
                if a == F::zero() {
                    return Ok(Aby3VmType::Public(F::zero()));
                }
                // TODO: check for overflows
                // This case is equivalent to a*2^b
                // Strategy: limit size of b to k bits
                // bit-decompose b into bits b_i
                let bit_shares = party.a2b(&b)?;
                let individual_bit_shares = (0..8)
                    .map(|i| {
                        let bit = Aby3BigUintShare {
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
                Aby3VmType::Shared(res)
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                // TODO: handle overflows
                // This case is equivalent to a*2^b
                // TODO: assert b < 256?
                let shift = F::from(2u64).pow([b.into_bigint().as_mut()[0]]);
                Aby3VmType::Shared(party.mul_with_public(&shift, &a))
            }
            (_, _) => todo!("Shared shift_left not implemented"),
        };
        Ok(res)
    }

    fn bool_and<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bool_and(a, b)?)
            }
            (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => {
                Aby3VmType::Shared(party.mul_with_public(&b, &a))
            }
            (Aby3VmType::Public(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.mul_with_public(&a, &b))
            }
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                Aby3VmType::Shared(party.mul(&a, &b)?)
            }
            (_, _) => todo!("BitShared not implemented"),
        };
        Ok(res)
    }

    fn bool_or<N: Aby3Network>(_party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bool_or(a, b)?)
            }
            (_, _) => todo!("Shared bool_or not implemented"),
        };
        Ok(res)
    }

    fn bit_and<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bit_and(a, b)?)
            }
            (Aby3VmType::Public(b), Aby3VmType::Shared(a))
            | (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => bit_and_public(party, a, b)?,
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let a_bits = party.a2b(&a)?;
                let b_bits = party.a2b(&b)?;
                let bit_shares = party.and(a_bits, b_bits)?;
                let res = party.b2a(bit_shares)?;
                Aby3VmType::Shared(res)
            }
            (_, _) => todo!("Shared bit_and not implemented"),
        };
        Ok(res)
    }

    fn bit_xor<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bit_xor(a, b)?)
            }
            (Aby3VmType::Public(b), Aby3VmType::Shared(a))
            | (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => bit_xor_public(party, a, b)?,
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                let a_bits = party.a2b(&a)?;
                let b_bits = party.a2b(&b)?;
                let b = &a_bits ^ &b_bits;
                let res = party.b2a(b)?;
                Aby3VmType::Shared(res)
            }
            (_, _) => todo!("Shared bit_xor not implemented"),
        };
        Ok(res)
    }

    fn bit_or<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self, b: Self) -> Result<Self> {
        let res = match (a, b) {
            (Aby3VmType::Public(a), Aby3VmType::Public(b)) => {
                let mut plain = PlainDriver::default();
                Aby3VmType::Public(plain.vm_bit_or(a, b)?)
            }
            (Aby3VmType::Public(b), Aby3VmType::Shared(a))
            | (Aby3VmType::Shared(a), Aby3VmType::Public(b)) => bit_or_public(party, a, b)?,
            (Aby3VmType::Shared(a), Aby3VmType::Shared(b)) => {
                // TODO: semantics of overflows in bit OR?
                let mask = (BigUint::from(1u64) << F::MODULUS_BIT_SIZE) - BigUint::one();
                let a_bits = party.a2b(&a)?;
                let b_bits = party.a2b(&b)?;
                let a_bits = &a_bits ^ &mask;
                let b_bits = &b_bits ^ &mask;
                let bit_shares = party.and(a_bits, b_bits)?;
                let bit_shares = &bit_shares ^ &mask;
                let res = party.b2a(bit_shares)?;
                Aby3VmType::Shared(res)
            }
            (_, _) => todo!("Shared bit_or not implemented"),
        };
        Ok(res)
    }

    fn is_zero<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self) -> Result<bool> {
        match a {
            Aby3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                plain.is_zero(a, false)
            }
            Aby3VmType::Shared(a) => {
                let res = is_zero(party, a)?;
                match res {
                    Aby3VmType::Public(res) => Ok(res.is_one()),
                    Aby3VmType::Shared(res) => {
                        let x = party.open(&res)?;
                        Ok(x.is_one())
                    }
                    _ => todo!("BitShared is_zero not implemented"),
                }
            }
            _ => todo!("BitShared is_zero not implemented"),
        }
    }

    fn to_index<N: Aby3Network>(party: &mut Aby3Protocol<F, N>, a: Self) -> Result<F> {
        match a {
            Aby3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                plain.vm_open(a)
            }
            Aby3VmType::Shared(a) => {
                tracing::warn!("Opening shared value that is coerced to an index!");
                Ok(party.open(&a)?)
            }
            _ => todo!("Shared to_index not implemented"),
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

    fn vm_pow(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Self::VmType::pow(self, a, b)
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
        if !matches!(a, Aby3VmType::Public(_)) && !allow_secret_inputs {
            bail!("is_zero called on secret inputs when not allowed")
        }
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

    fn is_shared(&mut self, a: &Self::VmType) -> Result<bool> {
        match a {
            Aby3VmType::Shared(_) | Aby3VmType::BitShared => Ok(true),
            Aby3VmType::Public(_) => Ok(false),
        }
    }

    fn vm_bool_not(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        match a {
            Aby3VmType::Public(a) => {
                let mut plain = PlainDriver::default();
                Ok(Aby3VmType::Public(plain.vm_bool_not(a)?))
            }
            Aby3VmType::Shared(a) => {
                // todo: check if 1? or do a bitextract?
                // todo: make a proper sub_public since this happens often
                let neg_a = self.neg(&a);
                Ok(Aby3VmType::Shared(self.add_with_public(&F::one(), &neg_a)))
            }
            Aby3VmType::BitShared => todo!("BitShared not yet implemented"),
        }
    }

    fn vm_cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> Result<Self::VmType> {
        assert!(
            matches!(cond, Aby3VmType::Shared(_)),
            "ATM we do not call this on non-shared values"
        );
        let b_min_a = self.vm_sub(truthy, falsy.clone());
        let d = self.vm_mul(cond, b_min_a)?;
        Ok(self.vm_add(falsy, d))
    }

    fn public_one(&self) -> Self::VmType {
        Aby3VmType::Public(F::one())
    }
}

fn bit_and_public<N: Aby3Network, F: PrimeField>(
    party: &mut Aby3Protocol<F, N>,
    a: Aby3PrimeFieldShare<F>,
    b: F,
) -> Result<Aby3VmType<F>> {
    if b == F::zero() {
        return Ok(Aby3VmType::Public(F::zero()));
    }
    if b == F::one() {
        // TODO: Special case for b == 1 as lsb-extract
        let bit_shares = party.a2b(&a)?;
        let bit_share = Aby3BigUintShare {
            a: bit_shares.a & BigUint::one(),
            b: bit_shares.b & BigUint::one(),
        };
        let res = party.bit_inject(bit_share)?;
        return Ok(Aby3VmType::Shared(res));
    }
    // generic case
    let bit_shares = party.a2b(&a)?;
    let b_bits: BigUint = b.into_bigint().into();
    let bit_share = Aby3BigUintShare {
        a: bit_shares.a & &b_bits,
        b: bit_shares.b & b_bits,
    };
    let res = party.b2a(bit_share)?;
    Ok(Aby3VmType::Shared(res))
}

fn bit_xor_public<N: Aby3Network, F: PrimeField>(
    party: &mut Aby3Protocol<F, N>,
    a: Aby3PrimeFieldShare<F>,
    b: F,
) -> Result<Aby3VmType<F>> {
    if b == F::zero() {
        return Ok(Aby3VmType::Shared(a));
    }
    // generic case
    let b_bits: BigUint = b.into_bigint().into();
    let bit_shares = party.a2b(&a)?;
    let bit_share = bit_shares.xor_with_public(&b_bits, party.network.get_id());
    let res = party.b2a(bit_share)?;
    Ok(Aby3VmType::Shared(res))
}

fn bit_or_public<N: Aby3Network, F: PrimeField>(
    party: &mut Aby3Protocol<F, N>,
    a: Aby3PrimeFieldShare<F>,
    b: F,
) -> Result<Aby3VmType<F>> {
    if b == F::zero() {
        return Ok(Aby3VmType::Shared(a));
    }
    // generic case
    let mask = (BigUint::from(1u64) << F::MODULUS_BIT_SIZE) - BigUint::one();
    let b_bits: BigUint = b.into_bigint().into();
    let inv_mask = mask ^ &b_bits;
    let bit_shares = party.a2b(&a)?;
    // keep secret bits where b is zero
    let mut bit_share = Aby3BigUintShare {
        a: bit_shares.a & &inv_mask,
        b: bit_shares.b & &inv_mask,
    };
    match party.network.get_id() {
        PartyID::ID0 => {
            bit_share.a |= b_bits;
        }
        PartyID::ID1 => {
            bit_share.b |= b_bits;
        }
        PartyID::ID2 => {}
    }

    let res = party.b2a(bit_share)?;
    Ok(Aby3VmType::Shared(res))
}

fn eq_public<N: Aby3Network, F: PrimeField>(
    party: &mut Aby3Protocol<F, N>,
    a: Aby3PrimeFieldShare<F>,
    b: F,
) -> Result<Aby3VmType<F>> {
    let val = party.add_with_public(&-b, &a);
    is_zero(party, val)
}

fn is_zero<N: Aby3Network, F: PrimeField>(
    party: &mut Aby3Protocol<F, N>,
    a: Aby3PrimeFieldShare<F>,
) -> Result<Aby3VmType<F>> {
    let bits = party.a2b(&a)?;
    let is_zero = party.is_zero(bits)?;
    let is_zero_f = party.bit_inject(is_zero)?;
    Ok(Aby3VmType::Shared(is_zero_f))
}
