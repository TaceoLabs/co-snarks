use super::VmCircomWitnessExtension;
use crate::mpc_vm::VMConfig;
use ark_ff::{One, PrimeField};
use eyre::Result;
use eyre::eyre;
use num_bigint::BigUint;

/// Transforms a field element into an usize if possible.
macro_rules! to_usize {
    ($field: expr) => {{
        use eyre::eyre;
        use num_traits::cast::ToPrimitive;
        let a: BigUint = $field.into();
        usize::try_from(a.to_u64().ok_or(eyre!("Cannot convert var into usize"))?)?
    }};
}
pub(crate) use to_usize;

macro_rules! bool_comp_op {
    ($driver: expr, $lhs: expr, $op: tt, $rhs: expr) => {{
        let lhs = $driver.val($lhs);
        let rhs = $driver.val($rhs);
       if (lhs $op rhs){
        tracing::trace!("{}{}{} -> 1", $lhs,stringify!($op), $rhs);
        F::one()
       } else {
        tracing::trace!("{}{}{} -> 0", $lhs,stringify!($op), $rhs);
        F::zero()
       }
    }};
}

macro_rules! to_bigint {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a
    }};
}

pub struct CircomPlainVmWitnessExtension<F: PrimeField> {
    negative_one: F,
}

impl<F: PrimeField> Default for CircomPlainVmWitnessExtension<F> {
    fn default() -> Self {
        let modulus = to_bigint!(F::MODULUS);
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        Self {
            negative_one: F::from(modulus / two + one),
        }
    }
}

impl<F: PrimeField> CircomPlainVmWitnessExtension<F> {
    /// Normally F is split into positive and negative numbers in the range [0, p/2] and [p/2 + 1, p)
    /// However, for comparisons, we want the negative numbers to be "lower" than the positive ones.
    /// Therefore we shift the input by p/2 + 1 to the left, which results in a mapping of [negative, 0, positive] into F.
    /// We can then compare the numbers as if they were unsigned.
    /// While this could be done easier by just comparing the numbers as BigInt, we do it this way because this is easier to replicate in MPC later.
    #[inline(always)]
    pub(crate) fn val(&self, z: F) -> F {
        z - self.negative_one
    }

    #[inline(always)]
    pub(crate) fn is_negative(&self, x: F) -> bool {
        x >= self.negative_one
    }
}

impl<F: PrimeField> VmCircomWitnessExtension<F> for CircomPlainVmWitnessExtension<F> {
    type Public = F;
    type ArithmeticShare = F;

    type VmType = F;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let result = a + b;
        tracing::trace!("{a}+{b}={result}");
        Ok(result)
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let result = a - b;
        tracing::trace!("{a}-{b}={result}");
        Ok(a - b)
    }

    fn mul(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a * b)
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a / b)
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs / rhs))
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a.pow(b.into_bigint()))
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let a = to_bigint!(a);
        let b = to_bigint!(b);
        Ok(F::from(a % b))
    }

    fn sqrt(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        let sqrt = a.sqrt().ok_or(eyre!("cannot compute sqrt for {a}"))?;
        if self.is_negative(sqrt) {
            Ok(-sqrt)
        } else {
            Ok(sqrt)
        }
    }

    fn neg(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        Ok(-a)
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, <, b))
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, <=, b))
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, >, b))
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(bool_comp_op!(self, a, >=, b))
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        if a == b {
            tracing::trace!("{a}=={b} -> 1");
            Ok(F::one())
        } else {
            tracing::trace!("{a}=={b} -> 0");
            Ok(F::zero())
        }
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        if a != b {
            tracing::trace!("{a}!={b} -> 1");
            Ok(F::one())
        } else {
            tracing::trace!("{a}!={b} -> 0");
            Ok(F::zero())
        }
    }

    fn shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val >> shift))
    }

    fn shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val << shift))
    }

    fn bool_not(&mut self, a: Self::VmType) -> Result<Self::VmType> {
        assert!(a.is_one() || a.is_zero());
        Ok(F::one() - a)
    }

    fn bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_usize!(a);
        let rhs = to_usize!(b);
        debug_assert!(rhs == 0 || rhs == 1);
        debug_assert!(lhs == 0 || lhs == 1);
        if rhs == 1 && lhs == 1 {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_usize!(a);
        let rhs = to_usize!(b);
        debug_assert!(rhs == 0 || rhs == 1);
        debug_assert!(lhs == 0 || lhs == 1);
        if rhs == 1 || lhs == 1 {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> Result<Self::VmType> {
        assert!(cond.is_one() || cond.is_zero());
        if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
    }

    fn bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs ^ rhs))
    }
    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs | rhs))
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs & rhs))
    }

    fn is_zero(&mut self, a: Self::VmType, _: bool) -> Result<bool> {
        Ok(a.is_zero())
    }

    fn is_shared(&mut self, _: &Self::VmType) -> Result<bool> {
        Ok(false)
    }

    fn to_index(&mut self, a: Self::VmType) -> Result<usize> {
        Ok(to_usize!(a))
    }

    fn open(&mut self, a: Self::VmType) -> Result<F> {
        Ok(a)
    }

    fn to_share(&mut self, a: Self::VmType) -> Result<Self::ArithmeticShare> {
        Ok(a)
    }

    fn public_one(&self) -> Self::VmType {
        F::one()
    }

    fn public_zero(&self) -> Self::VmType {
        F::zero()
    }

    fn compare_vm_config(&mut self, _config: &VMConfig) -> Result<()> {
        Ok(())
    }

    fn num2bits(&mut self, a: Self::VmType, bits: usize) -> Result<Vec<Self::VmType>> {
        let a = to_bigint!(a);
        let mut res = Vec::with_capacity(bits);
        for i in 0..bits {
            res.push(F::from((&a >> i) & BigUint::one()));
        }
        Ok(res)
    }

    fn addbits(
        &mut self,
        a: Vec<Self::VmType>,
        b: Vec<Self::VmType>,
    ) -> Result<(Vec<Self::VmType>, Self::VmType)> {
        assert!(a.len() == b.len());
        let bitlen = a.len();
        assert!(bitlen < F::MODULUS_BIT_SIZE as usize - 1);
        let acc_a = a.into_iter().fold(F::ZERO, |acc, x| acc.double() + x);
        let acc_b = b.into_iter().fold(F::ZERO, |acc, x| acc.double() + x);

        let sum = acc_a + acc_b;
        let sum = to_bigint!(sum);
        let carry_mask = BigUint::one() << bitlen;
        let carry = F::from((&sum & carry_mask) >> bitlen);
        let mut res = Vec::with_capacity(bitlen);
        for i in 0..bitlen {
            res.push(F::from((&sum >> i) & BigUint::one()));
        }
        res.reverse();
        Ok((res, carry))
    }

    fn log(&mut self, a: Self::VmType, _: bool) -> eyre::Result<String> {
        Ok(a.to_string())
    }
}
