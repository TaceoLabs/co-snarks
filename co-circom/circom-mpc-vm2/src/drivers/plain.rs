//! Plain (non-MPC) driver: `VmType = F`. For local runs and testing only.
use crate::driver::VmDriver;
use crate::program::VMConfig;
use ark_ff::{One, PrimeField};
use eyre::{Result, eyre};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

/// `(p + 1) / 2`, expressed as a field element.
///
/// Field elements represent signed integers in the range `(-p/2, p/2]`: values `<=
/// p/2` are non-negative, values `> p/2` (equivalently `>= (p+1)/2`) are negative.
/// Adding this offset before comparing two field elements maps that signed range onto
/// an unsigned one, so ordinary field-element comparison implements signed comparison.
fn negative_one<F: PrimeField>() -> F {
    let modulus: BigUint = F::MODULUS.into();
    F::from(modulus / BigUint::from(2u64) + BigUint::one())
}

/// Converts a field element into a [`BigUint`].
fn to_biguint<F: PrimeField>(f: &F) -> BigUint {
    (*f).into()
}

/// Converts a field element into a `usize`, erroring if it does not fit.
fn to_usize<F: PrimeField>(f: &F) -> Result<usize> {
    let a = to_biguint(f);
    let a = a
        .to_u64()
        .ok_or_else(|| eyre!("Cannot convert var into usize"))?;
    Ok(usize::try_from(a)?)
}

/// Local plain-field driver. Do not use with sensitive data — nothing is protected.
#[derive(Debug, Clone)]
pub struct PlainDriver<F: PrimeField> {
    /// Cached `(p + 1) / 2` boundary used by [`Self::signed_shift`]/[`Self::is_negative`].
    negative_one: F,
}

impl<F: PrimeField> Default for PlainDriver<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> PlainDriver<F> {
    /// Creates a new [`PlainDriver`], precomputing the signed-comparison boundary once.
    pub fn new() -> Self {
        Self {
            negative_one: negative_one::<F>(),
        }
    }

    /// Shifts `z` so that signed comparisons can be done with plain field-element `Ord`.
    /// See [`negative_one`].
    #[inline(always)]
    fn signed_shift(&self, z: &F) -> F {
        *z - self.negative_one
    }

    /// Whether the raw field element `x` lies in the "negative" half `[(p+1)/2, p)`.
    #[inline(always)]
    fn is_negative(&self, x: &F) -> bool {
        *x >= self.negative_one
    }
}

impl<F: PrimeField> VmDriver<F> for PlainDriver<F> {
    type Public = F;
    type ArithmeticShare = F;
    type VmType = F;

    fn add(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let result = *a + *b;
        tracing::trace!("{a}+{b}={result}");
        Ok(result)
    }

    fn sub(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let result = *a - *b;
        tracing::trace!("{a}-{b}={result}");
        Ok(result)
    }

    fn mul(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        Ok(*a * *b)
    }

    fn div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        Ok(*a / *b)
    }

    fn int_div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_biguint(a);
        let rhs = to_biguint(b);
        Ok(F::from(lhs / rhs))
    }

    fn pow(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        Ok(a.pow(b.into_bigint()))
    }

    fn modulo(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_biguint(a);
        let rhs = to_biguint(b);
        Ok(F::from(lhs % rhs))
    }

    fn sqrt(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        let sqrt = a
            .sqrt()
            .ok_or_else(|| eyre!("cannot compute sqrt for {a}"))?;
        if self.is_negative(&sqrt) {
            Ok(-sqrt)
        } else {
            Ok(sqrt)
        }
    }

    fn neg(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        Ok(-*a)
    }

    fn lt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = self.signed_shift(a);
        let rhs = self.signed_shift(b);
        let result = if lhs < rhs { F::one() } else { F::zero() };
        tracing::trace!("{a}<{b} -> {result}");
        Ok(result)
    }

    fn le(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = self.signed_shift(a);
        let rhs = self.signed_shift(b);
        let result = if lhs <= rhs { F::one() } else { F::zero() };
        tracing::trace!("{a}<={b} -> {result}");
        Ok(result)
    }

    fn gt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = self.signed_shift(a);
        let rhs = self.signed_shift(b);
        let result = if lhs > rhs { F::one() } else { F::zero() };
        tracing::trace!("{a}>{b} -> {result}");
        Ok(result)
    }

    fn ge(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = self.signed_shift(a);
        let rhs = self.signed_shift(b);
        let result = if lhs >= rhs { F::one() } else { F::zero() };
        tracing::trace!("{a}>={b} -> {result}");
        Ok(result)
    }

    fn eq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        if a == b {
            tracing::trace!("{a}=={b} -> 1");
            Ok(F::one())
        } else {
            tracing::trace!("{a}=={b} -> 0");
            Ok(F::zero())
        }
    }

    fn neq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        if a != b {
            tracing::trace!("{a}!={b} -> 1");
            Ok(F::one())
        } else {
            tracing::trace!("{a}!={b} -> 0");
            Ok(F::zero())
        }
    }

    fn shift_r(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let val = to_biguint(a);
        let shift = to_usize(b)?;
        Ok(F::from(val >> shift))
    }

    fn shift_l(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let val = to_biguint(a);
        let shift = to_usize(b)?;
        Ok(F::from(val << shift))
    }

    fn bool_not(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        assert!(a.is_one() || a.is_zero());
        Ok(F::one() - *a)
    }

    fn bool_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_usize(a)?;
        let rhs = to_usize(b)?;
        debug_assert!(rhs == 0 || rhs == 1);
        debug_assert!(lhs == 0 || lhs == 1);
        if rhs == 1 && lhs == 1 {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn bool_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_usize(a)?;
        let rhs = to_usize(b)?;
        debug_assert!(rhs == 0 || rhs == 1);
        debug_assert!(lhs == 0 || lhs == 1);
        if rhs == 1 || lhs == 1 {
            Ok(F::one())
        } else {
            Ok(F::zero())
        }
    }

    fn bit_xor(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_biguint(a);
        let rhs = to_biguint(b);
        Ok(F::from(lhs ^ rhs))
    }

    fn bit_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_biguint(a);
        let rhs = to_biguint(b);
        Ok(F::from(lhs | rhs))
    }

    fn bit_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        let lhs = to_biguint(a);
        let rhs = to_biguint(b);
        Ok(F::from(lhs & rhs))
    }

    fn cmux(
        &mut self,
        cond: &Self::VmType,
        truthy: &Self::VmType,
        falsy: &Self::VmType,
    ) -> Result<Self::VmType> {
        assert!(cond.is_one() || cond.is_zero());
        if cond.is_one() {
            Ok(*truthy)
        } else {
            Ok(*falsy)
        }
    }

    fn is_zero(&mut self, a: &Self::VmType, _allow_secret_inputs: bool) -> Result<bool> {
        Ok(a.is_zero())
    }

    fn is_shared(&self, _a: &Self::VmType) -> Result<bool> {
        Ok(false)
    }

    fn to_index(&mut self, a: &Self::VmType) -> Result<usize> {
        to_usize(a)
    }

    fn open(&mut self, a: &Self::VmType) -> Result<Self::Public> {
        Ok(*a)
    }

    fn to_share(&mut self, a: &Self::VmType) -> Result<Self::ArithmeticShare> {
        Ok(*a)
    }

    fn public_one(&self) -> Self::VmType {
        F::one()
    }

    fn public_zero(&self) -> Self::VmType {
        F::zero()
    }

    fn public_from(&self, f: F) -> Self::VmType {
        f
    }

    fn compare_vm_config(&mut self, _config: &VMConfig) -> Result<()> {
        Ok(())
    }

    fn log(&mut self, a: &Self::VmType, _allow_leaky_logs: bool) -> Result<String> {
        Ok(a.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    fn d() -> PlainDriver<Fr> {
        PlainDriver::default()
    }

    #[test]
    fn plain_arithmetic() {
        let mut d = d();
        assert_eq!(
            d.add(&Fr::from(2u64), &Fr::from(3u64)).unwrap(),
            Fr::from(5u64)
        );
        assert_eq!(
            d.mul(&Fr::from(2u64), &Fr::from(3u64)).unwrap(),
            Fr::from(6u64)
        );
        assert_eq!(
            d.int_div(&Fr::from(7u64), &Fr::from(2u64)).unwrap(),
            Fr::from(3u64)
        );
        assert_eq!(
            d.modulo(&Fr::from(7u64), &Fr::from(2u64)).unwrap(),
            Fr::from(1u64)
        );
    }

    #[test]
    fn plain_comparisons_signed_semantics() {
        let mut d = d();
        // circom comparisons interpret values in (-p/2, p/2]; -1 < 2 must hold.
        let minus_one = -Fr::from(1u64);
        assert_eq!(d.lt(&minus_one, &Fr::from(2u64)).unwrap(), Fr::from(1u64));
        assert_eq!(
            d.gt(&Fr::from(3u64), &Fr::from(2u64)).unwrap(),
            Fr::from(1u64)
        );
        assert_eq!(
            d.le(&Fr::from(2u64), &Fr::from(2u64)).unwrap(),
            Fr::from(1u64)
        );
        assert_eq!(
            d.eq(&Fr::from(2u64), &Fr::from(2u64)).unwrap(),
            Fr::from(1u64)
        );
        assert_eq!(
            d.neq(&Fr::from(2u64), &Fr::from(3u64)).unwrap(),
            Fr::from(1u64)
        );
    }

    #[test]
    fn plain_meta_ops() {
        let mut d = d();
        assert!(!d.is_shared(&Fr::from(1u64)).unwrap());
        assert!(d.is_zero(&Fr::from(0u64), false).unwrap());
        assert_eq!(d.to_index(&Fr::from(17u64)).unwrap(), 17usize);
        assert_eq!(d.open(&Fr::from(9u64)).unwrap(), Fr::from(9u64));
        assert_eq!(d.public_one(), Fr::from(1u64));
    }

    #[test]
    fn bin_many_default_matches_scalar() {
        let mut d = d();
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let r = d.bin_many(crate::isa::BinOp::Mul, &a, &b).unwrap();
        assert_eq!(r, vec![Fr::from(4u64), Fr::from(10u64), Fr::from(18u64)]);
    }
}
