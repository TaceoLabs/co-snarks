//! Taint driver: deterministic shared-ness tracking without any MPC.
//!
//! [`TaintDriver`] wraps a [`PlainDriver`] and delegates every value computation to it,
//! while separately tracking whether each value is "shared" (secret) or "public". This
//! lets tests exercise the visibility rules of the VM (e.g. which operations are
//! forbidden on secret values) deterministically, without running an actual MPC
//! protocol.
use crate::driver::VmDriver;
use crate::drivers::plain::PlainDriver;
use crate::program::VMConfig;
use ark_ff::PrimeField;
use eyre::{Result, bail};

/// A value tagged with whether it is shared (secret) or public.
///
/// The `val` field always holds the real value (the taint driver models visibility
/// rules, not actual secrecy — nothing is protected).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Taint<F> {
    /// The underlying value.
    pub val: F,
    /// Whether this value is considered shared (secret).
    pub shared: bool,
}

/// Local driver that tracks shared-ness alongside a [`PlainDriver`] computation.
///
/// Delegates all value computations to the wrapped `PlainDriver`; the `shared` flag of
/// the result is the OR of the operands' flags for binary ops (unary ops keep the
/// flag; `cmux` ORs all three operands). Used to test shared-if VM semantics
/// deterministically without MPC.
#[derive(Debug, Clone, Default)]
pub struct TaintDriver<F: PrimeField> {
    inner: PlainDriver<F>,
}

impl<F: PrimeField> TaintDriver<F> {
    /// c = f(a, b), tagging the result shared if either operand is shared.
    fn bin(
        &mut self,
        a: &Taint<F>,
        b: &Taint<F>,
        f: impl FnOnce(&mut PlainDriver<F>, &F, &F) -> Result<F>,
    ) -> Result<Taint<F>> {
        Ok(Taint {
            val: f(&mut self.inner, &a.val, &b.val)?,
            shared: a.shared || b.shared,
        })
    }

    /// c = f(a), keeping a's shared flag.
    fn un(
        &mut self,
        a: &Taint<F>,
        f: impl FnOnce(&mut PlainDriver<F>, &F) -> Result<F>,
    ) -> Result<Taint<F>> {
        Ok(Taint {
            val: f(&mut self.inner, &a.val)?,
            shared: a.shared,
        })
    }
}

impl<F: PrimeField> VmDriver<F> for TaintDriver<F> {
    type Public = F;
    type ArithmeticShare = F;
    type VmType = Taint<F>;

    fn add(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::add)
    }

    fn sub(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::sub)
    }

    fn mul(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::mul)
    }

    fn div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::div)
    }

    fn int_div(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::int_div)
    }

    fn pow(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::pow)
    }

    fn modulo(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::modulo)
    }

    fn neg(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        self.un(a, PlainDriver::neg)
    }

    fn lt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::lt)
    }

    fn le(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::le)
    }

    fn gt(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::gt)
    }

    fn ge(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::ge)
    }

    fn eq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::eq)
    }

    fn neq(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::neq)
    }

    fn shift_r(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::shift_r)
    }

    fn shift_l(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::shift_l)
    }

    fn bool_not(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        self.un(a, PlainDriver::bool_not)
    }

    fn bool_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::bool_and)
    }

    fn bool_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::bool_or)
    }

    fn bit_xor(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::bit_xor)
    }

    fn bit_or(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::bit_or)
    }

    fn bit_and(&mut self, a: &Self::VmType, b: &Self::VmType) -> Result<Self::VmType> {
        self.bin(a, b, PlainDriver::bit_and)
    }

    fn cmux(
        &mut self,
        cond: &Self::VmType,
        truthy: &Self::VmType,
        falsy: &Self::VmType,
    ) -> Result<Self::VmType> {
        Ok(Taint {
            val: self.inner.cmux(&cond.val, &truthy.val, &falsy.val)?,
            shared: cond.shared || truthy.shared || falsy.shared,
        })
    }

    fn is_zero(&mut self, a: &Self::VmType, allow_secret_inputs: bool) -> Result<bool> {
        if a.shared && !allow_secret_inputs {
            bail!("cannot check is_zero on a shared value without allow_secret_inputs");
        }
        self.inner.is_zero(&a.val, allow_secret_inputs)
    }

    fn is_shared(&self, a: &Self::VmType) -> Result<bool> {
        Ok(a.shared)
    }

    fn to_index(&mut self, a: &Self::VmType) -> Result<usize> {
        if a.shared {
            bail!("cannot convert a shared value to an index");
        }
        self.inner.to_index(&a.val)
    }

    fn open(&mut self, a: &Self::VmType) -> Result<Self::Public> {
        Ok(a.val)
    }

    fn to_share(&mut self, a: &Self::VmType) -> Result<Self::ArithmeticShare> {
        Ok(a.val)
    }

    fn public_one(&self) -> Self::VmType {
        Taint {
            val: self.inner.public_one(),
            shared: false,
        }
    }

    fn public_zero(&self) -> Self::VmType {
        Taint {
            val: self.inner.public_zero(),
            shared: false,
        }
    }

    fn public_from(&self, f: F) -> Self::VmType {
        Taint {
            val: self.inner.public_from(f),
            shared: false,
        }
    }

    fn compare_vm_config(&mut self, _config: &VMConfig) -> Result<()> {
        Ok(())
    }

    fn log(&mut self, a: &Self::VmType, allow_leaky_logs: bool) -> Result<String> {
        if a.shared && !allow_leaky_logs {
            return Ok("secret".to_string());
        }
        self.inner.log(&a.val, allow_leaky_logs)
    }

    fn sqrt(&mut self, a: &Self::VmType) -> Result<Self::VmType> {
        self.un(a, PlainDriver::sqrt)
    }

    fn num2bits(&mut self, a: &Self::VmType, bits: usize) -> Result<Vec<Self::VmType>> {
        let bits_vals = self.inner.num2bits(&a.val, bits)?;
        Ok(bits_vals
            .into_iter()
            .map(|val| Taint {
                val,
                shared: a.shared,
            })
            .collect())
    }

    fn addbits(
        &mut self,
        a: &[Self::VmType],
        b: &[Self::VmType],
    ) -> Result<(Vec<Self::VmType>, Self::VmType)> {
        let shared = a.iter().any(|x| x.shared) || b.iter().any(|x| x.shared);
        let a_vals: Vec<F> = a.iter().map(|x| x.val).collect();
        let b_vals: Vec<F> = b.iter().map(|x| x.val).collect();
        let (res, carry) = self.inner.addbits(&a_vals, &b_vals)?;
        Ok((
            res.into_iter().map(|val| Taint { val, shared }).collect(),
            Taint { val: carry, shared },
        ))
    }

    fn poseidon2_accelerator<const T: usize>(
        &mut self,
        inputs: &[Self::VmType],
    ) -> Result<(Vec<Self::VmType>, Vec<Self::VmType>)> {
        let shared = inputs.iter().any(|x| x.shared);
        let vals: Vec<F> = inputs.iter().map(|x| x.val).collect();
        let (state, trace) = self.inner.poseidon2_accelerator::<T>(&vals)?;
        Ok((
            state.into_iter().map(|val| Taint { val, shared }).collect(),
            trace.into_iter().map(|val| Taint { val, shared }).collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_propagates() {
        let mut d = TaintDriver::<ark_bn254::Fr>::default();
        let s = Taint {
            val: 3u64.into(),
            shared: true,
        };
        let p = Taint {
            val: 4u64.into(),
            shared: false,
        };
        let r = d.mul(&s, &p).unwrap();
        assert_eq!(r.val, 12u64.into());
        assert!(r.shared);
        assert!(!d.mul(&p, &p).unwrap().shared);
    }

    #[test]
    fn taint_guards_leaks() {
        let mut d = TaintDriver::<ark_bn254::Fr>::default();
        let s = Taint {
            val: 3u64.into(),
            shared: true,
        };
        assert!(d.is_zero(&s, false).is_err()); // would leak
        assert!(!d.is_zero(&s, true).unwrap()); // explicit open allowed
        assert!(d.to_index(&s).is_err()); // shared index is an error
        assert!(d.is_shared(&s).unwrap());
        assert_eq!(d.log(&s, false).unwrap(), "secret");
    }
}
