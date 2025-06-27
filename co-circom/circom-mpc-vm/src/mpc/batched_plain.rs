use ark_ff::One;
use ark_ff::PrimeField;
use itertools::Itertools as _;
use num_bigint::BigUint;

use crate::mpc::plain::to_usize;

use super::VmCircomWitnessExtension;
use super::plain::CircomPlainVmWitnessExtension;

macro_rules! bool_comp_op {
    ($driver: expr, $lhs: expr, $op: tt, $rhs: expr) => {{
        let lhs = $driver.val($lhs);
        let rhs = $driver.val($rhs);
       if (lhs $op rhs){
        F::one()
       } else {
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

pub struct BatchedCircomPlainVmWitnessExtension<F: PrimeField> {
    negative_one: F,
    plain_wts_ext: CircomPlainVmWitnessExtension<F>,
    batch_size: usize,
}

impl<F: PrimeField> BatchedCircomPlainVmWitnessExtension<F> {
    pub(crate) fn new(batch_size: usize) -> Self {
        let modulus = to_bigint!(F::MODULUS);
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        Self {
            negative_one: F::from(modulus / two + one),
            plain_wts_ext: CircomPlainVmWitnessExtension::default(),
            batch_size,
        }
    }
}

impl<F: PrimeField> BatchedCircomPlainVmWitnessExtension<F> {
    /// Normally F is split into positive and negative numbers in the range [0, p/2] and [p/2 + 1, p)
    /// However, for comparisons, we want the negative numbers to be "lower" than the positive ones.
    /// Therefore we shift the input by p/2 + 1 to the left, which results in a mapping of [negative, 0, positive] into F.
    /// We can then compare the numbers as if they were unsigned.
    /// While this could be done easier by just comparing the numbers as BigInt, we do it this way because this is easier to replicate in MPC later.
    #[inline(always)]
    pub(crate) fn val(&self, z: F) -> F {
        z - self.negative_one
    }

    #[expect(dead_code)]
    #[inline(always)]
    pub(crate) fn is_negative(&self, x: F) -> bool {
        x >= self.negative_one
    }
}

#[allow(dead_code)]
#[expect(unused_variables)]
impl<F: PrimeField> VmCircomWitnessExtension<F> for BatchedCircomPlainVmWitnessExtension<F> {
    type Public = Vec<F>;
    type ArithmeticShare = Vec<F>;

    type VmType = Vec<F>;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a + b).collect())
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a - b).collect())
    }

    fn mul(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a / b).collect())
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        a.iter()
            .zip(b.iter())
            .map(|(a, b)| self.plain_wts_ext.modulo(*a, *b))
            .collect()
    }

    fn sqrt(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn neg(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        Ok(a.iter()
            .zip(b.iter())
            .map(|(a, b)| bool_comp_op!(self, *a, <, *b))
            .collect())
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

    fn is_zero(&mut self, a: Self::VmType, _: bool) -> eyre::Result<bool> {
        let all_zero = a.iter().map(|a| a.is_zero()).collect_vec();
        // we are using is_zero only for ifs and asserts. If assert fails
        // for one, then simply all fail. We do not support shared ifs for
        // batched variant, therefore we can fail as well. For public ifs
        // this must be same for all.
        let is_zero = all_zero[0];
        if all_zero.iter().all(|x| *x == is_zero) {
            Ok(is_zero)
        } else {
            eyre::bail!("not all same in batch is zero");
        }
    }

    fn is_shared(&mut self, a: &Self::VmType) -> eyre::Result<bool> {
        todo!()
    }

    fn to_index(&mut self, a: Self::VmType) -> eyre::Result<usize> {
        assert!(!a.is_empty(), "Empty Batch in to_index");
        let mut all_indices = Vec::with_capacity(a.len());

        for ele in a.iter() {
            all_indices.push(to_usize!(*ele));
        }
        // TODO does this work? Maybe we need an Index Associated Type
        let index = all_indices[0];
        if all_indices.iter().all(|x| *x == index) {
            Ok(index)
        } else {
            eyre::bail!("not all same in batch to_index");
        }
    }

    fn open(&mut self, a: Self::VmType) -> eyre::Result<Self::Public> {
        Ok(a)
    }

    fn to_share(&mut self, a: Self::VmType) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a)
    }

    fn public_one(&self) -> Self::VmType {
        todo!()
    }

    fn public_zero(&self) -> Self::VmType {
        vec![F::zero(); self.batch_size]
    }

    fn compare_vm_config(&mut self, config: &crate::mpc_vm::VMConfig) -> eyre::Result<()> {
        Ok(())
    }

    fn num2bits(&mut self, a: Self::VmType, bits: usize) -> eyre::Result<Vec<Self::VmType>> {
        todo!()
    }

    fn addbits(
        &mut self,
        a: Vec<Self::VmType>,
        b: Vec<Self::VmType>,
    ) -> eyre::Result<(Vec<Self::VmType>, Self::VmType)> {
        assert!(a.len() == b.len());
        let bitlen = a.len();
        assert!(bitlen < F::MODULUS_BIT_SIZE as usize - 1);
        let acc_a = a
            .into_iter()
            .fold(vec![F::ZERO; self.batch_size], |acc, x| {
                acc.iter().zip(x).map(|(acc, x)| acc.double() + x).collect()
            });
        let acc_b = b
            .into_iter()
            .fold(vec![F::ZERO; self.batch_size], |acc, x| {
                acc.iter().zip(x).map(|(acc, x)| acc.double() + x).collect()
            });

        let sum = acc_a
            .into_iter()
            .zip(acc_b)
            .map(|(a, b)| to_bigint!(a + b))
            .collect_vec();
        let carry_mask = BigUint::one() << bitlen;
        let carry = sum
            .iter()
            .map(|sum| F::from((sum & &carry_mask) >> bitlen))
            .collect_vec();
        let mut res = Vec::with_capacity(bitlen);
        for i in 0..bitlen {
            res.push(
                sum.iter()
                    .map(|sum| F::from((sum >> i) & BigUint::one()))
                    .collect_vec(),
            );
        }
        res.reverse();
        Ok((res, carry))
    }

    fn log(&mut self, a: Self::VmType, _: bool) -> eyre::Result<String> {
        Ok(format!("[{}]", a.iter().map(|a| a.to_string()).join(", ")))
    }
}
