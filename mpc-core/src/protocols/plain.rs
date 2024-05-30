use crate::{
    traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol},
    RngType,
};
use ark_ff::PrimeField;
use eyre::eyre;
use eyre::Result;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use rand::SeedableRng;

#[macro_export]
macro_rules! to_usize {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        usize::try_from(a.to_u64().ok_or(eyre!("Cannot convert var into u64"))?)?
    }};
}

macro_rules! bool_op {
    ($lhs: expr, $op: tt, $rhs: expr) => {
       if $lhs $op $rhs {
        F::one()
       } else {
        F::zero()
       }
    };
}

macro_rules! to_u64 {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a.to_u64().ok_or(eyre!("Cannot convert var into u64"))?
    }};
}

macro_rules! to_bigint {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a
    }};
}
#[derive(Default)]
pub struct PlainDriver {}

impl<F: PrimeField> PrimeFieldMpcProtocol<F> for PlainDriver {
    type FieldShare = F;
    type FieldShareVec = Vec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        *a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        *a - b
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        *a + b
    }

    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec) {
        a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a -= b);
    }

    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare> {
        Ok(*a * b)
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        *a * b
    }

    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare> {
        if a.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot invert zero",
            ));
        }
        Ok(a.inverse().unwrap())
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -*a
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        let mut rng = RngType::from_entropy();
        Ok(F::rand(&mut rng))
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        Ok(*a)
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn promote_to_trivial_share(&self, public_values: &[F]) -> Self::FieldShareVec {
        public_values.to_vec()
    }

    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F) {
        let mut pow = c;
        for c in coeffs.iter_mut() {
            *c *= pow;
            pow *= g;
        }
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(F, usize)],
        public_inputs: &[F],
        private_witness: &Self::FieldShareVec,
    ) -> Self::FieldShare {
        let mut acc = F::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                acc += *coeff * public_inputs[*index];
            } else {
                acc += *coeff * private_witness[*index - public_inputs.len()];
            }
        }
        acc
    }

    fn clone_from_slice(
        &self,
        dst: &mut Self::FieldShareVec,
        src: &Self::FieldShareVec,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    ) {
        assert!(dst.len() >= dst_offset + len);
        assert!(src.len() >= src_offset + len);
        assert!(len > 0);
        dst[dst_offset..dst_offset + len].clone_from_slice(&src[src_offset..src_offset + len]);
    }

    fn print(&self, to_print: &Self::FieldShareVec) {
        print!("[");
        for a in to_print.iter() {
            print!("{a}, ")
        }
        println!("]");
    }
}

impl<F: PrimeField> CircomWitnessExtensionProtocol<F> for PlainDriver {
    type VmType = F;

    fn vm_add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        a + b
    }

    fn vm_sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        a - b
    }

    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a * b)
    }

    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType {
        -a
    }

    fn vm_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        Ok(a / b)
    }

    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_u64!(a);
        let rhs = to_u64!(b);
        Ok(F::from(lhs / rhs))
    }

    fn is_zero(&self, a: Self::VmType) -> bool {
        a.is_zero()
    }

    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        bool_op!(a, <, b)
    }

    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        bool_op!(a, <=, b)
    }

    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        bool_op!(a, >, b)
    }

    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        bool_op!(a, >=, b)
    }

    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        bool_op!(a, ==, b)
    }

    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        bool_op!(a, !=, b)
    }

    fn vm_shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val >> shift))
    }

    fn vm_shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val << shift))
    }

    fn vm_bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
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

    fn vm_bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs ^ rhs))
    }

    fn vm_bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs | rhs))
    }

    fn vm_bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> Result<Self::VmType> {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        Ok(F::from(lhs & rhs))
    }

    fn vm_open(&self, a: Self::VmType) -> F {
        a
    }
}

pub use to_usize;
