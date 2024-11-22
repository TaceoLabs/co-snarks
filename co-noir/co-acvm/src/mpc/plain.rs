use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;

use ark_ff::{One, PrimeField};
use co_brillig::mpc::{PlainBrilligDriver, PlainBrilligType};
use mpc_core::lut::{LookupTableProvider, PlainLookupTableProvider};
use num_bigint::BigUint;

use super::NoirWitnessExtensionProtocol;

#[derive(Default)]
pub struct PlainAcvmSolver<F: PrimeField> {
    plain_lut: PlainLookupTableProvider<F>,
    phantom_data: PhantomData<F>,
}
impl<F: PrimeField> PlainAcvmSolver<F> {
    pub fn new() -> Self {
        Self {
            plain_lut: Default::default(),
            phantom_data: Default::default(),
        }
    }
}

impl<F: PrimeField> NoirWitnessExtensionProtocol<F> for PlainAcvmSolver<F> {
    type Lookup = PlainLookupTableProvider<F>;
    type ArithmeticShare = F;
    type AcvmType = F;

    type BrilligDriver = PlainBrilligDriver<F>;

    fn init_brillig_driver(&mut self) -> std::io::Result<Self::BrilligDriver> {
        Ok(PlainBrilligDriver::default())
    }

    fn from_brillig_result(brillig_result: Vec<PlainBrilligType<F>>) -> Vec<Self::AcvmType> {
        brillig_result.into_iter().map(|v| v.into_field()).collect()
    }

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        a.is_zero()
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        a.is_one()
    }

    fn acvm_add_assign_with_public(&mut self, public: F, secret: &mut Self::AcvmType) {
        *secret += public;
    }

    fn acvm_mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        secret * public
    }

    fn acvm_negate_inplace(&mut self, a: &mut Self::AcvmType) {
        a.neg_in_place();
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, result: &mut Self::AcvmType) {
        *result += q_l * w_l;
    }

    fn add_assign(&mut self, lhs: &mut Self::AcvmType, rhs: Self::AcvmType) {
        *lhs += rhs;
    }

    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
    ) -> io::Result<Self::AcvmType> {
        Ok(c * lhs * rhs)
    }

    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        Ok(-c / q_l)
    }

    fn init_lut_by_acvm_type(&mut self, values: Vec<Self::AcvmType>) -> HashMap<F, F> {
        self.plain_lut
            .init_map(values.into_iter().enumerate().map(|(idx, value)| {
                let promoted_idx = F::from(u64::try_from(idx).expect("usize fits into u64"));
                (promoted_idx, value)
            }))
    }

    fn read_lut_by_acvm_type(
        &mut self,
        index: &Self::AcvmType,
        lut: &HashMap<F, F>,
    ) -> io::Result<F> {
        self.plain_lut.get_from_lut(*index, lut)
    }

    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        map: &mut HashMap<F, F>,
    ) -> io::Result<()> {
        self.plain_lut.write_to_lut(index, value, map)
    }

    fn is_shared(_: &Self::AcvmType) -> bool {
        false
    }

    fn get_shared(_: &Self::AcvmType) -> Option<Self::ArithmeticShare> {
        None
    }

    fn get_public(a: &Self::AcvmType) -> Option<F> {
        Some(*a)
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> io::Result<Vec<F>> {
        Ok(a.to_vec())
    }

    fn decompose_arithmetic(
        &mut self,
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::result::Result<std::vec::Vec<F>, std::io::Error> {
        let mut result = Vec::with_capacity(total_bit_size_per_field.div_ceil(decompose_bit_size));
        let big_mask = (BigUint::from(1u64) << total_bit_size_per_field) - BigUint::one();
        let small_mask = (BigUint::from(1u64) << decompose_bit_size) - BigUint::one();
        let mut x: BigUint = input.into();
        x &= &big_mask;
        for _ in 0..total_bit_size_per_field.div_ceil(decompose_bit_size) {
            let chunk = &x & &small_mask;
            x >>= decompose_bit_size;
            result.push(F::from(chunk));
        }
        Ok(result)
    }

    fn acvm_sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        share_1 - share_2
    }

    fn sort(
        &mut self,
        inputs: &[Self::ArithmeticShare],
        bitsize: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        let mut result = Vec::with_capacity(inputs.len());
        let mask = (BigUint::from(1u64) << bitsize) - BigUint::one();
        for x in inputs.iter() {
            let mut x: BigUint = (*x).into();
            x &= &mask;
            result.push(F::from(x));
        }
        result.sort();
        Ok(result)
    }

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        public_value
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn acvm_mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> io::Result<Self::AcvmType> {
        Ok(secret_1 * secret_2)
    }
}
