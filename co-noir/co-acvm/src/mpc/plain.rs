use super::NoirWitnessExtensionProtocol;
use ark_ff::{One, PrimeField};
use co_brillig::mpc::{PlainBrilligDriver, PlainBrilligType};
use mpc_core::{
    gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations},
    lut::{LookupTableProvider, PlainLookupTableProvider},
};
use num_bigint::BigUint;
use std::io;
use std::marker::PhantomData;

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

impl<F: PrimeField> Default for PlainAcvmSolver<F> {
    fn default() -> Self {
        Self::new()
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

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<PlainBrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        Ok(brillig_result.into_iter().map(|v| v.into_field()).collect())
    }

    fn shared_zeros(&mut self, len: usize) -> io::Result<Vec<Self::AcvmType>> {
        Ok(vec![F::default(); len])
    }

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        a.is_zero()
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        a.is_one()
    }

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> io::Result<Self::AcvmType> {
        assert!(cond.is_one() || cond.is_zero());
        if cond.is_one() {
            Ok(truthy)
        } else {
            Ok(falsy)
        }
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        lhs + rhs
    }

    fn add_assign_with_public(&mut self, public: F, secret: &mut Self::AcvmType) {
        *secret += public;
    }

    fn sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        share_1 - share_2
    }

    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        secret * public
    }

    fn mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> io::Result<Self::AcvmType> {
        Ok(secret_1 * secret_2)
    }

    fn negate_inplace(&mut self, a: &mut Self::AcvmType) {
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

    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        self.plain_lut.init_public(values)
    }

    fn read_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> io::Result<F> {
        let mut a = ();
        let mut b = ();
        self.plain_lut.get_from_lut(index, lut, &mut a, &mut b)
    }

    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> io::Result<()> {
        let mut a = ();
        let mut b = ();
        self.plain_lut
            .write_to_lut(index, value, lut, &mut a, &mut b)
    }

    fn get_length_of_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> usize {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_lut_len(lut)
    }

    fn get_public_lut(
        lut: &<Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> io::Result<Vec<F>> {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_public_lut(lut)
    }

    fn one_hot_vector_from_shared_index(
        &mut self,
        index: Self::ArithmeticShare,
        len: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        let len_ = if len.is_power_of_two() {
            len
        } else {
            len.next_power_of_two()
        };
        let mut result = vec![F::zero(); len_];
        let index: BigUint = index.into();
        let index = usize::try_from(index).expect("Index to large for usize");
        result[index] = F::one();
        Ok(result)
    }

    fn write_to_shared_lut_from_ohv(
        &mut self,
        ohv: &[Self::ArithmeticShare],
        value: Self::ArithmeticShare,
        lut: &mut [Self::ArithmeticShare],
    ) -> std::io::Result<()> {
        let index = ohv
            .iter()
            .enumerate()
            .find(|x| x.1.is_one())
            .expect("Is an one_hot_encoded vector")
            .0;
        lut[index] = value;
        Ok(())
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

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        public_value
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
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

    fn decompose_arithmetic_many(
        &mut self,
        input: &[Self::ArithmeticShare],
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
        input
            .iter()
            .map(|&inp| {
                Self::decompose_arithmetic(self, inp, total_bit_size_per_field, decompose_bit_size)
            })
            .collect()
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

    fn slice(
        &mut self,
        input: Self::ArithmeticShare,
        msb: u8,
        lsb: u8,
        bitsize: usize,
    ) -> std::io::Result<[Self::ArithmeticShare; 3]> {
        let big_mask = (BigUint::from(1u64) << bitsize) - BigUint::one();
        let hi_mask = (BigUint::one() << (bitsize - msb as usize)) - BigUint::one();
        let lo_mask = (BigUint::one() << lsb) - BigUint::one();
        let slice_mask = (BigUint::one() << ((msb - lsb) as u32 + 1)) - BigUint::one();

        let msb_plus_one = msb as u32 + 1;
        let mut x: BigUint = input.into();
        x &= &big_mask;

        let hi = F::from((&x >> msb_plus_one) & hi_mask);
        let lo = F::from(&x & lo_mask);
        let slice = F::from((x >> lsb) & slice_mask);

        Ok([lo, slice, hi])
    }

    fn integer_bitwise_and(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        let lhs: BigUint = lhs.into();
        let rhs: BigUint = rhs.into();
        let res = (lhs & rhs) & mask;
        Ok(Self::AcvmType::from(res))
    }

    fn integer_bitwise_xor(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        let lhs: BigUint = lhs.into();
        let rhs: BigUint = rhs.into();
        let res = (lhs ^ rhs) & mask;
        Ok(Self::AcvmType::from(res))
    }

    fn slice_and_get_and_rotate_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: usize,
        total_bitsize: usize,
        rotation: usize,
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let num_decomps_per_field = total_bitsize.div_ceil(basis_bits);
        let basis = BigUint::one() << basis_bits;

        let mut target1: BigUint = input1.into();
        let mut target2: BigUint = input2.into();
        let mut slices1: Vec<u64> = Vec::with_capacity(num_decomps_per_field);
        let mut slices2: Vec<u64> = Vec::with_capacity(num_decomps_per_field);
        for i in 0..num_decomps_per_field {
            if i == num_decomps_per_field - 1 && (target1 >= basis || target2 >= basis) {
                panic!("Last key slice greater than {}", basis);
            }
            slices1.push(
                (&target1 % &basis)
                    .try_into()
                    .expect("Conversion must work"),
            );
            slices2.push(
                (&target2 % &basis)
                    .try_into()
                    .expect("Conversion must work"),
            );
            target1 /= &basis;
            target2 /= &basis;
        }
        let mut results = Vec::with_capacity(num_decomps_per_field);
        slices1.iter().zip(slices2.iter()).for_each(|(s1, s2)| {
            let res = s1 & s2;
            results.push(F::from(if rotation != 0 {
                (res >> rotation) | (res << (64 - rotation))
            } else {
                res
            }));
        });
        Ok((
            results,
            slices1.into_iter().map(F::from).collect(),
            slices2.into_iter().map(F::from).collect(),
        ))
    }

    fn slice_and_get_xor_rotate_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: usize,
        total_bitsize: usize,
        rotation: usize,
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let num_decomps_per_field = total_bitsize.div_ceil(basis_bits);
        let basis = BigUint::one() << basis_bits;

        let mut target1: BigUint = input1.into();
        let mut target2: BigUint = input2.into();
        let mut slices1: Vec<u64> = Vec::with_capacity(num_decomps_per_field);
        let mut slices2: Vec<u64> = Vec::with_capacity(num_decomps_per_field);
        for i in 0..num_decomps_per_field {
            if i == num_decomps_per_field - 1 && (target1 >= basis || target2 >= basis) {
                panic!("Last key slice greater than {}", basis);
            }
            slices1.push(
                (&target1 % &basis)
                    .try_into()
                    .expect("Conversion must work"),
            );
            slices2.push(
                (&target2 % &basis)
                    .try_into()
                    .expect("Conversion must work"),
            );
            target1 /= &basis;
            target2 /= &basis;
        }
        let mut results = Vec::with_capacity(num_decomps_per_field);
        slices1.iter().zip(slices2.iter()).for_each(|(s1, s2)| {
            let res = s1 ^ s2;
            results.push(F::from(if rotation != 0 {
                (res >> rotation) | (res << (64 - rotation))
            } else {
                res
            }));
        });
        Ok((
            results,
            slices1.into_iter().map(F::from).collect(),
            slices2.into_iter().map(F::from).collect(),
        ))
    }

    fn sort_vec_by(
        &mut self,
        key: &[Self::ArithmeticShare],
        inputs: Vec<&[Self::ArithmeticShare]>,
        bitsize: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
        let mask = (BigUint::from(1u64) << bitsize) - BigUint::one();

        let mut indexed_values: Vec<(F, usize)> = key
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let mut x: BigUint = (*x).into();
                x &= &mask;
                (F::from(x), i)
            })
            .collect();

        indexed_values.sort_by(|a, b| a.0.cmp(&b.0));

        let mut results = Vec::with_capacity(inputs.len());

        for inp in inputs {
            results.push(indexed_values.iter().map(|(_, i)| inp[*i]).collect())
        }
        Ok(results)
    }

    fn poseidon2_permutation<const T: usize, const D: u64>(
        &mut self,
        mut input: Vec<Self::AcvmType>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Vec<Self::AcvmType>> {
        if input.len() != T {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Expected {} values but encountered {}", T, input.len(),),
            ));
        }
        poseidon2.permutation_in_place(
            input
                .as_mut_slice()
                .try_into()
                .expect("Sizes are checked already"),
        );
        Ok(input)
    }

    fn poseidon2_matmul_external_inplace<const T: usize, const D: u64>(
        &self,
        input: &mut [Self::ArithmeticShare; T],
    ) {
        Poseidon2::<F, T, D>::matmul_external(input);
    }

    fn poseidon2_preprocess_permutation<const T: usize, const D: u64>(
        &mut self,
        _num_poseidon: usize,
        _poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        Ok(Poseidon2Precomputations::default())
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        _precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()> {
        poseidon2.external_round(input, r);
        Ok(())
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        _precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()> {
        poseidon2.internal_round(input, r);
        Ok(())
    }

    fn is_public_lut(_lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> bool {
        true
    }

    fn equal(&mut self, a: &Self::AcvmType, b: &Self::AcvmType) -> std::io::Result<Self::AcvmType> {
        Ok(Self::ArithmeticShare::from(a == b))
    }
}
