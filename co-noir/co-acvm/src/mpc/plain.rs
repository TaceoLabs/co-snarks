use super::{NoirWitnessExtensionProtocol, downcast};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, MontConfig, One, PrimeField};
use blake2::{Blake2s256, Digest};
use co_brillig::mpc::{PlainBrilligDriver, PlainBrilligType};
use core::panic;
use libaes::Cipher;
use mpc_core::{
    gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations},
    lut::{LookupTableProvider, PlainLookupTableProvider},
    protocols::rep3::yao::circuits::SHA256Table,
};
use num_bigint::BigUint;
use std::any::TypeId;
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

    pub(crate) fn create_grumpkin_point(
        x: ark_bn254::Fr,
        y: ark_bn254::Fr,
        is_infinity: bool,
    ) -> eyre::Result<ark_grumpkin::Affine> {
        if is_infinity {
            return Ok(ark_grumpkin::Affine::zero());
        }
        let point = ark_grumpkin::Affine::new_unchecked(x, y);
        if !point.is_on_curve() {
            eyre::bail!("Point ({}, {}) is not on curve", x, y);
        };
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            eyre::bail!("Point ({}, {}) is not in correct subgroup", x, y);
        };
        Ok(point)
    }

    pub(crate) fn bn254_fr_to_u128(inp: ark_bn254::Fr) -> eyre::Result<u128> {
        let inp_bigint = inp.into_bigint();
        if inp_bigint.0[2] != 0 || inp_bigint.0[3] != 0 {
            eyre::bail!("Scalar {} is not less than 2^128", inp);
        }
        let output = inp_bigint.0[0] as u128 + ((inp_bigint.0[1] as u128) << 64);
        Ok(output)
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
    type AcvmPoint<C: CurveGroup<BaseField = F>> = C;

    type BrilligDriver = PlainBrilligDriver<F>;

    fn init_brillig_driver(&mut self) -> eyre::Result<Self::BrilligDriver> {
        Ok(PlainBrilligDriver::default())
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<PlainBrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        Ok(brillig_result.into_iter().map(|v| v.into_field()).collect())
    }

    fn shared_zeros(&mut self, len: usize) -> eyre::Result<Vec<Self::AcvmType>> {
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
    ) -> eyre::Result<Self::AcvmType> {
        assert!(cond.is_one() || cond.is_zero());
        if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        lhs + rhs
    }

    fn add_points<C: CurveGroup<BaseField = F>>(
        &self,
        lhs: Self::AcvmPoint<C>,
        rhs: Self::AcvmPoint<C>,
    ) -> Self::AcvmPoint<C> {
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
    ) -> eyre::Result<Self::AcvmType> {
        Ok(secret_1 * secret_2)
    }

    fn invert(&mut self, secret: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        secret
            .inverse()
            .ok_or_else(|| eyre::eyre!("Cannot invert zero"))
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
    ) -> eyre::Result<Self::AcvmType> {
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
    ) -> eyre::Result<F> {
        self.plain_lut
            .get_from_lut(index, lut, &(), &(), &mut (), &mut ())
    }

    fn read_from_public_luts(
        &mut self,
        index: Self::AcvmType,
        luts: &[Vec<F>],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        let mut result = Vec::with_capacity(luts.len());
        for lut in luts {
            let res = self
                .plain_lut
                .get_from_lut(index, lut, &(), &(), &mut (), &mut ())?;
            result.push(res);
        }
        Ok(result)
    }

    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<()> {
        self.plain_lut
            .write_to_lut(index, value, lut, &(), &(), &mut (), &mut ())
    }

    fn get_length_of_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> usize {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_lut_len(lut)
    }

    fn get_public_lut(
        lut: &<Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<&Vec<F>> {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_public_lut(lut)
    }

    fn one_hot_vector_from_shared_index(
        &mut self,
        index: Self::ArithmeticShare,
        len: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let len_ = len.next_power_of_two();
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
    ) -> eyre::Result<()> {
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

    fn get_public_point<C: CurveGroup<BaseField = F>>(a: &Self::AcvmPoint<C>) -> Option<C> {
        Some(*a)
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> eyre::Result<Vec<F>> {
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
    ) -> eyre::Result<std::vec::Vec<F>> {
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
    ) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
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
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
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
    ) -> eyre::Result<[Self::ArithmeticShare; 3]> {
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
    ) -> eyre::Result<Self::AcvmType> {
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
    ) -> eyre::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        let lhs: BigUint = lhs.into();
        let rhs: BigUint = rhs.into();
        let res = (lhs ^ rhs) & mask;
        Ok(Self::AcvmType::from(res))
    }

    fn slice_and_get_and_rotate_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: usize,
        _total_bitsize: usize,
        _rotation: usize,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_and_rotate_values not implemented for plaindriver and normally should not be called"
        );
    }

    fn slice_and_get_xor_rotate_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: usize,
        _total_bitsize: usize,
        _rotation: usize,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_xor_rotate_values not implemented for plaindriver and normally should not be called"
        );
    }

    fn slice_and_get_xor_rotate_values_with_filter(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: &[u64],
        _rotation: &[usize],
        _filter: &[bool],
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_xor_rotate_values_with_filter not implemented for plaindriver and normally should not be called"
        );
    }

    fn sort_vec_by(
        &mut self,
        key: &[Self::AcvmType],
        inputs: Vec<&[Self::ArithmeticShare]>,
        bitsize: usize,
    ) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
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
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if input.len() != T {
            eyre::bail!("Expected {} values but encountered {}", T, input.len());
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
    ) -> eyre::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        Ok(Poseidon2Precomputations::default())
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        _precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        poseidon2.external_round(input, r);
        Ok(())
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        _precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        poseidon2.internal_round(input, r);
        Ok(())
    }

    fn is_public_lut(_lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> bool {
        true
    }

    fn equal(&mut self, a: &Self::AcvmType, b: &Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        Ok(Self::ArithmeticShare::from(a == b))
    }

    fn equal_many(
        &mut self,
        a: &[Self::AcvmType],
        b: &[Self::AcvmType],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if a.len() != b.len() {
            eyre::bail!(
                "Vectors must have the same length. Length of a : {} and length of b: {}",
                a.len(),
                b.len()
            );
        }
        let mut result = Vec::with_capacity(a.len());
        for (a_i, b_i) in a.iter().zip(b.iter()) {
            result.push(Self::ArithmeticShare::from(a_i == b_i));
        }
        Ok(result)
    }

    fn multi_scalar_mul(
        &mut self,
        points: &[Self::AcvmType],
        scalars_lo: &[Self::AcvmType],
        scalars_hi: &[Self::AcvmType],
        pedantic_solving: bool,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        // We transmute since we only support one curve

        // Safety: We checked that the types match
        let points = unsafe { std::mem::transmute::<&[Self::AcvmType], &[ark_bn254::Fr]>(points) };
        // Safety: We checked that the types match
        let scalars_lo =
            unsafe { std::mem::transmute::<&[Self::AcvmType], &[ark_bn254::Fr]>(scalars_lo) };
        // Safety: We checked that the types match
        let scalars_hi =
            unsafe { std::mem::transmute::<&[Self::AcvmType], &[ark_bn254::Fr]>(scalars_hi) };

        if points.len() != 3 * scalars_lo.len() || scalars_lo.len() != scalars_hi.len() {
            eyre::bail!("Points and scalars must have the same length");
        }

        let mut output_point = ark_grumpkin::Affine::zero();

        for i in (0..points.len()).step_by(3) {
            if pedantic_solving && points[i + 2] > ark_bn254::Fr::one() {
                eyre::bail!(
                    "--pedantic-solving: is_infinity expected to be a bool, but found to be > 1"
                );
            }
            let point = Self::create_grumpkin_point(
                points[i],
                points[i + 1],
                points[i + 2] == ark_bn254::Fr::one(),
            )?;

            let scalar_low = Self::bn254_fr_to_u128(scalars_lo[i / 3])?;
            let scalar_high = Self::bn254_fr_to_u128(scalars_hi[i / 3])?;
            let grumpkin_integer: BigUint = (BigUint::from(scalar_high) << 128) + scalar_low;

            // Check if this is smaller than the grumpkin modulus
            if pedantic_solving && grumpkin_integer >= ark_grumpkin::FrConfig::MODULUS.into() {
                eyre::bail!(
                    "{} is not a valid grumpkin scalar",
                    grumpkin_integer.to_str_radix(16)
                );
            }

            let iteration_output_point =
                ark_grumpkin::Affine::from(point.mul_bigint(grumpkin_integer.to_u64_digits()));

            output_point = ark_grumpkin::Affine::from(output_point + iteration_output_point);
        }

        // TODO maybe find a way to unify this with pointshare_to_field_shares
        if let Some((out_x, out_y)) = output_point.xy() {
            let out_x = *downcast(&out_x).expect("We checked types");
            let out_y = *downcast(&out_y).expect("We checked types");
            Ok((out_x, out_y, F::zero()))
        } else {
            Ok((F::zero(), F::zero(), F::one()))
        }
    }

    fn field_shares_to_pointshare<C: CurveGroup<BaseField = F>>(
        &mut self,
        x: Self::AcvmType,
        y: Self::AcvmType,
        is_infinity: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmPoint<C>> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        if is_infinity > F::one() {
            eyre::bail!(
                "--pedantic-solving: is_infinity expected to be a bool, but found to be > 1"
            );
        }

        // Ensure the curve type matches grumpkin at runtime to avoid invalid downcasts
        if TypeId::of::<C::Affine>() != TypeId::of::<ark_grumpkin::Affine>()
            || TypeId::of::<C>() != TypeId::of::<ark_grumpkin::Projective>()
        {
            eyre::bail!("Only the grumpkin curve is supported for field_shares_to_pointshare");
        }

        let x = *downcast(&x).expect("We checked types");
        let y = *downcast(&y).expect("We checked types");
        let point_affine = Self::create_grumpkin_point(x, y, is_infinity == F::one())?;
        let point_affine_cast = *downcast(&point_affine).expect("We checked types");

        Ok(C::from(point_affine_cast))
    }

    fn pointshare_to_field_shares<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        if let Some((out_x, out_y)) = point.into_affine().xy() {
            Ok((out_x, out_y, F::zero()))
        } else {
            Ok((F::zero(), F::zero(), F::one()))
        }
    }

    fn gt(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        Ok(F::from(lhs > rhs))
    }

    fn right_shift(&mut self, input: Self::AcvmType, shift: usize) -> eyre::Result<Self::AcvmType> {
        let x: BigUint = input.into();
        Ok((x >> shift).into())
    }

    fn set_point_to_value_if_zero<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
        value: Self::AcvmPoint<C>,
    ) -> eyre::Result<Self::AcvmPoint<C>> {
        if point.is_zero() {
            Ok(value)
        } else {
            Ok(point)
        }
    }
    fn sha256_compression(
        &mut self,
        state: &[Self::AcvmType; 8],
        message: &[Self::AcvmType; 16],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        let mut state_as_u32 = [0u32; 8];
        for (i, input) in state.iter().enumerate() {
            let x: BigUint = (*input).into();
            state_as_u32[i] = x.iter_u32_digits().next().unwrap_or_default();
        }
        let mut blocks = [0_u8; 64];
        for (i, input) in message.iter().enumerate() {
            let x: BigUint = (*input).into();
            let message_as_u32 = x.iter_u32_digits().next().unwrap_or_default();
            let bytes = message_as_u32.to_be_bytes();
            blocks[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        let blocks = blocks.into();
        sha2::compress256(&mut state_as_u32, &[blocks]);
        state_as_u32.iter().map(|x| Ok(F::from(*x))).collect()
    }

    fn sha256_get_overflow_bit(
        &mut self,
        input: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let mut sum: BigUint = input.into();
        let mask = BigUint::from(u64::MAX);
        sum &= mask;
        let normalized_sum = sum.iter_u32_digits().next().unwrap_or_default();
        Ok(Self::ArithmeticShare::from((sum - normalized_sum) >> 32))
    }

    fn slice_and_get_sparse_table_with_rotation_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: &[u64],
        _rotation: &[u32],
        _total_bitsize: usize,
        _base: u64,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_sparse_table_with_rotation_values not implemented for plaindriver and normally should not be called"
        );
    }

    fn slice_and_get_sparse_normalization_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _base_bits: &[u64],
        _base: u64,
        _total_output_bitlen_per_field: usize,
        _table_type: &SHA256Table,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_sparse_normalization_values not implemented for plaindriver and normally should not be called"
        );
    }

    fn blake2s_hash(
        &mut self,
        message_input: Vec<Self::AcvmType>,
        num_bits: &[usize],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        let mut real_input = Vec::new();
        for (inp, num_bits) in message_input.iter().zip(num_bits.iter()) {
            let num_elements = num_bits.div_ceil(8); // We need to round to the next byte
            let bytes = inp.into_bigint().to_bytes_le();
            real_input.extend_from_slice(&bytes[..num_elements])
        }
        let output_bytes: [u8; 32] = Blake2s256::digest(real_input).into();
        let result = output_bytes.into_iter().map(|x| F::from(x)).collect();
        Ok(result)
    }

    fn blake3_hash(
        &mut self,
        message_input: Vec<Self::AcvmType>,
        num_bits: &[usize],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        let mut real_input = Vec::new();
        for (inp, num_bits) in message_input.iter().zip(num_bits.iter()) {
            let num_elements = num_bits.div_ceil(8); // We need to round to the next byte
            let bytes = inp.into_bigint().to_bytes_le();
            real_input.extend_from_slice(&bytes[..num_elements])
        }
        let output_bytes: [u8; 32] = blake3::hash(&real_input).into();
        let result = output_bytes.into_iter().map(|x| F::from(x)).collect();
        Ok(result)
    }

    fn embedded_curve_add(
        &mut self,
        input1_x: Self::AcvmType,
        input1_y: Self::AcvmType,
        input1_infinite: Self::AcvmType,
        input2_x: Self::AcvmType,
        input2_y: Self::AcvmType,
        input2_infinite: Self::AcvmType,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        if input1_infinite > F::one() || input2_infinite > F::one() {
            eyre::bail!(
                "--pedantic-solving: is_infinity expected to be a bool, but found to be > 1"
            );
        }

        let input1_x = *downcast::<_, ark_bn254::Fr>(&input1_x).expect("We checked types");
        let input1_y = *downcast::<_, ark_bn254::Fr>(&input1_y).expect("We checked types");
        let input2_x = *downcast::<_, ark_bn254::Fr>(&input2_x).expect("We checked types");
        let input2_y = *downcast::<_, ark_bn254::Fr>(&input2_y).expect("We checked types");

        let point1 = Self::create_grumpkin_point(input1_x, input1_y, input1_infinite == F::one())?;

        let point2 = Self::create_grumpkin_point(input2_x, input2_y, input2_infinite == F::one())?;

        let add = point1 + point2;

        if let Some((out_x, out_y)) = add.into_affine().xy() {
            let out_x = *downcast(&out_x).expect("We checked types");
            let out_y = *downcast(&out_y).expect("We checked types");
            Ok((out_x, out_y, F::zero()))
        } else {
            Ok((F::zero(), F::zero(), F::one()))
        }
    }

    fn aes128_encrypt(
        &mut self,
        scalars: &[Self::AcvmType],
        iv: Vec<Self::AcvmType>,
        key: Vec<Self::AcvmType>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        let mut scalar_to_be_bytes = Vec::with_capacity(scalars.len());
        let mut iv_to_be_bytes = Vec::with_capacity(iv.len());
        let mut key_to_be_bytes = Vec::with_capacity(key.len());
        for inp in scalars {
            let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
            scalar_to_be_bytes.push(byte);
        }
        for inp in iv {
            let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
            iv_to_be_bytes.push(byte);
        }
        for inp in key {
            let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
            key_to_be_bytes.push(byte);
        }
        let cipher = Cipher::new_128(
            key_to_be_bytes
                .as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        );
        let encrypted = cipher.cbc_encrypt(&iv_to_be_bytes, &scalar_to_be_bytes);
        encrypted
            .into_iter()
            .map(|x| Ok(Self::AcvmType::from(x as u128)))
            .collect()
    }

    fn slice_and_get_aes_sparse_normalization_values_from_key(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _base_bits: &[u64],
        _base: u64,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_aes_sparse_normalization_values_from_key not implemented for plaindriver and normally should not be called"
        );
    }

    fn slice_and_get_aes_sbox_values_from_key(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _base_bits: &[u64],
        _base: u64,
        _sbox: &[u8],
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "slice_and_get_aes_sbox_values_from_key not implemented for plaindriver and normally should not be called"
        );
    }

    // I know this is not so nice, but the map_from_sparse_form needed here lives in the builder in utils. Keep in mind for future refactor
    fn accumulate_from_sparse_bytes(
        &mut self,
        _inputs: &[Self::AcvmType],
        _base: u64,
        _input_bitsize: usize,
        _output_bitsize: usize,
    ) -> eyre::Result<Self::AcvmType> {
        panic!(
            "accumulate_from_sparse_bytes not implemented for plaindriver and normally should not be called"
        );
    }
}
