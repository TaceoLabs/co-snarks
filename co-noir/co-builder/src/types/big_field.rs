use core::num;
use std::cmp::max;

use crate::prelude::{derive_generators, offset_generator};
use crate::types::field_ct::WitnessCT;
use crate::types::rom_ram::TwinRomTable;
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_bn254::Fq;
use ark_ec::CurveGroup;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::{One, PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::utils::Utils;
use num_bigint::BigUint;

use super::field_ct::BoolCT;

pub(crate) const NUM_LIMBS: usize = 4;

#[derive(Debug, Default, Clone)]
pub(crate) struct BigField<F: PrimeField> {
    pub(crate) binary_basis_limbs: [Limb<F>; NUM_LIMBS],
    pub(crate) prime_basis_limb: FieldCT<F>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Limb<F: PrimeField> {
    pub(crate) element: FieldCT<F>,
    pub(crate) maximum_value: BigUint,
}

impl<F: PrimeField> Limb<F> {
    pub(crate) fn new(input: FieldCT<F>, max: BigUint) -> Self {
        let maximum_value = if input.is_constant() {
            let maximum_value = input.additive_constant.into();
            assert!(maximum_value <= max);
            maximum_value
        } else {
            max
        };
        Limb {
            element: input,
            maximum_value,
        }
    }
}

impl<F: PrimeField> BigField<F> {
    pub(crate) const NUM_LIMB_BITS: u32 = 68;
    pub(crate) const NUM_LAST_LIMB_BITS: u32 = 50;

    /// Set the witness indices of the binary basis limbs to public
    ///
    /// Returns the public input index at which the representation of the BigField starts.
    pub(crate) fn set_public<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> usize {
        let start_index = builder.public_inputs.len();
        for limb in &self.binary_basis_limbs {
            let wtns_idx = limb.element.normalize(builder, driver).witness_index;
            builder.set_public_input(wtns_idx);
        }
        start_index
    }

    pub(crate) fn new_from_u256(value: BigUint) -> Self {
        let default_maximum_limb: BigUint = BigUint::from((1u128 << Self::NUM_LIMB_BITS) - 1);
        let limbs = [
            Limb::new(
                F::from(Utils::slice_u256(&value, 0, Self::NUM_LIMB_BITS as u64)).into(),
                default_maximum_limb.clone(),
            ),
            Limb::new(
                F::from(Utils::slice_u256(
                    &value,
                    Self::NUM_LIMB_BITS as u64,
                    (Self::NUM_LIMB_BITS * 2) as u64,
                ))
                .into(),
                default_maximum_limb.clone(),
            ),
            Limb::new(
                F::from(Utils::slice_u256(
                    &value,
                    (Self::NUM_LIMB_BITS * 2) as u64,
                    (Self::NUM_LIMB_BITS * 3) as u64,
                ))
                .into(),
                default_maximum_limb.clone(),
            ),
            Limb::new(
                F::from(Utils::slice_u256(
                    &value,
                    (Self::NUM_LIMB_BITS * 3) as u64,
                    (Self::NUM_LIMB_BITS * 4) as u64,
                ))
                .into(),
                default_maximum_limb.clone(),
            ),
        ];
        let prime_basis_limb = F::from(value).into();
        BigField {
            binary_basis_limbs: limbs,
            prime_basis_limb,
        }
    }

    #[expect(dead_code)]
    pub(crate) fn is_constant(&self) -> bool {
        self.prime_basis_limb.is_constant()
    }

    pub(crate) fn from_witness<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &T::AcvmType,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> eyre::Result<Self> {
        let [lo, hi]: [T::AcvmType; 2] = if T::is_shared(input) {
            let [lo, hi, _] = T::slice(
                driver,
                T::get_shared(input).expect("Already checked it is shared"),
                (Self::NUM_LIMB_BITS * 4) as u8,
                (Self::NUM_LIMB_BITS * 2) as u8,
                256,
            )?;
            [lo.into(), hi.into()]
        } else {
            let mut x: BigUint = T::get_public(input)
                .expect("Already checked it is public")
                .into();
            let msb = Self::NUM_LIMB_BITS * 4;
            let lsb = Self::NUM_LIMB_BITS * 2;
            let big_mask = (BigUint::from(1u64) << 256) - BigUint::one();
            let lo_mask = (BigUint::one() << lsb) - BigUint::one();
            let slice_mask = (BigUint::one() << ((msb - lsb) + 1)) - BigUint::one();

            x &= &big_mask;

            let lo = F::from(&x & lo_mask);
            let slice = F::from((x >> lsb) & slice_mask);
            [lo.into(), slice.into()]
        };
        let low = FieldCT::from_witness(lo, builder);
        let high = FieldCT::from_witness(hi, builder);
        Self::from_slices(low, high, driver, builder)
    }

    pub(crate) fn from_witness_other_acvm_type<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &T::OtherAcvmType<P>,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> eyre::Result<Self> {
        todo!();
    }

    pub(crate) fn from_slices<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        low_bits_in: FieldCT<F>,
        high_bits_in: FieldCT<F>,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> eyre::Result<Self> {
        assert_eq!(low_bits_in.is_constant(), high_bits_in.is_constant());

        let shift_1: F = F::from(BigUint::one() << Self::NUM_LIMB_BITS);
        let shift_2: F = F::from(BigUint::one() << (Self::NUM_LIMB_BITS * 2));
        let default_maximum_limb: BigUint =
            (BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one();
        let default_maximum_most_significant_limb: BigUint =
            (BigUint::one() << Self::NUM_LAST_LIMB_BITS) - BigUint::one();

        // we dont do these asserts
        // Check that the values of two parts are within specified bounds
        // assert!(low_bits_in.get_value() < (BigUint::one() << (NUM_LIMB_BITS * 2)));
        // assert!(high_bits_in.get_value() < (BigUint::one() << (NUM_LIMB_BITS * 2)));

        let mut limb_0 = FieldCT::default();
        let mut limb_1 = FieldCT::default();
        let mut limb_2 = FieldCT::default();
        let mut limb_3 = FieldCT::default();

        if !low_bits_in.is_constant() {
            // MERGE NOTE: this was the if constexpr block introduced in ecebe7643
            let low_bits_in_normalized = low_bits_in.get_normalized_witness_index(builder, driver);
            let limb_witnesses = builder.decompose_non_native_field_double_width_limb(
                low_bits_in_normalized,
                (2 * Self::NUM_LIMB_BITS) as usize,
            )?;
            limb_0.witness_index = limb_witnesses[0];
            limb_1.witness_index = limb_witnesses[1];
            let mul = FieldCT::multiply(&limb_1.neg(), &shift_1.into(), builder, driver)?;
            FieldCT::evaluate_linear_identity(
                &low_bits_in,
                &limb_0.neg(),
                &mul,
                &FieldCT::default(),
                builder,
                driver,
            );

            // // Enforce that low_bits_in indeed only contains 2*NUM_LIMB_BITS bits
            // low_accumulator = context->decompose_into_default_range(low_bits_in.witness_index,
            //                                                         static_cast<size_t>(NUM_LIMB_BITS * 2));
            // // If this doesn't hold we're using a default plookup range size that doesn't work well with the limb
            // size
            // // here
            // ASSERT(low_accumulator.size() % 2 == 0);
            // size_t mid_index = low_accumulator.size() / 2 - 1;
            // limb_0.witness_index = low_accumulator[mid_index]; // Q:safer to just slice this from low_bits_in?
            // limb_1 = (low_bits_in - limb_0) * shift_right_1;
        } else {
            let mut x: BigUint = low_bits_in.additive_constant.into();
            let msb = Self::NUM_LIMB_BITS * 2;
            let lsb = Self::NUM_LIMB_BITS;
            let big_mask = (BigUint::from(1u64) << 256) - BigUint::one();
            let lo_mask = (BigUint::one() << lsb) - BigUint::one();
            let slice_mask = (BigUint::one() << ((msb - lsb) + 1)) - BigUint::one();

            x &= &big_mask;

            let lo = F::from(&x & lo_mask);
            let slice = F::from((x >> lsb) & slice_mask);
            limb_0 = FieldCT::from_witness(lo.into(), builder);
            limb_1 = FieldCT::from_witness(slice.into(), builder);
        }

        // If we wish to continue working with this element with lazy reductions - i.e. not moding out again after each
        // addition we apply a more limited range - 2^s for smallest s such that p<2^s (this is the case can_overflow ==
        // false)

        // We create the high limb values similar to the low limb ones above
        let num_high_limb_bits = Self::NUM_LIMB_BITS + Self::NUM_LAST_LIMB_BITS;
        if !high_bits_in.is_constant() {
            let high_bits_in_normalized =
                high_bits_in.get_normalized_witness_index(builder, driver);
            let limb_witnesses = builder.decompose_non_native_field_double_width_limb(
                high_bits_in_normalized,
                num_high_limb_bits as usize,
            )?;
            limb_2.witness_index = limb_witnesses[0];
            limb_3.witness_index = limb_witnesses[1];
            let mul = FieldCT::multiply(&limb_3.neg(), &shift_1.into(), builder, driver)?;
            FieldCT::evaluate_linear_identity(
                &high_bits_in,
                &(limb_2.neg()),
                &mul,
                &FieldCT::default(),
                builder,
                driver,
            );
        } else {
            let mut x: BigUint = high_bits_in.additive_constant.into();
            let msb = num_high_limb_bits;
            let lsb = Self::NUM_LIMB_BITS;
            let big_mask = (BigUint::from(1u64) << 256) - BigUint::one();
            let lo_mask = (BigUint::one() << lsb) - BigUint::one();
            let slice_mask = (BigUint::one() << ((msb - lsb) + 1)) - BigUint::one();

            x &= &big_mask;

            let lo = F::from(&x & lo_mask);
            let slice = F::from((x >> lsb) & slice_mask);
            limb_2 = FieldCT::from_witness(lo.into(), builder);
            limb_3 = FieldCT::from_witness(slice.into(), builder);
        }

        let binary_basis_limbs = [
            Limb::new(limb_0.clone(), default_maximum_limb.clone()),
            Limb::new(limb_1.clone(), default_maximum_limb.clone()),
            Limb::new(limb_2.clone(), default_maximum_limb.clone()),
            Limb::new(limb_3.clone(), default_maximum_most_significant_limb),
        ];

        let mul = FieldCT::multiply(&high_bits_in, &shift_2.into(), builder, driver)?;
        let prime_basis_limb = FieldCT::add(&low_bits_in, &mul, builder, driver);

        // We dont do these tags, these are for debugging
        // auto new_tag = OriginTag(low_bits_in.tag, high_bits_in.tag);
        // set_origin_tag(new_tag);

        Ok(BigField {
            binary_basis_limbs,
            prime_basis_limb,
        })
    }

    pub(crate) fn convert_constant_to_fixed_witness<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        for limb in &mut self.binary_basis_limbs {
            limb.element
                .convert_constant_to_fixed_witness(builder, driver);
        }
        self.prime_basis_limb
            .convert_constant_to_fixed_witness(builder, driver);
    }
}
#[expect(dead_code)]
#[derive(Default)]
pub(crate) struct BigGroup<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) x: BigField<P::ScalarField>,
    pub(crate) y: BigField<P::ScalarField>,
    pub(crate) is_infinity: BoolCT<P, T>,
}
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> BigGroup<P, T> {
    #[expect(dead_code)]
    pub(crate) fn new(x: BigField<P::ScalarField>, y: BigField<P::ScalarField>) -> Self {
        BigGroup {
            x,
            y,
            is_infinity: BoolCT::<P, T>::from(false),
        }
    }

    pub(crate) fn get_value<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        driver: &mut T,
    ) -> eyre::Result<T::OtherAcvmType<P>> {
        let limb_values: Vec<T::AcvmType> = self
            .binary_basis_limbs
            .iter()
            .map(|limb| limb.element.get_value(builder, driver))
            .collect();
        driver.acvm_type_limbs_to_other_acvm_type::<P>(
            &limb_values
                .try_into()
                .expect("We provided NUM_LIMBS elements"),
        )
    }

    pub(crate) fn get_maximum_value(&self) -> BigUint {
        let mut result = BigUint::zero();
        let mut shift = BigUint::one();
        for i in 0..NUM_LIMBS {
            result += &self.binary_basis_limbs[i].maximum_value * &shift;
            shift <<= Self::NUM_LIMB_BITS;
        }
        result
    }

    // construct a proof that points are different mod p, when they are different mod r
    // WARNING: This method doesn't have perfect completeness - for points equal mod r (or with certain difference kp
    // mod r) but different mod p, you can't construct a proof. The chances of an honest prover running afoul of this
    // condition are extremely small (TODO: compute probability) Note also that the number of constraints depends on how
    // much the values have overflown beyond p e.g. due to an addition chain The function is based on the following.
    // Suppose a-b = 0 mod p. Then a-b = k*p for k in a range [-R,L] such that L*p>= a, R*p>=b. And also a-b = k*p mod r
    // for such k. Thus we can verify a-b is non-zero mod p by taking the product of such values (a-b-kp) and showing
    // it's non-zero mod r
    pub(crate) fn assert_is_not_equal<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // Why would we use this for 2 constants? Turns out, in biggroup
        // Helper function to count how many times modulus fits into maximum_value
        fn get_overload_count(maximum_value: &BigUint) -> usize {
            // TODO CESAR: Hardcoded for BN254 Fq
            let target_modulus: BigUint = Fq::MODULUS.into();
            let mut target = target_modulus.clone();
            let mut overload_count = 0;
            while &target <= maximum_value {
                overload_count += 1;
                target += target_modulus.clone();
            }
            overload_count
        }

        let lhs_overload_count = get_overload_count(&self.get_maximum_value());
        let rhs_overload_count = get_overload_count(&other.get_maximum_value());

        // if (a == b) then (a == b mod n)
        // to save gates, we only check that (a == b mod n)

        // if numeric val of a = a' + p.q
        // we want to check (a' + p.q == b mod n)
        let base_diff = FieldCT::sub(
            &self.prime_basis_limb,
            &other.prime_basis_limb,
            builder,
            driver,
        );
        let mut diff = base_diff.clone();

        // TODO CESAR: Is this even correct?
        let prime_basis =
            FieldCT::from_witness(P::ScalarField::from(Fq::MODULUS.into()).into(), builder);
        let mut prime_basis_accumulator = prime_basis.clone();

        // Each loop iteration adds 1 gate
        // (prime_basis and prime_basis accumulator are constant so only the * operator adds a gate)
        for _ in 0..lhs_overload_count {
            diff = diff.multiply(
                &base_diff.sub(&prime_basis_accumulator, builder, driver),
                builder,
                driver,
            )?;
            prime_basis_accumulator = prime_basis_accumulator.add(&prime_basis, builder, driver);
        }
        prime_basis_accumulator = prime_basis.clone();
        for _ in 0..rhs_overload_count {
            diff = diff.multiply(
                &base_diff.add(&prime_basis_accumulator, builder, driver),
                builder,
                driver,
            )?;
            prime_basis_accumulator = prime_basis_accumulator.add(&prime_basis, builder, driver);
        }
        diff.assert_is_not_zero(builder, driver)
    }

    pub(crate) fn sub<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn add<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn neg<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn div_without_denominator_check<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        numerators: &[BigField<F>],
        denominator: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        Self::internal_div(numerators, denominator, false, builder, driver)
    }

    // TODO CESAR: This is likely much slower than the bb version. Which works on integer types
    pub(crate) fn internal_div<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        numerators: &[BigField<F>],
        denominator: &BigField<F>,
        check_for_zero: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        if numerators.is_empty() {
            return Ok(BigField::default());
        }
        // TODO CESAR: Do we even need a reduction check?
        // denominator.reduction_check(builder, driver)?;

        let numerator_values = numerators
            .iter()
            .map(|n| n.get_value(driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let numerator_constant = numerators.iter().all(|n| n.is_constant());
        let numerator_sum = numerator_values
            .into_iter()
            .reduce(|a, b| driver.add_other_acvm_types::<P>(a, b))
            .expect("We checked numerators is not empty");

        // a / b = c
        // TODO CESAR: Handle zero case
        let denominator_value = denominator.get_value(driver)?;
        let inverse_value = driver.inverse_other_acvm_type::<P>(denominator_value);
        let result_value = driver.mul(numerator_sum, inverse_value);

        if numerator_constant && denominator.is_constant() {
            // TODO CESAR: Wrong
            return Ok(BigField::from_witness_other_acvm_type(
                result_value,
                driver,
                builder,
            ));
        }

        // TODO CESAR: WTF happens here

        // We do this after the quotient check, since this creates gates and we don't want to do this twice
        if (check_for_zero) {
            denominator.assert_is_not_equal(zero());
        }

        let quotient = BigField::from_witness_other_acvm_type(result_value, driver, builder)?;
        let inverse = BigField::from_witness_other_acvm_type(inverse_value, driver, builder)?;
        unsafe_evaluate_multiple_add(
            &denominator,
            &inverse,
            &BigField::default(), // TODO CESAR: Is this equivalent to unreduced_zero()?
            &quotient,
            &numerators,
            builder,
            driver,
        );
        return Ok(inverse);
    }

    pub(crate) fn unsafe_evaluate_multiple_add<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input_left: &BigField<F>,
        input_to_mul: &BigField<F>,
        to_add: &[BigField<F>],
        input_quotient: &BigField<F>,
        input_remainders: &[BigField<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn unsafe_evaluate_square_add<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        left: &BigField<F>,
        to_add: &[BigField<F>],
        quotient: &BigField<F>,
        remainders: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    /**
     * Compute a * a + ...to_add = b mod p
     *
     * We can chain multiple additions to a square/multiply with a single quotient/remainder.
     *
     * Chaining the additions here is cheaper than calling operator+ because we can combine some gates in
     *`evaluate_multiply_add`
     **/
    pub(crate) fn sqradd<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        to_add: &[BigField<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        // TODO CESAR: ASSERT(to_add.size() <= MAXIMUM_SUMMAND_COUNT);
        // TODO CESAR: reduction_check()?

        // TODO CESAR: reduction_check()?
        let add_values = to_add
            .iter()
            .map(|a| a.get_value(driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let add_sum = add_values
            .into_iter()
            .reduce(|a, b| driver.add_other_acvm_types::<P>(a, b))
            .expect("At least one element in to_add");
        let add_constant = to_add.iter().all(|a| a.is_constant());

        let self_value = self.get_value(driver)?;
        let mut left = self_value.clone();
        let mut right = self_value.clone();
        let mut add_right = add_sum;

        if self.is_constant() {
            if add_constant {
                let tmp = driver.mul_other_acvm_types::<P>(left, right);
                let tmp = driver.add_other_acvm_types::<P>(tmp, add_right);

                let (quotient, remainder) = driver.div_mod_other_acvm_type::<P>(tmp);

                // TODO CESAR: Wrong
                return Ok(BigField::from_witness_other_acvm_type(
                    remainder, driver, builder,
                ));
            } else {
                // left and right are constant
                let tmp = driver.mul_other_acvm_types::<P>(left, right);

                let (quotient, remainder) = driver.div_mod_other_acvm_type::<P>(tmp);

                let mut new_to_add = to_add.to_vec();
                new_to_add.push(BigField::from_witness_other_acvm_type(
                    remainder, driver, builder,
                )?);

                return Self::sum(&new_to_add, builder, driver);
            }
        }
        // TODO CESAR: Check the quotient fits the range proof
        // TODO CESAR: self_reduce()?
        let tmp = driver.mul_other_acvm_types::<P>(left, right);
        let tmp = driver.add_other_acvm_types::<P>(tmp, add_right);

        let (quotient, remainder) = driver.div_mod_other_acvm_type::<P>(tmp);

        // TODO CESAR: can_overflow?
        let quotient = BigField::from_witness_other_acvm_type(quotient, driver, builder)?;
        let remainder = BigField::from_witness_other_acvm_type(remainder, driver, builder)?;

        Self::unsafe_evaluate_square_add(self, &to_add, &quotient, &remainder, builder, driver)?;

        Ok(remainder)
    }

    /**
     * @brief Create constraints for summing these terms
     *
     * @tparam Builder
     * @tparam T
     * @param terms
     * @return The sum of terms
     */
    pub(crate) fn sum<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        terms: &[BigField<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn madd<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        to_mul: &BigField<F>,
        to_add: &[BigField<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    /**
     * multiply, subtract, divide.
     * This method computes:
     *
     * result = -(\sum{mul_left[i] * mul_right[i]} + ...to_add) / divisor
     *
     * Algorithm is constructed in this way to ensure that all computed terms are positive
     *
     * i.e. we evaluate:
     * result * divisor + (\sum{mul_left[i] * mul_right[i]) + ...to_add) = 0
     *
     * It is critical that ALL the terms on the LHS are positive to eliminate the possiblity of underflows
     * when calling `evaluate_multiple_multiply_add`
     *
     * only requires one quotient and remainder + overflow limbs
     *
     * We proxy this to mult_madd, so it only requires one quotient and remainder + overflow limbs
     **/
    pub(crate) fn msub_div<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        mul_left: &[BigField<F>],
        mul_right: &[BigField<F>],
        divisor: &BigField<F>,
        to_sub: &[BigField<F>],
        enable_divisor_nz_check: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        // Check the basics
        assert_eq!(mul_left.len(), mul_right.len());
        // ASSERT(divisor.get_value() != 0);

        let modulus: BigUint = Fq::MODULUS.into();
        let num_multiplications = mul_left.len();
        let mut product_native = T::OtherAcvmType::<P>::default();
        let mut products_constant = true;

        // This check is optional, because it is heavy and often we don't need it at all
        if enable_divisor_nz_check {
            divisor.assert_is_not_equal(&BigField::default::<P, T>(), builder, driver)?;
        }

        // Compute the sum of products
        for i in 0..num_multiplications {
            // Get the native values modulo the field modulus
            let mul_left_native = mul_left[i].get_value(driver)?.into();
            let mul_right_native = mul_right[i].get_value(driver)?.into();

            let tmp = driver.neg_other_acvm_type(mul_right_native);
            let tmp = driver.multiply_other_acvm_types::<P>(mul_left_native, tmp);
            product_native = driver.add_other_acvm_types::<P>(product_native, tmp);

            products_constant &= mul_left[i].is_constant() && mul_right[i].is_constant();
        }

        // Compute the sum of to_sub
        let mut sub_native = T::OtherAcvmType::<P>::default();
        let mut sub_constant = true;
        for sub in to_sub {
            let sub_value = sub.get_value(driver)?;
            sub_native = driver.add_other_acvm_types::<P>(sub_native, sub_value);
            sub_constant &= sub.is_constant();
        }

        let divisor_native = divisor.get_value(driver)?;

        // Compute the result
        let numerator_native = driver.sub_other_acvm_types(product_native, sub_native);
        let result_value = driver.div_other_acvm_types::<P>(numerator_native, divisor_native);

        // If everything is constant, then we just return the constant result
        if products_constant && sub_constant && divisor.is_constant() {
            // TODO CESAR: Wrong
            return Ok(BigField::from_witness_other_acvm_type(
                result_value,
                driver,
                builder,
            ));
        }

        // Create the result witness
        let result = BigField::from_witness_other_acvm_type(result_value, driver, builder)?;

        let eval_left = vec![result.clone()];
        let eval_right = vec![divisor.clone()];
        for e in mul_left {
            eval_left.push(e.clone());
        }
        for e in mul_right {
            eval_right.push(e.clone());
        }

        BigField::mult_madd(&eval_left, &eval_right, to_sub, true, builder, driver)?;
        Ok(result)
    }

    pub(crate) fn mult_madd<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        mul_left: &[BigField<F>],
        mul_right: &[BigField<F>],
        to_add: &[BigField<F>],
        fix_remainder_to_zero: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    // TODO CESAR: Batch FieldCT ops
    pub fn conditional_assign<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        predicate: &BoolCT<P, T>,
        lhs: &BigField<F>,
        rhs: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        if predicate.is_constant() && rhs.is_constant() && lhs.is_constant() {
            if predicate.get_value(driver) == P::ScalarField::ONE.into() {
                return Ok(lhs.clone());
            } else {
                return Ok(rhs.clone());
            }
        }

        let binary_limbs = (0..NUM_LIMBS)
            .map(|i| {
                predicate.to_field_ct(driver).madd(
                    &rhs.binary_basis_limbs[i].element.sub(
                        &lhs.binary_basis_limbs[i].element,
                        builder,
                        driver,
                    ),
                    &lhs.binary_basis_limbs[i].element,
                    builder,
                    driver,
                )
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let prime_basis_limb = predicate.to_field_ct(driver).madd(
            &rhs.prime_basis_limb
                .sub(&lhs.prime_basis_limb, builder, driver),
            &lhs.prime_basis_limb,
            builder,
            driver,
        )?;

        let binary_basis_limbs = (0..NUM_LIMBS)
            .map(|i| {
                Limb::new(
                    binary_limbs[i].clone(),
                    max(
                        lhs.binary_basis_limbs[i].maximum_value.clone(),
                        rhs.binary_basis_limbs[i].maximum_value.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        Ok(BigField {
            binary_basis_limbs: binary_basis_limbs
                .try_into()
                .expect("We provided NUM_LIMBS elements"),
            prime_basis_limb: prime_basis_limb,
        })
    }
}
