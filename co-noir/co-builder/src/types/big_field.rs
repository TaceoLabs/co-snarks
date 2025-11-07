use std::cmp::max;

use crate::types::field_ct::WitnessCT;
use crate::types::types::{AddQuad, NonNativeFieldWitnesses};
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_bn254::Fq;
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::utils::Utils;
use num_bigint::BigUint;

use super::field_ct::BoolCT;

pub(crate) const NUM_LIMBS: usize = 4;
pub(crate) const NUM_LIMB_BITS: usize = 68;
pub(crate) const DEFAULT_MAXIMUM_LIMB: u128 = (1 << NUM_LIMB_BITS) - 1;
pub(crate) const MAXIMUM_SUMMAND_COUNT: usize = 16;

#[derive(Debug, Default, Clone)]
pub struct BigField<F: PrimeField> {
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
    pub(crate) const NUM_BN254_SCALARS: u32 = 2;

    /// Set the witness indices of the binary basis limbs to public
    ///
    /// Returns the public input index at which the representation of the BigField starts.
    pub(crate) fn set_public<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
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

    pub(crate) fn is_constant(&self) -> bool {
        self.prime_basis_limb.is_constant()
    }

    pub(crate) fn from_witness<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
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

    pub(crate) fn from_constant(value: &BigUint) -> Self {
        let mut limbs = Vec::with_capacity(NUM_LIMBS);
        let mut shift = 0;
        for _ in 0..NUM_LIMBS {
            let limb_value =
                (value >> shift) & ((BigUint::one() << NUM_LIMB_BITS) - BigUint::one());
            let limb_ct = FieldCT::from(F::from(limb_value));
            limbs.push(Limb::new(
                limb_ct,
                (BigUint::one() << NUM_LIMB_BITS) - BigUint::one(),
            ));
            shift += NUM_LIMB_BITS;
        }

        let prime_limb_ct = FieldCT::from(F::from(value.clone()));

        BigField {
            binary_basis_limbs: [
                limbs[0].clone(),
                limbs[1].clone(),
                limbs[2].clone(),
                limbs[3].clone(),
            ],
            prime_basis_limb: prime_limb_ct,
        }
    }

    /**
     * ORIGINAL FUNCTION NAME: `create_from_u256_witness`
     * @brief Creates a bigfield element from a uint512_t.
     * Bigfield element is constructed as a witness and not a circuit constant
     *
     * @param ctx
     * @param value
     * @param can_overflow Can the input value have more than log2(modulus) bits?
     * @param maximum_bitlength Provide the explicit maximum bitlength if known. Otherwise bigfield max value will be
     * either log2(modulus) bits iff can_overflow = false, or (4 * NUM_LIMB_BITS) iff can_overflow = true
     * @return bigfield<Builder, T>
     *
     * @details This method is 1 gate more efficient than constructing from 2 field_ct elements.
     */
    pub(crate) fn from_witness_other_acvm_type<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        input: &T::OtherAcvmType<P>,
        can_overflow: bool,
        maximum_bitlength: usize,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> eyre::Result<Self> {
        assert!(
            (can_overflow && maximum_bitlength == 0)
                || (!can_overflow
                    && (maximum_bitlength == 0 || maximum_bitlength > (3 * NUM_LIMB_BITS)))
        );

        let limbs = driver.other_acvm_type_to_acvm_type_limbs::<P>(input)?;

        // UltraFlavor has plookup
        let mut limbs_ct = (0..NUM_LIMBS)
            .map(|i| FieldCT::default())
            .collect::<Vec<FieldCT<F>>>();

        for (i, limb) in limbs.iter().enumerate() {
            limbs_ct[i].witness_index = builder.add_variable(limb.clone());
        }
        let mut prime_limb = FieldCT::default();

        let shift_1 = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift_2 = BigUint::from(1u64) << (NUM_LIMB_BITS * 2);
        let shift_3 = BigUint::from(1u64) << (NUM_LIMB_BITS * 3);
        let tmp = driver.mul_many(
            &limbs,
            &[
                BigUint::one(),
                shift_1.clone(),
                shift_2.clone(),
                shift_3.clone(),
            ]
            .map(F::from)
            .map(Into::into),
        )?;
        prime_limb.witness_index = builder.add_variable(
            tmp.into_iter()
                .reduce(|a, b| driver.add(a, b))
                .expect("At least one element"),
        );

        let [a, b, c, d, limb_0_witness_index] = [
            limbs_ct[1].get_normalized_witness_index(builder, driver),
            limbs_ct[2].get_normalized_witness_index(builder, driver),
            limbs_ct[3].get_normalized_witness_index(builder, driver),
            prime_limb.get_normalized_witness_index(builder, driver),
            limbs_ct[0].get_normalized_witness_index(builder, driver),
        ];

        // evaluate prime basis limb with addition gate that taps into the 4th wire in the next gate
        builder.create_big_add_gate(
            &AddQuad {
                a,
                b,
                c,
                d,
                a_scaling: F::from(shift_1),
                b_scaling: F::from(shift_2),
                c_scaling: F::from(shift_3),
                d_scaling: -F::one(),
                const_scaling: F::zero(),
            },
            true,
        );

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/879): dummy necessary for preceeding big add
        // gate
        GenericUltraCircuitBuilder::<P, T>::create_dummy_gate(
            &mut builder.blocks.arithmetic,
            builder.zero_idx,
            builder.zero_idx,
            builder.zero_idx,
            limb_0_witness_index,
        );

        let mut num_last_limb_bits = if can_overflow {
            NUM_LIMB_BITS
        } else {
            (F::MODULUS_BIT_SIZE - (NUM_LIMB_BITS * 3) as u32) as usize
        };

        let mut result = BigField::default();
        for i in 0..(NUM_LIMBS - 1) {
            result.binary_basis_limbs[i] =
                Limb::new(limbs_ct[i].clone(), BigUint::from(DEFAULT_MAXIMUM_LIMB));
        }
        let default_maximum_most_significant_limb: BigUint =
            (BigUint::one() << num_last_limb_bits) - BigUint::one();
        result.binary_basis_limbs[NUM_LIMBS - 1] = Limb::new(
            limbs_ct[NUM_LIMBS - 1].clone(),
            if can_overflow {
                BigUint::from(DEFAULT_MAXIMUM_LIMB)
            } else {
                default_maximum_most_significant_limb
            },
        );

        // if maximum_bitlength is set, this supercedes can_overflow
        if maximum_bitlength > 0 {
            num_last_limb_bits = maximum_bitlength - (NUM_LIMB_BITS * 3);
            let max_limb_value = (BigUint::one() << num_last_limb_bits) - BigUint::one();
            result.binary_basis_limbs[NUM_LIMBS - 1].maximum_value = max_limb_value;
        }

        result.prime_basis_limb = prime_limb;
        builder.range_constrain_two_limbs(limb_0_witness_index, a, NUM_LIMB_BITS, NUM_LIMB_BITS)?;

        builder.range_constrain_two_limbs(b, c, NUM_LIMB_BITS, num_last_limb_bits)?;
        Ok(result)
    }

    pub fn from_slices<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
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

    /**
     * @brief Construct a bigfield element from binary limbs and a prime basis limb that are already reduced
     *
     * @details This API should only be used by bigfield and other stdlib members for efficiency and with extreme care.
     * We need it in cases where we precompute and reduce the elements, for example, and then put them in a table
     *
     */
    pub(crate) fn unsafe_construct_from_limbs(
        a: &FieldCT<F>,
        b: &FieldCT<F>,
        c: &FieldCT<F>,
        d: &FieldCT<F>,
        prime_limb: &FieldCT<F>,
        can_overflow: bool,
    ) -> Self {
        assert!(
            a.is_constant() == b.is_constant()
                && b.is_constant() == c.is_constant()
                && c.is_constant() == d.is_constant()
                && d.is_constant() == prime_limb.is_constant()
        );

        let mut result = BigField::default();
        result.binary_basis_limbs[0] = Limb::new(a.clone(), BigUint::from(DEFAULT_MAXIMUM_LIMB));
        result.binary_basis_limbs[1] = Limb::new(b.clone(), BigUint::from(DEFAULT_MAXIMUM_LIMB));
        result.binary_basis_limbs[2] = Limb::new(c.clone(), BigUint::from(DEFAULT_MAXIMUM_LIMB));
        result.binary_basis_limbs[3] = Limb::new(
            d.clone(),
            if can_overflow {
                BigUint::from(DEFAULT_MAXIMUM_LIMB)
            } else {
                (BigUint::one() << Self::NUM_LAST_LIMB_BITS) - BigUint::one()
            },
        );
        result.prime_basis_limb = prime_limb.clone();
        result
    }

    pub(crate) fn get_value<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
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
        T: NoirWitnessExtensionProtocol<F>,
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
        let modulus: BigUint = Fq::MODULUS.into();
        let prime_basis = FieldCT::from_witness(F::from(modulus).into(), builder);
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

    /**
     * @brief Validate whether two bigfield elements are equal to each other
     * @details To evaluate whether `(a == b)`, we use result boolean `r` to evaluate the following logic:
     *          (n.b all algebra involving bigfield elements is done in the bigfield)
     *              1. If `r == 1` , `a - b == 0`
     *              2. If `r == 0`, `a - b` posesses an inverse `I` i.e. `(a - b) * I - 1 == 0`
     *          We efficiently evaluate this logic by evaluating a single expression `(a - b)*X = Y`
     *          We use conditional assignment logic to define `X, Y` to be the following:
     *              If `r == 1` then `X = 1, Y = 0`
     *              If `r == 0` then `X = I, Y = 1`
     *          This allows us to evaluate `operator==` using only 1 bigfield multiplication operation.
     *          We can check the product equals 0 or 1 by directly evaluating the binary basis/prime basis limbs of Y.
     *          i.e. if `r == 1` then `(a - b)*X` should have 0 for all limb values
     *               if `r == 0` then `(a - b)*X` should have 1 in the least significant binary basis limb and 0
     * elsewhere
     * @tparam Builder
     * @tparam T
     * @param other
     * @return bool_t<Builder>
     */
    pub(crate) fn equals<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BoolCT<F, T>> {
        let lhs = self.get_value(builder, driver)?;
        let rhs = other.get_value(builder, driver)?;
        let is_equal_raw = driver.equals_other_acvm_type(&lhs, &rhs)?;
        let is_equal =
            BoolCT::from_witness_ct(WitnessCT::from_acvm_type(is_equal_raw, builder), builder);

        let diff = self.sub(other, builder, driver)?;
        let diff_native = diff.get_value(builder, driver)?;

        // TODO CESAR: Handle zero case
        let inverse_native = driver.inverse_other_acvm_type(diff_native)?;
        let inverse = BigField::from_witness_other_acvm_type::<P, T>(
            &inverse_native,
            false,
            0,
            driver,
            builder,
        )?;
        let multiplicand = BigField::conditional_select(
            &is_equal,
            &BigField::from_constant(&BigUint::one()),
            &inverse,
            builder,
            driver,
        )?;

        let product = diff.mul(&multiplicand, builder, driver)?;

        let result = FieldCT::conditional_assign(
            &is_equal,
            &FieldCT::from(F::zero()),
            &FieldCT::from(F::one()),
            builder,
            driver,
        )?;

        product
            .prime_basis_limb
            .assert_equal(&result, builder, driver);
        product.binary_basis_limbs[0]
            .element
            .assert_equal(&result, builder, driver);
        for i in 1..NUM_LIMBS {
            product.binary_basis_limbs[i].element.assert_equal(
                &FieldCT::from(F::zero()),
                builder,
                driver,
            );
        }

        Ok(is_equal)
    }

    pub(crate) fn add<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        // TODO CESAR: reduction_check()?

        if self.is_constant() && other.is_constant() {
            let mut result_value = self.get_value(builder, driver)?;
            let other_value = other.get_value(builder, driver)?;
            result_value = driver.add_other_acvm_types(&result_value, &other_value);

            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        let mut result = self.clone();
        result.binary_basis_limbs[0].element.add_assign(
            &other.binary_basis_limbs[0].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[1].element.add_assign(
            &other.binary_basis_limbs[1].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[2].element.add_assign(
            &other.binary_basis_limbs[2].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[3].element.add_assign(
            &other.binary_basis_limbs[3].element,
            builder,
            driver,
        );

        // UltraFlavor has plookup
        if self.prime_basis_limb.multiplicative_constant == F::one()
            && other.prime_basis_limb.multiplicative_constant == F::one()
            && !self.is_constant()
            && !other.is_constant()
        {
            // We are checking if this is and identical element, so we need to compare the actual indices, not normalized ones
            let limbconst = result.binary_basis_limbs[0].element.is_constant()
                || result.binary_basis_limbs[1].element.is_constant()
                || result.binary_basis_limbs[2].element.is_constant()
                || result.binary_basis_limbs[3].element.is_constant()
                || self.prime_basis_limb.is_constant()
                || other.binary_basis_limbs[0].element.is_constant()
                || other.binary_basis_limbs[1].element.is_constant()
                || other.binary_basis_limbs[2].element.is_constant()
                || other.binary_basis_limbs[3].element.is_constant()
                || other.prime_basis_limb.is_constant()
                || (self.prime_basis_limb.witness_index == other.prime_basis_limb.witness_index);
            if !limbconst {
                let x0 = (
                    result.binary_basis_limbs[0].element.witness_index,
                    result.binary_basis_limbs[0].element.multiplicative_constant,
                );
                let x1 = (
                    result.binary_basis_limbs[1].element.witness_index,
                    result.binary_basis_limbs[1].element.multiplicative_constant,
                );
                let x2 = (
                    result.binary_basis_limbs[2].element.witness_index,
                    result.binary_basis_limbs[2].element.multiplicative_constant,
                );
                let x3 = (
                    result.binary_basis_limbs[3].element.witness_index,
                    result.binary_basis_limbs[3].element.multiplicative_constant,
                );

                let y0 = (
                    other.binary_basis_limbs[0].element.witness_index,
                    other.binary_basis_limbs[0].element.multiplicative_constant,
                );
                let y1 = (
                    other.binary_basis_limbs[1].element.witness_index,
                    other.binary_basis_limbs[1].element.multiplicative_constant,
                );
                let y2 = (
                    other.binary_basis_limbs[2].element.witness_index,
                    other.binary_basis_limbs[2].element.multiplicative_constant,
                );
                let y3 = (
                    other.binary_basis_limbs[3].element.witness_index,
                    other.binary_basis_limbs[3].element.multiplicative_constant,
                );

                let c0 = result.binary_basis_limbs[0].element.additive_constant
                    - other.binary_basis_limbs[0].element.additive_constant;
                let c1 = result.binary_basis_limbs[1].element.additive_constant
                    - other.binary_basis_limbs[1].element.additive_constant;
                let c2 = result.binary_basis_limbs[2].element.additive_constant
                    - other.binary_basis_limbs[2].element.additive_constant;
                let c3 = result.binary_basis_limbs[3].element.additive_constant
                    - other.binary_basis_limbs[3].element.additive_constant;

                let xp = self.prime_basis_limb.witness_index;
                let yp = other.prime_basis_limb.witness_index;
                let cp = result.prime_basis_limb.additive_constant
                    + other.prime_basis_limb.additive_constant;
                let output_witness = builder.evaluate_non_native_field_addition(
                    (x0, y0, c0),
                    (x1, y1, c1),
                    (x2, y2, c2),
                    (x3, y3, c3),
                    (xp, yp, cp),
                    driver,
                )?;

                result.binary_basis_limbs[0].element =
                    FieldCT::from_witness_index(output_witness[0]);
                result.binary_basis_limbs[1].element =
                    FieldCT::from_witness_index(output_witness[1]);
                result.binary_basis_limbs[2].element =
                    FieldCT::from_witness_index(output_witness[2]);
                result.binary_basis_limbs[3].element =
                    FieldCT::from_witness_index(output_witness[3]);
                result.prime_basis_limb = FieldCT::from_witness_index(output_witness[4]);
                return Ok(result);
            }
        }
        result.binary_basis_limbs[0].element.add_assign(
            &other.binary_basis_limbs[0].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[1].element.add_assign(
            &other.binary_basis_limbs[1].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[2].element.add_assign(
            &other.binary_basis_limbs[2].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[3].element.add_assign(
            &other.binary_basis_limbs[3].element,
            builder,
            driver,
        );
        result
            .prime_basis_limb
            .add_assign(&other.prime_basis_limb, builder, driver);
        Ok(result)
    }

    // TODO CESAR: Makes this smaller
    pub(crate) fn sub<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        // TODO CESAR: reduction_check()?

        if self.is_constant() && other.is_constant() {
            let mut result_value = self.get_value(builder, driver)?;
            let other_value = other.get_value(builder, driver)?;
            result_value = driver.sub_other_acvm_types::<P>(result_value, other_value);

            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        // TODO CESAR: other.is_constant() case

        // Plookup bigfield subtraction
        //
        // We have a special addition gate we can toggle, that will compute: (w_1 + w_4 - w_4_omega + q_arith = 0)
        // This is in addition to the regular addition gate
        //
        // We can arrange our wires in memory like this:
        //
        //   |  1  |  2  |  3  |  4  |
        //   |-----|-----|-----|-----|
        //   | b.p | a.0 | b.0 | c.p | (b.p + c.p - a.p = 0) AND (a.0 - b.0 - c.0 = 0)
        //   | a.p | a.1 | b.1 | c.0 | (a.1 - b.1 - c.1 = 0)
        //   | a.2 | b.2 | c.2 | c.1 | (a.2 - b.2 - c.2 = 0)
        //   | a.3 | b.3 | c.3 | --- | (a.3 - b.3 - c.3 = 0)
        //

        // Step 1: For each limb compute the MAXIMUM value we will have to borrow from the next significant limb
        //
        // i.e. if we assume that `*this = 0` and `other = other.maximum_value`, how many bits do we need to borrow from
        // the next significant limb to ensure each limb value is positive?
        //
        // N.B. for this segment `maximum_value` really refers to maximum NEGATIVE value of the result

        let limb_0_maximum_value = other.binary_basis_limbs[0].maximum_value.clone();

        // Compute maximum shift factor for limb_0
        let limb_0_borrow_shift = std::cmp::max(
            limb_0_maximum_value.bits() as u32, // get_msb() + 1
            Self::NUM_LIMB_BITS,
        );

        // Compute the maximum negative value of limb_1, including the bits limb_0 may need to borrow
        let limb_1_maximum_value = &other.binary_basis_limbs[1].maximum_value
            + (BigUint::one() << (limb_0_borrow_shift - Self::NUM_LIMB_BITS));

        // repeat the above for the remaining limbs
        let limb_1_borrow_shift =
            std::cmp::max(limb_1_maximum_value.bits() as u32, Self::NUM_LIMB_BITS);

        let limb_2_maximum_value = &other.binary_basis_limbs[2].maximum_value
            + (BigUint::one() << (limb_1_borrow_shift - Self::NUM_LIMB_BITS));
        let limb_2_borrow_shift =
            std::cmp::max(limb_2_maximum_value.bits() as u32, Self::NUM_LIMB_BITS);

        let limb_3_maximum_value = &other.binary_basis_limbs[3].maximum_value
            + (BigUint::one() << (limb_2_borrow_shift - Self::NUM_LIMB_BITS));

        // Step 2: Compute the constant value `X = m * p` we must add to the result to ensure EVERY limb is >= 0
        //
        // We need to find a value `X` where `X.limb[3] > limb_3_maximum_value`.
        // As long as the above holds, we can borrow bits from X.limb[3] to ensure less significant limbs are positive
        //
        // Start by setting constant_to_add = p
        let modulus: BigUint = Fq::MODULUS.into();
        let mut constant_to_add = modulus.clone();
        // add a large enough multiple of p to not get negative result in subtraction
        // TODO CESAR: Check whether this is correct
        while {
            // Get the 4th limb (most significant) using .to_bytes_be
            let bytes = constant_to_add.to_bytes_be();
            // Calculate the starting and ending bit positions for the 4th limb
            let start_bit = (Self::NUM_LIMB_BITS * 3) as usize;
            let end_bit = (Self::NUM_LIMB_BITS * 4) as usize;
            // Convert bytes to BigUint, then shift and mask to get the limb value
            let total_bits = constant_to_add.bits() as usize;
            let mut limb_3 = BigUint::zero();
            if total_bits > start_bit {
                let shifted = &constant_to_add >> start_bit;
                let mask = (BigUint::one() << (end_bit - start_bit)) - BigUint::one();
                limb_3 = &shifted & &mask;
            }
            limb_3 <= limb_3_maximum_value
        } {
            constant_to_add += modulus.clone();
        }

        // Step 3: Compute offset terms t0, t1, t2, t3 that we add to our result to ensure each limb is positive
        //
        // t3 represents the value we are BORROWING from constant_to_add.limb[3]
        // t2, t1, t0 are the terms we will ADD to constant_to_add.limb[2], constant_to_add.limb[1],
        // constant_to_add.limb[0]
        //
        // i.e. The net value we add to `constant_to_add` is 0. We must ensure that:
        // t3 = t0 + (t1 << NUM_LIMB_BITS) + (t2 << NUM_LIMB_BITS * 2)
        //
        // e.g. the value we borrow to produce t0 is subtracted from t1,
        //      the value we borrow from t1 is subtracted from t2
        //      the value we borrow from t2 is equal to t3
        let t0 = BigUint::one() << limb_0_borrow_shift;
        let t1 = (BigUint::one() << limb_1_borrow_shift)
            - (BigUint::one() << (limb_0_borrow_shift - Self::NUM_LIMB_BITS));
        let t2 = (BigUint::one() << limb_2_borrow_shift)
            - (BigUint::one() << (limb_1_borrow_shift - Self::NUM_LIMB_BITS));
        let t3 = BigUint::one() << (limb_2_borrow_shift - Self::NUM_LIMB_BITS);

        // Compute the limbs of `constant_to_add`, including our offset terms t0, t1, t2, t3 that ensure each result limb is positive
        let to_add_0 = constant_to_add.clone()
            & (((BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one()) + &t0);
        let to_add_1 = ((constant_to_add.clone() >> Self::NUM_LIMB_BITS)
            & ((BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one()))
            + &t1;
        let to_add_2 = ((constant_to_add.clone() >> (Self::NUM_LIMB_BITS * 2))
            & ((BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one()))
            + &t2;
        let to_add_3 = ((constant_to_add.clone() >> (Self::NUM_LIMB_BITS * 3))
            & ((BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one()))
            - &t3;

        // Update the maximum possible value of the result. We assume here that (*this.value) = 0
        let mut result = self.clone();
        result.binary_basis_limbs[0].maximum_value += &to_add_0;
        result.binary_basis_limbs[1].maximum_value += &to_add_1;
        result.binary_basis_limbs[2].maximum_value += &to_add_2;
        result.binary_basis_limbs[3].maximum_value += &to_add_3;

        // Convert to_add_i to FieldCT and add to each limb
        let to_add_0 = FieldCT::from_witness(F::from(to_add_0).into(), builder);
        let to_add_1 = FieldCT::from_witness(F::from(to_add_1).into(), builder);
        let to_add_2 = FieldCT::from_witness(F::from(to_add_2).into(), builder);
        let to_add_3 = FieldCT::from_witness(F::from(to_add_3).into(), builder);

        // Compute the binary basis limbs of our result
        result.binary_basis_limbs[0].element = self.binary_basis_limbs[0]
            .element
            .add(&to_add_0, builder, driver);
        result.binary_basis_limbs[1].element = self.binary_basis_limbs[1]
            .element
            .add(&to_add_1, builder, driver);
        result.binary_basis_limbs[2].element = self.binary_basis_limbs[2]
            .element
            .add(&to_add_2, builder, driver);
        result.binary_basis_limbs[3].element = self.binary_basis_limbs[3]
            .element
            .add(&to_add_3, builder, driver);

        // UltraFlavor has plookup
        if self.prime_basis_limb.multiplicative_constant == F::one()
            && other.prime_basis_limb.multiplicative_constant == F::one()
            && !self.is_constant()
            && !other.is_constant()
        {
            // We are checking if this is and identical element, so we need to compare the actual indices, not normalized ones
            let limbconst = result.binary_basis_limbs[0].element.is_constant()
                || result.binary_basis_limbs[1].element.is_constant()
                || result.binary_basis_limbs[2].element.is_constant()
                || result.binary_basis_limbs[3].element.is_constant()
                || self.prime_basis_limb.is_constant()
                || other.binary_basis_limbs[0].element.is_constant()
                || other.binary_basis_limbs[1].element.is_constant()
                || other.binary_basis_limbs[2].element.is_constant()
                || other.binary_basis_limbs[3].element.is_constant()
                || other.prime_basis_limb.is_constant()
                || (self.prime_basis_limb.witness_index == other.prime_basis_limb.witness_index);
            if !limbconst {
                let x0 = (
                    result.binary_basis_limbs[0].element.witness_index,
                    result.binary_basis_limbs[0].element.multiplicative_constant,
                );
                let x1 = (
                    result.binary_basis_limbs[1].element.witness_index,
                    result.binary_basis_limbs[1].element.multiplicative_constant,
                );
                let x2 = (
                    result.binary_basis_limbs[2].element.witness_index,
                    result.binary_basis_limbs[2].element.multiplicative_constant,
                );
                let x3 = (
                    result.binary_basis_limbs[3].element.witness_index,
                    result.binary_basis_limbs[3].element.multiplicative_constant,
                );

                let y0 = (
                    other.binary_basis_limbs[0].element.witness_index,
                    other.binary_basis_limbs[0].element.multiplicative_constant,
                );
                let y1 = (
                    other.binary_basis_limbs[1].element.witness_index,
                    other.binary_basis_limbs[1].element.multiplicative_constant,
                );
                let y2 = (
                    other.binary_basis_limbs[2].element.witness_index,
                    other.binary_basis_limbs[2].element.multiplicative_constant,
                );
                let y3 = (
                    other.binary_basis_limbs[3].element.witness_index,
                    other.binary_basis_limbs[3].element.multiplicative_constant,
                );

                let c0 = result.binary_basis_limbs[0].element.additive_constant
                    - other.binary_basis_limbs[0].element.additive_constant;
                let c1 = result.binary_basis_limbs[1].element.additive_constant
                    - other.binary_basis_limbs[1].element.additive_constant;
                let c2 = result.binary_basis_limbs[2].element.additive_constant
                    - other.binary_basis_limbs[2].element.additive_constant;
                let c3 = result.binary_basis_limbs[3].element.additive_constant
                    - other.binary_basis_limbs[3].element.additive_constant;

                let xp = self.prime_basis_limb.witness_index;
                let yp = other.prime_basis_limb.witness_index;

                // TODO CESAR: Is this even correct?
                let constant_to_add_mod_p = constant_to_add % F::MODULUS.into();
                let cp = self.prime_basis_limb.additive_constant
                    - other.prime_basis_limb.additive_constant
                    + F::from(constant_to_add_mod_p);

                let output_witness = builder.evaluate_non_native_field_subtraction(
                    (x0, y0, c0),
                    (x1, y1, c1),
                    (x2, y2, c2),
                    (x3, y3, c3),
                    (xp, yp, cp),
                    driver,
                )?;

                result.binary_basis_limbs[0].element =
                    FieldCT::from_witness_index(output_witness[0]);
                result.binary_basis_limbs[1].element =
                    FieldCT::from_witness_index(output_witness[1]);
                result.binary_basis_limbs[2].element =
                    FieldCT::from_witness_index(output_witness[2]);
                result.binary_basis_limbs[3].element =
                    FieldCT::from_witness_index(output_witness[3]);
                result.prime_basis_limb = FieldCT::from_witness_index(output_witness[4]);
                return Ok(result);
            }
        }

        // Subtract each limb's element
        result.binary_basis_limbs[0].element = result.binary_basis_limbs[0].element.sub(
            &other.binary_basis_limbs[0].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[1].element = result.binary_basis_limbs[1].element.sub(
            &other.binary_basis_limbs[1].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[2].element = result.binary_basis_limbs[2].element.sub(
            &other.binary_basis_limbs[2].element,
            builder,
            driver,
        );
        result.binary_basis_limbs[3].element = result.binary_basis_limbs[3].element.sub(
            &other.binary_basis_limbs[3].element,
            builder,
            driver,
        );

        // Compute the prime basis limb of the result
        let constant_to_add_mod_p = &constant_to_add % F::MODULUS.into();
        let prime_basis_to_add =
            FieldCT::from_witness(F::from(constant_to_add_mod_p).into(), builder);
        result.prime_basis_limb = result
            .prime_basis_limb
            .add(&prime_basis_to_add, builder, driver);
        result.prime_basis_limb =
            result
                .prime_basis_limb
                .sub(&other.prime_basis_limb, builder, driver);

        Ok(result)
    }

    pub(crate) fn mul<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        // TODO CESAR: reduction_check()?

        // Now we can actually compute the quotienet and remainder values
        let (quotient_value, remainder_value) = {
            let lhs_value = self.get_value(builder, driver)?;
            let rhs_value = other.get_value(builder, driver)?;
            driver.compute_quotient_remainder_values(&lhs_value, &rhs_value, &[])?
        };

        if self.is_constant() && other.is_constant() {
            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&remainder_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        // when writing a*b = q*p + r we wish to enforce r<2^s for smallest s such that p<2^s
        // hence the second constructor call is with can_overflow=false. This will allow using r in more additions
        // mod 2^t without needing to apply the mod, where t=4*NUM_LIMB_BITS

        // Check if the product overflows CRT or the quotient can't be contained in a range proof and reduce
        // accordingly
        // TODO CESAR: WTF happens here

        let quotient =
            BigField::from_witness_other_acvm_type(&quotient_value, true, 0, driver, builder)?;
        let remainder = BigField::from_witness_other_acvm_type(
            &remainder_value,
            false,
            4 * Self::NUM_LIMB_BITS as usize,
            driver,
            builder,
        )?;

        // Call `evaluate_multiply_add` to validate the correctness of our computed quotient and remainder
        Self::unsafe_evaluate_multiply_add(
            self,
            other,
            &[],
            &quotient,
            std::slice::from_ref(&remainder),
            builder,
            driver,
        )?;

        Ok(remainder)
    }

    pub(crate) fn neg<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        BigField::default().sub(self, builder, driver)
    }

    pub(crate) fn div_without_denominator_check<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
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
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
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
            .map(|n| n.get_value(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let numerator_constant = numerators.iter().all(|n| n.is_constant());
        let numerator_sum = numerator_values
            .into_iter()
            .reduce(|a, b| driver.add_other_acvm_types(&a, &b))
            .expect("We checked numerators is not empty");

        // a / b = c
        // TODO CESAR: Handle zero case
        let denominator_value = denominator.get_value(builder, driver)?;
        let inverse_value = driver.inverse_other_acvm_type::<P>(denominator_value)?;
        let result_value = driver.mul_other_acvm_types(&numerator_sum, &inverse_value)?;

        if numerator_constant && denominator.is_constant() {
            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        // TODO CESAR: WTF happens here

        // We do this after the quotient check, since this creates gates and we don't want to do this twice
        if check_for_zero {
            denominator.assert_is_not_equal(&BigField::default(), builder, driver)?;
        }

        // TODO CESAR: Set can_overflow and num_quotient_bits properly
        let quotient =
            BigField::from_witness_other_acvm_type(&result_value, true, 0, driver, builder)?;
        let inverse =
            BigField::from_witness_other_acvm_type(&inverse_value, true, 0, driver, builder)?;
        Self::unsafe_evaluate_multiply_add(
            &denominator,
            &inverse,
            &[BigField::default()], // TODO CESAR: Is this equivalent to unreduced_zero()?
            &quotient,
            &numerators,
            builder,
            driver,
        )?;
        Ok(inverse)
    }

    /**
     * Evaluate a multiply add identity with several added elements and several remainders
     *
     * i.e:
     *
     * input_left*input_to_mul + (to_add[0]..to_add[-1]) - input_quotient*modulus -
     * (input_remainders[0]+..+input_remainders[-1]) = 0 (mod CRT)
     *
     * See detailed explanation at https://hackmd.io/LoEG5nRHQe-PvstVaD51Yw?view
     *
     * THIS FUNCTION IS UNSAFE TO USE IN CIRCUITS AS IT DOES NOT PROTECT AGAINST CRT OVERFLOWS.
     * */
    pub(crate) fn unsafe_evaluate_multiply_add<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        input_left: &BigField<F>,
        input_to_mul: &BigField<F>,
        to_add: &[BigField<F>],
        input_quotient: &BigField<F>,
        input_remainders: &[BigField<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        assert!(to_add.len() <= MAXIMUM_SUMMAND_COUNT);
        assert!(input_remainders.len() <= MAXIMUM_SUMMAND_COUNT);

        // TODO CESAR: Sanity checks?

        let neg_modulus_limbs: [BigUint; 4] = {
            let modulus: BigUint = Fq::MODULUS.into();
            let neg_modulus: BigUint =
                (&BigUint::one() << (4 * BigField::<F>::NUM_LIMB_BITS)) - modulus;
            let mut limbs = Vec::new();
            let limb_mask = (BigUint::one() << BigField::<F>::NUM_LIMB_BITS) - BigUint::one();
            for i in 0..4 {
                let limb = (neg_modulus.clone() >> (i * BigField::<F>::NUM_LIMB_BITS)) & &limb_mask;
                limbs.push(limb);
            }
            limbs.try_into().expect("Length is correct")
        };

        let mut remainders = input_remainders.to_vec();

        let mut left = input_left.clone();
        let mut to_mul = input_to_mul.clone();
        let mut quotient = input_quotient.clone();

        let max_b0 = &left.binary_basis_limbs[1].maximum_value
            * &to_mul.binary_basis_limbs[0].maximum_value
            + &neg_modulus_limbs[1] * &quotient.binary_basis_limbs[0].maximum_value;
        let max_b1 = &left.binary_basis_limbs[0].maximum_value
            * &to_mul.binary_basis_limbs[1].maximum_value
            + &neg_modulus_limbs[0] * &quotient.binary_basis_limbs[1].maximum_value;
        let max_c0 = &left.binary_basis_limbs[1].maximum_value
            * &to_mul.binary_basis_limbs[1].maximum_value
            + &neg_modulus_limbs[1] * &quotient.binary_basis_limbs[1].maximum_value;
        let max_c1 = &left.binary_basis_limbs[2].maximum_value
            * &to_mul.binary_basis_limbs[0].maximum_value
            + &neg_modulus_limbs[2] * &quotient.binary_basis_limbs[0].maximum_value;
        let max_c2 = &left.binary_basis_limbs[0].maximum_value
            * &to_mul.binary_basis_limbs[2].maximum_value
            + &neg_modulus_limbs[0] * &quotient.binary_basis_limbs[2].maximum_value;
        let max_d0 = &left.binary_basis_limbs[3].maximum_value
            * &to_mul.binary_basis_limbs[0].maximum_value
            + &neg_modulus_limbs[3] * &quotient.binary_basis_limbs[0].maximum_value;
        let max_d1 = &left.binary_basis_limbs[2].maximum_value
            * &to_mul.binary_basis_limbs[1].maximum_value
            + &neg_modulus_limbs[2] * &quotient.binary_basis_limbs[1].maximum_value;
        let max_d2 = &left.binary_basis_limbs[1].maximum_value
            * &to_mul.binary_basis_limbs[2].maximum_value
            + &neg_modulus_limbs[1] * &quotient.binary_basis_limbs[2].maximum_value;
        let max_d3 = &left.binary_basis_limbs[0].maximum_value
            * &to_mul.binary_basis_limbs[3].maximum_value
            + &neg_modulus_limbs[0] * &quotient.binary_basis_limbs[3].maximum_value;

        let mut max_r0 = &left.binary_basis_limbs[0].maximum_value
            * &to_mul.binary_basis_limbs[0].maximum_value
            + &neg_modulus_limbs[0] * &quotient.binary_basis_limbs[0].maximum_value;
        let mut max_r1 = max_b0 + max_b1;

        let mut borrow_lo_value = BigUint::zero();
        for remainder in input_remainders {
            max_r0 += &remainder.binary_basis_limbs[0].maximum_value;
            max_r1 += &remainder.binary_basis_limbs[1].maximum_value;
            borrow_lo_value += &remainder.binary_basis_limbs[0].maximum_value
                + (&remainder.binary_basis_limbs[1].maximum_value << NUM_LIMB_BITS);
        }

        borrow_lo_value >>= 2 * NUM_LIMB_BITS;
        let borrow_lo = FieldCT::from_witness(F::from(borrow_lo_value).into(), builder);

        let max_r2 = max_c0 + max_c1 + max_c2;
        let max_r3 = max_d0 + max_d1 + max_d2 + max_d3;

        let mut max_a0 = BigUint::zero();
        let mut max_a1 = BigUint::zero();
        for i in 0..to_add.len() {
            max_a0 += &to_add[i].binary_basis_limbs[0].maximum_value
                + (&to_add[i].binary_basis_limbs[1].maximum_value << NUM_LIMB_BITS);
            max_a1 += &to_add[i].binary_basis_limbs[2].maximum_value
                + (&to_add[i].binary_basis_limbs[3].maximum_value << NUM_LIMB_BITS);
        }

        let max_lo = max_r0 + (max_r1 << NUM_LIMB_BITS) + max_a0;
        let max_lo_carry = &max_lo >> (2 * NUM_LIMB_BITS);
        let max_h1 = max_r2 + (max_r3 << NUM_LIMB_BITS) + max_a1 + &max_lo_carry;

        // TODO CESAR: Maybe this is not the same as msb() + 1
        let mut max_lo_bits = max_lo.bits() as usize;
        let mut max_h1_bits = max_h1.bits() as usize;
        if max_lo_bits & 1 == 1 {
            max_lo_bits += 1;
        }
        if max_h1_bits & 1 == 1 {
            max_h1_bits += 1;
        }

        let mut carry_lo_msb = max_lo_bits - (2 * NUM_LIMB_BITS);
        let mut carry_hi_msb = max_h1_bits - (2 * NUM_LIMB_BITS);

        if max_lo_bits < NUM_LIMB_BITS * 2 {
            carry_lo_msb = 0;
        }
        if max_h1_bits < NUM_LIMB_BITS * 2 {
            carry_hi_msb = 0;
        }

        // UltraFlavor has plookup
        // The plookup custom bigfield gate requires inputs are witnesses.
        // If we're using constant values, instantiate them as circuit variables

        let mut convert_constant_to_fixed_witness =
            |bf: &BigField<F>| -> eyre::Result<BigField<F>> {
                let mut output = BigField::default();
                for i in 0..4 {
                    let value =
                        T::get_public(&bf.binary_basis_limbs[i].element.get_value(builder, driver))
                            .expect("Constant values are public");

                    output.binary_basis_limbs[i].element =
                        FieldCT::from_witness_index(builder.put_constant_variable(value));
                }

                let value = T::get_public(&bf.prime_basis_limb.get_value(builder, driver))
                    .expect("Constant values are public");
                output.prime_basis_limb =
                    FieldCT::from_witness_index(builder.put_constant_variable(value));
                Ok(output)
            };

        if left.is_constant() {
            left = convert_constant_to_fixed_witness(&left)?;
        }
        if to_mul.is_constant() {
            to_mul = convert_constant_to_fixed_witness(&to_mul)?;
        }
        if quotient.is_constant() {
            quotient = convert_constant_to_fixed_witness(&quotient)?;
        }
        if remainders[0].is_constant() {
            remainders[0] = convert_constant_to_fixed_witness(&remainders[0])?;
        }

        let mut limb_0_accumulator = vec![remainders[0].binary_basis_limbs[0].element.clone()];
        let mut limb_2_accumulator = vec![remainders[0].binary_basis_limbs[2].element.clone()];
        let mut prime_limb_accumulator = vec![remainders[0].prime_basis_limb.clone()];
        let shift_1 =
            FieldCT::from_witness(F::from(BigUint::one() << NUM_LIMB_BITS).into(), builder);
        for i in 1..remainders.len() {
            limb_0_accumulator.push(remainders[i].binary_basis_limbs[0].element.clone());
            limb_0_accumulator.push(
                remainders[i].binary_basis_limbs[1]
                    .element
                    .multiply(&shift_1, builder, driver)?,
            );
            limb_2_accumulator.push(remainders[i].binary_basis_limbs[2].element.clone());
            limb_2_accumulator.push(
                remainders[i].binary_basis_limbs[3]
                    .element
                    .multiply(&shift_1, builder, driver)?,
            );
            prime_limb_accumulator.push(remainders[i].prime_basis_limb.clone());
        }

        for add in to_add {
            limb_0_accumulator.push(add.binary_basis_limbs[0].element.neg());
            limb_0_accumulator.push(
                add.binary_basis_limbs[1]
                    .element
                    .neg()
                    .multiply(&shift_1, builder, driver)?,
            );
            limb_2_accumulator.push(add.binary_basis_limbs[2].element.neg());
            limb_2_accumulator.push(
                add.binary_basis_limbs[3]
                    .element
                    .neg()
                    .multiply(&shift_1, builder, driver)?,
            );
            prime_limb_accumulator.push(add.prime_basis_limb.neg());
        }

        let t0 = &remainders[0].binary_basis_limbs[1].element;
        let t1 = &remainders[0].binary_basis_limbs[3].element;
        let needs_normalize = (t0.additive_constant != F::zero()
            || t0.multiplicative_constant != F::one())
            || (t1.additive_constant != F::zero() || t1.multiplicative_constant != F::one());
        if needs_normalize {
            limb_0_accumulator.push(
                remainders[0].binary_basis_limbs[1]
                    .element
                    .multiply(&shift_1, builder, driver)?,
            );
            limb_2_accumulator.push(
                remainders[0].binary_basis_limbs[3]
                    .element
                    .multiply(&shift_1, builder, driver)?,
            );
        }

        let remainder_limbs = [
            FieldCT::accumulate(&limb_0_accumulator, builder, driver)?,
            if needs_normalize {
                FieldCT::from_witness_index(builder.zero_idx)
            } else {
                remainders[0].binary_basis_limbs[1].element.clone()
            },
            FieldCT::accumulate(&limb_2_accumulator, builder, driver)?,
            if needs_normalize {
                FieldCT::from_witness_index(builder.zero_idx)
            } else {
                remainders[0].binary_basis_limbs[3].element.clone()
            },
        ];

        let remainder_prime_limb = FieldCT::accumulate(&prime_limb_accumulator, builder, driver)?;

        let modulus: BigUint = Fq::MODULUS.into();
        let witnesses = NonNativeFieldWitnesses {
            a: left
                .binary_basis_limbs
                .map(|limb| limb.element.get_normalized_witness_index(builder, driver)),
            b: to_mul
                .binary_basis_limbs
                .map(|limb| limb.element.get_normalized_witness_index(builder, driver)),
            q: quotient
                .binary_basis_limbs
                .map(|limb| limb.element.get_normalized_witness_index(builder, driver)),
            r: remainder_limbs.map(|limb| limb.get_normalized_witness_index(builder, driver)),
            neg_modulus: neg_modulus_limbs.map(|limb| F::from(limb)),

            // TODO CESAR: Clarify this, modulus represents Fq::MODULUS and it is a u256, but here it is implicitly casted to Fr.
            // Then: Is modulus = Fq::MODULUS % Fr::MODULUS?
            modulus: F::from(modulus.clone()),
        };

        // N.B. this method also evaluates the prime field component of the non-native field mul
        let [lo_idx, hi_idx] =
            builder.evaluate_non_native_field_multiplication(&witnesses, driver)?;

        let neg_prime = -F::from(modulus);
        FieldCT::evaluate_polynomial_identity(
            &left.prime_basis_limb,
            &to_mul.prime_basis_limb,
            &quotient
                .prime_basis_limb
                .multiply(&FieldCT::from(neg_prime), builder, driver)?,
            &remainder_prime_limb.neg(),
            builder,
            driver,
        );

        let lo = FieldCT::from_witness_index(lo_idx).add(&borrow_lo, builder, driver);
        let hi = FieldCT::from_witness_index(hi_idx);

        // if both the hi and lo output limbs have less than 70 bits, we can use our custom
        // limb accumulation gate (accumulates 2 field elements, each composed of 5 14-bit limbs, in 3 gates)

        let hi_nwi = hi.get_normalized_witness_index(builder, driver);
        let lo_nwi = lo.get_normalized_witness_index(builder, driver);
        if (carry_lo_msb <= 70) && (carry_hi_msb <= 70) {
            builder.range_constrain_two_limbs(hi_nwi, lo_nwi, carry_hi_msb, carry_lo_msb)?;
        } else {
            //TACEO TODO: We can batch the two decompositions into a single one here for more efficiency
            builder.decompose_into_default_range(
                driver,
                hi_nwi,
                carry_hi_msb as u64,
                None,
                GenericUltraCircuitBuilder::<P, T>::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
            )?;
            builder.decompose_into_default_range(
                driver,
                lo_nwi,
                carry_lo_msb as u64,
                None,
                GenericUltraCircuitBuilder::<P, T>::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
            )?;
        }
        Ok(())
    }

    pub(crate) fn unsafe_evaluate_square_add<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        left: &BigField<F>,
        to_add: &[BigField<F>],
        quotient: &BigField<F>,
        remainders: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        Self::unsafe_evaluate_multiply_add(
            left,
            left,
            to_add,
            quotient,
            std::slice::from_ref(remainders),
            builder,
            driver,
        )?;
        Ok(())
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
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
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
            .map(|a| a.get_value(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let add_sum = add_values
            .into_iter()
            .reduce(|a, b| driver.add_other_acvm_types(&a, &b))
            .expect("At least one element in to_add");
        let add_constant = to_add.iter().all(|a| a.is_constant());

        let self_value = self.get_value(builder, driver)?;
        let mut left = self_value.clone();
        let mut right = self_value.clone();
        let mut add_right = add_sum;

        if self.is_constant() {
            if add_constant {
                let tmp = driver.mul_other_acvm_types(&left, &right)?;
                let tmp = driver.add_other_acvm_types(&tmp, &add_right);

                let (quotient, remainder) = driver.div_mod_other_acvm_type(&tmp)?;

                // TODO CESAR: Maybe wrong
                return Ok(BigField::from_constant(
                    &T::get_public_other_acvm_type(&remainder)
                        .expect("Constants are public")
                        .into_bigint()
                        .into(),
                ));
            } else {
                // left and right are constant
                let tmp = driver.mul_other_acvm_types(&left, &right)?;

                let (quotient, remainder) = driver.div_mod_other_acvm_type(&tmp)?;

                let mut new_to_add = to_add.to_vec();
                new_to_add.push(BigField::from_constant(
                    // TODO CESAR: Maybe wrong
                    &T::get_public_other_acvm_type(&remainder)
                        .expect("Constants are public")
                        .into_bigint()
                        .into(),
                ));

                return Self::sum(&new_to_add, builder, driver);
            }
        }
        // TODO CESAR: Check the quotient fits the range proof
        // TODO CESAR: self_reduce()?
        let tmp = driver.mul_other_acvm_types(&left, &right)?;
        let tmp = driver.add_other_acvm_types(&tmp, &add_right);

        let (quotient, remainder) = driver.div_mod_other_acvm_type::<P>(&tmp)?;

        // TODO CESAR: Set can_overflow and num_quotient_bits properly
        let quotient = BigField::from_witness_other_acvm_type(&quotient, true, 0, driver, builder)?;
        let remainder =
            BigField::from_witness_other_acvm_type(&remainder, true, 0, driver, builder)?;

        Self::unsafe_evaluate_square_add(self, to_add, &quotient, &remainder, builder, driver)?;

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
    pub(crate) fn sum<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        terms: &[BigField<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn madd<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
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
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
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
        let mut product_native = T::OtherAcvmType::default();
        let mut products_constant = true;

        // This check is optional, because it is heavy and often we don't need it at all
        if enable_divisor_nz_check {
            divisor.assert_is_not_equal(&BigField::default(), builder, driver)?;
        }

        // Compute the sum of products
        for i in 0..num_multiplications {
            // Get the native values modulo the field modulus
            let mul_left_native = mul_left[i].get_value(builder, driver)?;
            let mul_right_native = mul_right[i].get_value(builder, driver)?;

            let tmp = driver.neg_other_acvm_type(mul_right_native);
            let tmp = driver.mul_other_acvm_types(&mul_left_native, &tmp)?;
            product_native = driver.add_other_acvm_types(&product_native, &tmp);

            products_constant &= mul_left[i].is_constant() && mul_right[i].is_constant();
        }

        // Compute the sum of to_sub
        let mut sub_native = T::OtherAcvmType::default();
        let mut sub_constant = true;
        for sub in to_sub {
            let sub_value = sub.get_value(builder, driver)?;
            sub_native = driver.add_other_acvm_types(&sub_native, &sub_value);
            sub_constant &= sub.is_constant();
        }

        let divisor_native = divisor.get_value(builder, driver)?;

        // Compute the result
        let numerator_native = driver.sub_other_acvm_types(product_native, sub_native);
        let result_value =
            driver.div_unchecked_other_acvm_types(numerator_native, divisor_native)?;

        // If everything is constant, then we just return the constant result
        if products_constant && sub_constant && divisor.is_constant() {
            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        // Create the result witness
        let result =
            BigField::from_witness_other_acvm_type(&result_value, false, 0, driver, builder)?;

        let mut eval_left = vec![result.clone()];
        let mut eval_right = vec![divisor.clone()];
        for e in mul_left {
            eval_left.push(e.clone());
        }
        for e in mul_right {
            eval_right.push(e.clone());
        }

        BigField::mult_madd(&eval_left, &eval_right, to_sub, true, builder, driver)?;
        Ok(result)
    }

    pub(crate) fn mult_madd<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        mul_left: &[BigField<F>],
        mul_right: &[BigField<F>],
        to_add: &[BigField<F>],
        fix_remainder_to_zero: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        todo!();
    }

    pub(crate) fn conditional_assign<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        predicate: &BoolCT<F, T>,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        *self = BigField::conditional_select(predicate, self, other, builder, driver)?;
        Ok(())
    }

    // TODO CESAR: Batch FieldCT ops
    pub(crate) fn conditional_select<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        predicate: &BoolCT<F, T>,
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
            prime_basis_limb,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
