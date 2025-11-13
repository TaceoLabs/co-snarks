use crate::types::field_ct::WitnessCT;
use crate::types::types::{AddQuad, NonNativeMultiplicationFieldWitnesses};
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_bn254::Fq;
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::utils::Utils;
use core::panic;
use eyre::Ok;
use num_bigint::BigUint;
use std::array;
use std::cmp::max;

use super::field_ct::BoolCT;

pub(crate) const NUM_LIMBS: usize = 4;
pub(crate) const NUM_LIMB_BITS: usize = 68;
pub(crate) const DEFAULT_MAXIMUM_LIMB: u128 = (1 << NUM_LIMB_BITS) - 1;

#[derive(Debug, Clone)]
pub struct BigField<F: PrimeField> {
    pub(crate) binary_basis_limbs: [Limb<F>; NUM_LIMBS],
    pub(crate) prime_basis_limb: FieldCT<F>,
}

impl<F: PrimeField> Default for BigField<F> {
    fn default() -> Self {
        BigField {
            binary_basis_limbs: [
                Limb::new(FieldCT::default(), BigUint::from(DEFAULT_MAXIMUM_LIMB)),
                Limb::new(FieldCT::default(), BigUint::from(DEFAULT_MAXIMUM_LIMB)),
                Limb::new(FieldCT::default(), BigUint::from(DEFAULT_MAXIMUM_LIMB)),
                Limb::new(FieldCT::default(), BigUint::from(DEFAULT_MAXIMUM_LIMB)),
            ],
            prime_basis_limb: FieldCT::default(),
        }
    }
}

#[derive(Clone, Debug)]
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
    pub(crate) const NUM_LIMB_BITS: usize = 68;

    // Fq::MODULUS_BIT_SIZE - (NUM_LIMB_BITS * 3) = 254 - 204 = 50
    pub(crate) const NUM_LAST_LIMB_BITS: usize = 50;
    pub(crate) const MAXIMUM_SUMMAND_COUNT: usize = 16;
    // If the logarithm of the maximum value of a limb is more than this, we need to reduce
    // We allow an element to be added to itself 10 times. There is no actual usecase
    pub(crate) const MAX_UNREDUCED_LIMB_BITS: usize = NUM_LIMB_BITS + 10;
    pub(crate) const NUM_BN254_SCALARS: u32 = 2;

    // If we reach this size of a limb, we stop execution (as safety measure). This should never reach during addition
    // as we would reduce the limbs before they reach this size.
    pub(crate) const PROHIBITED_LIMB_BITS: usize = Self::MAX_UNREDUCED_LIMB_BITS + 5;

    #[inline]
    fn default_maximum_remainder() -> BigUint {
        (BigUint::one() << (Self::NUM_LIMB_BITS * 3 + Self::NUM_LAST_LIMB_BITS)) - BigUint::one()
    }

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
            let wtns_idx = limb.element.get_witness_index(builder, driver);
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
        self.binary_basis_limbs
            .iter()
            .all(|limb| limb.element.is_constant())
            && self.prime_basis_limb.is_constant()
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
        Self::from_slices(&low, &high, driver, builder)
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
    pub fn from_witness_other_acvm_type<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        input: &T::OtherAcvmType<P>,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> eyre::Result<Self> {
        let [lo, hi] =
            driver.other_acvm_type_to_acvm_type_limbs::<2, { 2 * NUM_LIMB_BITS }, _>(&input)?;
        let low = FieldCT::from_witness(lo, builder);
        let high = FieldCT::from_witness(hi, builder);
        Self::from_slices(&low, &high, driver, builder)
    }

    pub(crate) fn from_acvm_limbs<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        limbs: &[T::AcvmType; NUM_LIMBS],
        can_overflow: bool,
        maximum_bitlength: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        assert!(
            (can_overflow && maximum_bitlength == 0)
                || (!can_overflow
                    && (maximum_bitlength == 0 || maximum_bitlength > (3 * NUM_LIMB_BITS)))
        );

        let limbs_ct = limbs
            .iter()
            .map(|limb| {
                let mut ct = FieldCT::default();
                ct.witness_index = builder.add_variable(limb.clone());
                ct
            })
            .collect::<Vec<FieldCT<F>>>();

        let shift = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shifts = [
            BigUint::one(),
            shift.clone(),
            shift.clone() << NUM_LIMB_BITS,
            shift.clone() << (NUM_LIMB_BITS * 2),
        ]
        .map(F::from);
        let prime_limb = driver
            .mul_many(limbs, &shifts.map(Into::into))?
            .into_iter()
            .reduce(|a, b| driver.add(a, b))
            .expect("At least one element");
        let mut prime_limb_ct = FieldCT::default();
        prime_limb_ct.witness_index = builder.add_variable(prime_limb);

        // evaluate prime basis limb with addition gate that taps into the 4th wire in the next gate
        let limb_0_nwi = limbs_ct[0].get_witness_index(builder, driver);
        let limb_1_nwi = limbs_ct[1].get_witness_index(builder, driver);
        let limb_2_nwi = limbs_ct[2].get_witness_index(builder, driver);
        let limb_3_nwi = limbs_ct[3].get_witness_index(builder, driver);
        let prime_limb_nwi = prime_limb_ct.get_witness_index(builder, driver);

        builder.create_big_add_gate(
            &AddQuad {
                a: limb_1_nwi,
                b: limb_2_nwi,
                c: limb_3_nwi,
                d: prime_limb_nwi,
                a_scaling: shifts[1],
                b_scaling: shifts[2],
                c_scaling: shifts[3],
                d_scaling: -F::one(),
                const_scaling: F::zero(),
            },
            true,
        );

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/879): dummy necessary for preceeding big add
        // gate

        GenericUltraCircuitBuilder::<P, T>::create_unconstrained_gate(
            &mut builder.blocks.arithmetic,
            builder.zero_idx,
            builder.zero_idx,
            builder.zero_idx,
            limb_0_nwi,
        );

        builder.check_selector_length_consistency();
        builder.num_gates += 1;

        let mut num_last_limb_bits = if can_overflow {
            NUM_LIMB_BITS
        } else {
            (Fq::MODULUS_BIT_SIZE - (NUM_LIMB_BITS * 3) as u32) as usize
        };

        let mut result = BigField::default();
        for i in 0..(NUM_LIMBS - 1) {
            result.binary_basis_limbs[i] =
                Limb::new(limbs_ct[i].clone(), BigUint::from(DEFAULT_MAXIMUM_LIMB));
        }

        result.binary_basis_limbs[NUM_LIMBS - 1] = Limb::new(
            limbs_ct[NUM_LIMBS - 1].clone(),
            if can_overflow {
                BigUint::from(DEFAULT_MAXIMUM_LIMB)
            } else {
                (BigUint::one() << num_last_limb_bits) - BigUint::one()
            },
        );

        // if maximum_bitlength is set, this supercedes can_overflow
        if maximum_bitlength > 0 {
            num_last_limb_bits = maximum_bitlength - (NUM_LIMB_BITS * 3);
            let max_limb_value = (BigUint::one() << num_last_limb_bits) - BigUint::one();
            result.binary_basis_limbs[NUM_LIMBS - 1].maximum_value = max_limb_value;
        }

        result.prime_basis_limb = prime_limb_ct;
        let limb_0_index = limbs_ct[0].get_witness_index(builder, driver);
        let limb_1_index = limbs_ct[1].get_witness_index(builder, driver);
        let limb_2_index = limbs_ct[2].get_witness_index(builder, driver);
        let limb_3_index = limbs_ct[3].get_witness_index(builder, driver);
        builder.range_constrain_two_limbs(
            limb_0_index,
            limb_1_index,
            NUM_LIMB_BITS,
            NUM_LIMB_BITS,
        )?;

        builder.range_constrain_two_limbs(
            limb_2_index,
            limb_3_index,
            NUM_LIMB_BITS,
            num_last_limb_bits,
        )?;

        Ok(result)
    }

    pub fn from_slices<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        low_bits_in: &FieldCT<F>,
        high_bits_in: &FieldCT<F>,
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
            let low_bits_in_normalized = low_bits_in.get_witness_index(builder, driver);
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
            let high_bits_in_normalized = high_bits_in.get_witness_index(builder, driver);
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

    /**
     * @brief Construct a bigfield element from binary limbs that are already reduced and ensure they are range
     * constrained
     *
     */
    pub fn construct_from_limbs<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        a: &FieldCT<F>,
        b: &FieldCT<F>,
        c: &FieldCT<F>,
        d: &FieldCT<F>,
        can_overflow: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        assert!(a.is_constant() == b.is_constant());
        assert!(b.is_constant() == c.is_constant());
        assert!(c.is_constant() == d.is_constant());

        let mut result = Self::default();

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

        let shift_1 = FieldCT::from(F::from(BigUint::one() << Self::NUM_LIMB_BITS));
        let shift_2 = FieldCT::from(F::from(BigUint::one() << (Self::NUM_LIMB_BITS * 2)));
        let shift_3 = FieldCT::from(F::from(BigUint::one() << (Self::NUM_LIMB_BITS * 3)));

        let mul_3 = FieldCT::multiply(
            &result.binary_basis_limbs[3].element,
            &shift_3,
            builder,
            driver,
        )?;
        let mul_2 = FieldCT::multiply(
            &result.binary_basis_limbs[2].element,
            &shift_2,
            builder,
            driver,
        )?;
        let mul_1 = FieldCT::multiply(
            &result.binary_basis_limbs[1].element,
            &shift_1,
            builder,
            driver,
        )?;

        let add = FieldCT::add_two(&mul_3, &mul_2, &mul_1, builder, driver);
        result.prime_basis_limb =
            FieldCT::add(&add, &result.binary_basis_limbs[0].element, builder, driver);

        // Range constrain the first two limbs each to NUM_LIMB_BITS
        let first_index = result.binary_basis_limbs[0]
            .element
            .get_witness_index(builder, driver);
        let second_index = result.binary_basis_limbs[1]
            .element
            .get_witness_index(builder, driver);
        builder.range_constrain_two_limbs(
            first_index,
            second_index,
            Self::NUM_LIMB_BITS as usize,
            Self::NUM_LIMB_BITS as usize,
        )?;

        // Range constrain the last two limbs to NUM_LIMB_BITS and NUM_LAST_LIMB_BITS
        let num_last_limb_bits = if can_overflow {
            Self::NUM_LIMB_BITS
        } else {
            Self::NUM_LAST_LIMB_BITS
        };

        let first_index = result.binary_basis_limbs[2]
            .element
            .get_witness_index(builder, driver);
        let second_index = result.binary_basis_limbs[3]
            .element
            .get_witness_index(builder, driver);
        builder.range_constrain_two_limbs(
            first_index,
            second_index,
            Self::NUM_LIMB_BITS as usize,
            num_last_limb_bits as usize,
        )?;

        Ok(result)
    }

    /**
     * @brief Reconstruct a bigfield from limbs (generally stored in the public inputs)
     */
    pub(crate) fn reconstruct_from_public<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        limbs: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        debug_assert_eq!(limbs.len(), NUM_LIMBS);
        Self::construct_from_limbs(
            &limbs[0], &limbs[1], &limbs[2], &limbs[3], false, builder, driver,
        )
    }

    pub(crate) fn get_value_fq<
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

    pub(crate) fn get_limb_values<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[T::AcvmType; NUM_LIMBS]> {
        let mut limb_values: Vec<T::AcvmType> = Vec::with_capacity(NUM_LIMBS);
        for limb in &self.binary_basis_limbs {
            limb_values.push(limb.element.get_value(builder, driver));
        }
        Ok(limb_values
            .try_into()
            .expect("We provided NUM_LIMBS elements"))
    }

    pub(crate) fn get_unreduced_value<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> BigUint {
        let limb_values: [T::AcvmType; NUM_LIMBS] = self.get_limb_values(builder, driver).unwrap();
        let limbs_values = if T::is_shared(&limb_values[0]) {
            driver
                .open_many(
                    &limb_values
                        .map(|limb| T::get_shared(&limb).expect("Already checked it is shared")),
                )
                .unwrap()
        } else {
            limb_values
                .map(|limb| {
                    T::get_public(&limb)
                        .expect("Already checked it is public")
                        .into()
                })
                .to_vec()
        };

        let mut result = BigUint::zero();
        let mut shift = BigUint::one();
        for i in 0..NUM_LIMBS {
            let limb_value: BigUint = limbs_values[i].into();
            result += limb_value * &shift;
            shift <<= Self::NUM_LIMB_BITS;
        }
        return result;
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

    fn get_maximum_unreduced_value() -> BigUint {
        // This = `T * n = 2^272 * |BN(Fr)|` So this equals n*2^t
        let maximum_product = Self::get_maximum_crt_product();
        // In multiplying two bigfield elements a and b, we must check that:
        //
        // a * b = q * p + r
        //
        // where q is the quotient, r is the remainder, and p is the size of the non-native field.
        // The CRT requires that we check that the equation:
        // (a) holds modulo the size of the native field n,
        // (b) holds modulo the size of the bigger ring 2^t,
        // (c) both sides of the equation are less than the max product M = 2^t * n.
        // Thus, the max value of an unreduced bigfield element is √M. In this case, we use
        // an even stricter bound. Let n = 2^m + l (where 1 < l < 2^m). Thus, we have:
        //
        //     M = 2^t * n = 2^t * (2^m + l) = 2^(t + m) + (2^t * l)
        // =>  M > 2^(t + m)
        // => √M > 2^((t + m) / 2)
        //
        // We set the maximum unreduced value of a bigfield element to be: 2^((t + m) / 2) < √M.
        //
        // Note: We use a further safer bound of 2^((t + m - 1) / 2). We use -1 to stay safer,
        // because it provides additional space to avoid the overflow, but get_msb() by itself should be enough.
        let maximum_product_bits = maximum_product.bits() - 2; // maximum_product.get_msb() - 1;
        (BigUint::one() << (maximum_product_bits >> 1)) - BigUint::one()
    }

    fn get_prohibited_limb_value() -> BigUint {
        BigUint::one() << Self::PROHIBITED_LIMB_BITS
    }

    // If we encounter this maximum value of a bigfield we stop execution
    // This is a Rust translation of the C++ get_prohibited_value() function.
    // It computes a value slightly larger than sqrt(maximum_product) with a security margin.
    fn get_prohibited_value() -> BigUint {
        let maximum_product = Self::get_maximum_crt_product();
        let maximum_product_bits = maximum_product.bits() - 2;
        let arbitrary_secure_margin = 20;
        (BigUint::one() << ((maximum_product_bits >> 1) + arbitrary_secure_margin)) - BigUint::one()
    }

    /**
     * @brief Create an unreduced 0 ~ p*k, where p*k is the minimal multiple of modulus that should be reduced
     *
     * @details We need it for division. If we always add this element during division, then we never run into the
     * formula-breaking situation
     */
    pub(crate) fn unreduced_zero<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >() -> Self {
        let modulus_u512: BigUint = Fq::MODULUS.into();
        let max_unreduced_value = Self::get_maximum_unreduced_value();
        let multiple_of_modulus =
            ((&max_unreduced_value / &modulus_u512) + BigUint::one()) * &modulus_u512;
        let msb = multiple_of_modulus.bits() as usize - 1; // get_msb() returns 0-based index

        // Slice the multiple_of_modulus into limbs
        let limb_0 = (&multiple_of_modulus) & ((BigUint::one() << NUM_LIMB_BITS) - BigUint::one());
        let limb_1 = (&multiple_of_modulus >> NUM_LIMB_BITS)
            & ((BigUint::one() << NUM_LIMB_BITS) - BigUint::one());
        let limb_2 = (&multiple_of_modulus >> (2 * NUM_LIMB_BITS))
            & ((BigUint::one() << NUM_LIMB_BITS) - BigUint::one());
        let limb_3 = (&multiple_of_modulus >> (3 * NUM_LIMB_BITS))
            & ((BigUint::one() << (msb + 1 - 3 * NUM_LIMB_BITS)) - BigUint::one());

        let mut result = BigField::default();
        result.binary_basis_limbs[0].element = FieldCT::from(F::from(limb_0));
        result.binary_basis_limbs[1].element = FieldCT::from(F::from(limb_1));
        result.binary_basis_limbs[2].element = FieldCT::from(F::from(limb_2));
        result.binary_basis_limbs[3].element = FieldCT::from(F::from(limb_3));
        result.prime_basis_limb = FieldCT::from(F::from(multiple_of_modulus % F::MODULUS.into()));
        result
    }

    fn get_binary_basis_limb_witness_indices<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[u32; NUM_LIMBS]> {
        let mut limb_witness_indices = [0u32; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            limb_witness_indices[i] = self.binary_basis_limbs[i]
                .element
                .get_witness_index(builder, driver);
        }
        Ok(limb_witness_indices)
    }

    /// Checks that two BigField elements are equal modulo p by proving their integer difference is a multiple of p.
    /// This relies on the minus operator for a-b increasing a by a multiple of p large enough so diff is non-negative.
    /// When one of the elements is a constant and another is a witness, we check equality of limbs, so if the witness
    /// bigfield element is in an unreduced form, it needs to be reduced first. We don't have automatic reduced form
    /// detection for now, so it is up to the circuit writer to detect this.
    pub(crate) fn assert_equal<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        other: &BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        msg: &str,
    ) -> eyre::Result<()> {
        let modulus_u512: BigUint = Fq::MODULUS.into();

        if self.is_constant() && other.is_constant() {
            // bigfield: calling assert equal on 2 CONSTANT bigfield elements...is this intended?
            let self_value = self.get_value_fq(builder, driver)?;
            let other_value = other.get_value_fq(builder, driver)?;

            let pub_self =
                T::get_public_other_acvm_type(&self_value).expect("Constants should be public");
            let pub_other =
                T::get_public_other_acvm_type(&other_value).expect("Constants should be public");

            assert_eq!(pub_self, pub_other);
            return Ok(());
        } else if other.is_constant() {
            // NOTE: This can lead to a situation where an honest prover cannot satisfy the constraints,
            // because `self` is not reduced, but `other` is, i.e., `self` = kp + r  and  `other` = r
            // where k is a positive integer. In such a case, the prover cannot satisfy the constraints
            // because the limb-differences would not be 0 mod r. Therefore, an honest prover needs to make sure that
            // `self` is reduced before calling this method. Also `other` should never be greater than the modulus by
            // design. As a precaution, we assert that the circuit-constant `other` is less than the modulus.
            let other_value = other.get_value_fq(builder, driver)?;
            let pub_other =
                T::get_public_other_acvm_type(&other_value).expect("Constants should be public");

            let mut limb_diffs = Vec::with_capacity(NUM_LIMBS);
            for i in 0..NUM_LIMBS {
                limb_diffs.push(FieldCT::sub(
                    &self.binary_basis_limbs[i].element,
                    &other.binary_basis_limbs[i].element,
                    builder,
                    driver,
                ));
            }
            let t4 = FieldCT::sub(
                &self.prime_basis_limb,
                &other.prime_basis_limb,
                builder,
                driver,
            );
            limb_diffs.push(t4);
            for limb in limb_diffs {
                limb.assert_is_zero(builder);
            }
            Ok(())
        } else if self.is_constant() {
            // Delegate to other
            other.assert_equal(self, builder, driver, msg)
        } else {
            // Catch the error if the reduced value of the two elements are not equal
            let lhs_reduced_value = self.get_value_fq(builder, driver)?;
            let rhs_reduced_value = other.get_value_fq(builder, driver)?;

            // TODO CESAR: Do we open the equality check on these two reduced values?

            // Remove tags, we don't want to cause violations on assert_equal
            // (Tags are not implemented in Rust version, so we skip this.)

            let diff = self.clone().sub(&mut other.clone(), builder, driver)?;
            let diff_val = diff.get_limb_values(builder, driver)?;
            let modulus = modulus_u512.clone();

            let (quotient_value, remainder_value) = driver.div_mod_acvm_limbs::<P>(&diff_val)?;
            // TODO CESAR: How do we check whether the remainder is zero?

            let num_quotient_bits = BigField::<F>::get_quotient_max_bits(&[BigUint::zero()]);

            // TODO CESAR: Is this correct?
            let quotient = BigField::<F>::from_acvm_limbs(
                &quotient_value,
                false,
                num_quotient_bits,
                builder,
                driver,
            )?;

            Self::unsafe_evaluate_multiply_add(
                &diff,
                &BigField::<F>::from_constant(&BigUint::one()),
                &[],
                &quotient,
                &[BigField::<F>::default()],
                builder,
                driver,
            )?;

            Ok(())
        }
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

    // We reduce an element's mod 2^t representation (t=4*NUM_LIMB_BITS) to size 2^s for smallest s with 2^s>p
    // This is much cheaper than actually reducing mod p and suffices for addition chains (where we just need not to
    // overflow 2^t) We also reduce any "spillage" inside the first 3 limbs, so that their range is NUM_LIMB_BITS and
    // not larger
    pub(crate) fn self_reduce<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // Warning: this assumes we have run circuit construction at least once in debug mode where large non reduced
        // constants are disallowed via ASSERT
        if self.is_constant() {
            return Ok(());
        }

        // AZTEC TODO: handle situation where some limbs are constant and others are not constant
        let limb_values = self.get_limb_values(builder, driver)?;

        let (quotient_value, remainder_value) = driver.div_mod_acvm_limbs::<P>(&limb_values)?;

        let maximum_quotient_size = self.get_maximum_value() / P::BaseField::MODULUS.into();
        let mut maximum_quotient_bits = maximum_quotient_size.bits(); // get_msb() returns 0-based index
        if maximum_quotient_bits & 1 == 1 {
            maximum_quotient_bits += 1;
        }

        assert!(maximum_quotient_bits <= NUM_LIMB_BITS as u64);
        let last_quotient_limb = quotient_value.last().expect("At least one limb").clone();
        let quotient_limb_index = builder.add_variable(last_quotient_limb);
        let quotient_limb = FieldCT::from_witness_index(quotient_limb_index);
        let quotient_limb_wi = quotient_limb.get_witness_index(builder, driver);

        // Range-constrain the quotient limb
        builder.decompose_into_default_range(
            driver,
            quotient_limb_wi,
            maximum_quotient_bits,
            None,
            GenericUltraCircuitBuilder::<P, T>::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
        )?;

        // Assert that the quotient fits within the allowed range (debug assertion)
        let modulus_u512: BigUint = Fq::MODULUS.into();
        debug_assert!(
            (BigUint::one() << maximum_quotient_bits) * &modulus_u512
                + Self::default_maximum_remainder()
                < Self::get_maximum_crt_product()
        );

        // Build the quotient as a BigField with only the first limb set
        let mut quotient = BigField::default();
        quotient.binary_basis_limbs[0] = Limb::new(
            quotient_limb.clone(),
            BigUint::one() << maximum_quotient_bits,
        );
        for i in 1..NUM_LIMBS {
            quotient.binary_basis_limbs[i] = Limb::new(
                FieldCT::from_witness_index(builder.zero_idx),
                BigUint::zero(),
            );
        }
        quotient.prime_basis_limb = quotient_limb;

        // TODO CESAR: Is this the same as:
        //    bigfield remainder = bigfield(
        // witness_t(context, fr(remainder_value.slice(0, NUM_LIMB_BITS * 2).lo)),
        // witness_t(context, fr(remainder_value.slice(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3 + NUM_LAST_LIMB_BITS).lo)));
        let [remainder_lo, remainder_hi] = driver
            .other_acvm_type_to_acvm_type_limbs::<2, { 2 * NUM_LIMB_BITS }, _>(&remainder_value)?;
        let remainder = BigField::from_slices::<P, T>(
            &FieldCT::from_witness(remainder_lo, builder),
            &FieldCT::from_witness(remainder_hi, builder),
            driver,
            builder,
        )?;
        // Enforce the multiply-add identity
        Self::unsafe_evaluate_multiply_add(
            self,
            &BigField::from_constant(&BigUint::one()),
            &[],
            &quotient,
            &[remainder.clone()],
            builder,
            driver,
        )?;

        // Update self to be the reduced remainder
        for i in 0..NUM_LIMBS {
            self.binary_basis_limbs[i] = remainder.binary_basis_limbs[i].clone();
        }
        self.prime_basis_limb = remainder.prime_basis_limb.clone();
        Ok(())
    }

    /// Checks if the BigField is reduced, and reduces it if necessary.
    /// Ensures the maximum value is less than sqrt(2^{272} * native_modulus)
    /// and each binary basis limb is less than the maximum limb value.
    pub(crate) fn reduction_check<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        if self.is_constant() {
            // this seems not a reduction check, but actually computing the reduction
            // AZTEC TODO THIS IS UGLY WHY CAN'T WE JUST DO (*THIS) = REDUCED?
            let reduced_value = self.get_value_fq(builder, driver)?;
            let reduced = BigField::from_constant(
                &T::get_public_other_acvm_type(&reduced_value)
                    .expect("Constant value")
                    .into(),
            );
            for i in 0..NUM_LIMBS {
                self.binary_basis_limbs[i] = reduced.binary_basis_limbs[i].clone();
            }
            self.prime_basis_limb = reduced.prime_basis_limb.clone();
            return Ok(());
        }

        let maximum_unreduced_limb_value =
            (BigUint::one() << Self::MAX_UNREDUCED_LIMB_BITS) - BigUint::one();
        let limb_overflow_test = (0..NUM_LIMBS)
            .any(|i| self.binary_basis_limbs[i].maximum_value > maximum_unreduced_limb_value);

        // If the value or any limb exceeds the allowed maximum, reduce.
        if self.get_maximum_value() > Self::get_maximum_unreduced_value() || limb_overflow_test {
            self.self_reduce(builder, driver)?;
        }
        Ok(())
    }

    /// Performs a sanity check on the BigField element.
    /// Ensures that no limb exceeds the prohibited value and that the overall value is within allowed bounds.
    /// This is a debug assertion and is not checked at runtime in release builds.
    pub(crate) fn sanity_check(&self) {
        // max_val < sqrt(2^T * n)
        // Note this is a static assertion, so it is not checked at runtime
        let prohibited_limb_value = Self::get_prohibited_limb_value();
        let limb_overflow_test_0 = self.binary_basis_limbs[0].maximum_value > prohibited_limb_value;
        let limb_overflow_test_1 = self.binary_basis_limbs[1].maximum_value > prohibited_limb_value;
        let limb_overflow_test_2 = self.binary_basis_limbs[2].maximum_value > prohibited_limb_value;
        let limb_overflow_test_3 = self.binary_basis_limbs[3].maximum_value > prohibited_limb_value;
        assert!(
            !(self.get_maximum_value() > Self::get_prohibited_value()
                || limb_overflow_test_0
                || limb_overflow_test_1
                || limb_overflow_test_2
                || limb_overflow_test_3),
            "BigField sanity check failed: value or limb exceeds allowed maximum"
        );
    }

    /// Returns an array containing the maximum values of the binary basis limbs.
    pub(crate) fn get_binary_basis_limb_maximums(&self) -> [BigUint; NUM_LIMBS] {
        let mut limb_maximums = array::from_fn(|_| BigUint::zero());
        for i in 0..NUM_LIMBS {
            limb_maximums[i] = self.binary_basis_limbs[i].maximum_value.clone();
        }
        limb_maximums
    }

    // Validate whether two bigfield elements are equal to each other.
    // To evaluate whether `(a == b)`, we use result boolean `r` to evaluate the following logic:
    //   1. If `r == 1`, `a - b == 0`
    //   2. If `r == 0`, `a - b` possesses an inverse `I` i.e. `(a - b) * I - 1 == 0`
    // We efficiently evaluate this logic by evaluating a single expression `(a - b)*X = Y`
    // We use conditional assignment logic to define `X, Y` as:
    //   If `r == 1` then `X = 1, Y = 0`
    //   If `r == 0` then `X = I, Y = 1`
    // This allows us to evaluate `operator==` using only 1 bigfield multiplication operation.
    // We can check the product equals 0 or 1 by directly evaluating the binary basis/prime basis limbs of Y.
    //   if `r == 1` then `(a - b)*X` should have 0 for all limb values
    //   if `r == 0` then `(a - b)*X` should have 1 in the least significant binary basis limb and 0 elsewhere
    // See also: operator== for bigfield.
    pub(crate) fn equals<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BoolCT<F, T>> {
        let lhs = self.get_value_fq(builder, driver)?;
        let rhs = other.get_value_fq(builder, driver)?;
        let is_equal_raw = driver.equals_other_acvm_type(&lhs, &rhs)?;
        let is_equal =
            BoolCT::from_witness_ct(WitnessCT::from_acvm_type(is_equal_raw, builder), builder);

        if self.is_constant() && other.is_constant() {
            return Ok(is_equal);
        }

        let mut diff = self.sub(other, builder, driver)?;
        let diff_native = diff.get_value_fq(builder, driver)?;

        // TODO CESAR: Handle zero case
        let inverse_native = driver.inverse_other_acvm_type(diff_native)?;

        let mut inverse =
            BigField::from_witness_other_acvm_type::<P, T>(&inverse_native, driver, builder)?;
        let mut multiplicand = BigField::conditional_assign(
            &is_equal,
            &mut BigField::from_constant(&BigUint::one()),
            &mut inverse,
            builder,
            driver,
        )?;

        let product = diff.mul(&mut multiplicand, builder, driver)?;

        let result = FieldCT::conditional_assign_internal(
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
        &mut self,
        other: &mut BigField<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        self.reduction_check(builder, driver)?;
        other.reduction_check(builder, driver)?;

        if self.is_constant() && other.is_constant() {
            let lhs = self.get_value_fq(builder, driver)?;
            let rhs = other.get_value_fq(builder, driver)?;
            let result_value = driver.add_other_acvm_types(lhs, rhs);

            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        let mut result = BigField::default();

        for i in 0..NUM_LIMBS {
            result.binary_basis_limbs[i].maximum_value = &self.binary_basis_limbs[i].maximum_value
                + &other.binary_basis_limbs[i].maximum_value;
        }

        // If both the elements are witnesses, we use an optimized addition trick that uses 4 gates instead of 5.
        //
        // Naively, we would need 5 gates to add two bigfield elements: 4 gates to add the binary basis limbs and
        // 1 gate to add the prime basis limbs.
        //
        // In the optimized version, we fit 15 witnesses into 4 gates (4 + 4 + 4 + 3 = 15), and we add the prime basis limbs
        // and one of the binary basis limbs in the first gate.
        // gate 1: z.limb_0 = x.limb_0 + y.limb_0  &&  z.prime_limb = x.prime_limb + y.prime_limb
        // gate 2: z.limb_1 = x.limb_1 + y.limb_1
        // gate 3: z.limb_2 = x.limb_2 + y.limb_2
        // gate 4: z.limb_3 = x.limb_3 + y.limb_3
        //
        let both_witnesses = !self.is_constant() && !other.is_constant();
        let both_prime_limb_multiplicative_constants_one =
            self.prime_basis_limb.multiplicative_constant == F::one()
                && other.prime_basis_limb.multiplicative_constant == F::one();
        if both_witnesses && both_prime_limb_multiplicative_constants_one {
            // We are checking if this is and identical element, so we need to compare the actual indices, not normalized ones
            let limbconst = self.is_constant()
                || other.is_constant()
                || (self.prime_basis_limb.witness_index == other.prime_basis_limb.witness_index);
            if !limbconst {
                let [x0, x1, x2, x3] = self
                    .binary_basis_limbs
                    .iter()
                    .map(|limb| {
                        (
                            limb.element.witness_index,
                            limb.element.multiplicative_constant,
                        )
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have 4 limbs");
                let [y0, y1, y2, y3] = other
                    .binary_basis_limbs
                    .iter()
                    .map(|limb| {
                        (
                            limb.element.witness_index,
                            limb.element.multiplicative_constant,
                        )
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have 4 limbs");
                let [c0, c1, c2, c3] = (0..4)
                    .map(|i| {
                        self.binary_basis_limbs[i].element.additive_constant
                            + other.binary_basis_limbs[i].element.additive_constant
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have 4 limbs");

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
                for (i, &witness) in output_witness.iter().take(NUM_LIMBS).enumerate() {
                    result.binary_basis_limbs[i].element = FieldCT::from_witness_index(witness);
                }
                result.prime_basis_limb = FieldCT::from_witness_index(output_witness[NUM_LIMBS]);
                return Ok(result);
            }
        }
        // If one of the elements is a constant or its prime limb does not have a multiplicative constant of 1, we
        // use the standard addition method. This will not use additional gates because field addition with one constant
        // does not require any additional gates.
        for i in 0..NUM_LIMBS {
            result.binary_basis_limbs[i].element = self.binary_basis_limbs[i].element.add(
                &other.binary_basis_limbs[i].element,
                builder,
                driver,
            );
        }
        result.prime_basis_limb =
            self.prime_basis_limb
                .add(&other.prime_basis_limb, builder, driver);
        Ok(result)
    }

    pub(crate) fn sub<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        self.reduction_check(builder, driver)?;
        other.reduction_check(builder, driver)?;

        if self.is_constant() && other.is_constant() {
            let left = self.get_value_fq(builder, driver)?;
            let right = other.get_value_fq(builder, driver)?;
            let result_value = driver.sub_other_acvm_types::<P>(left, right);

            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        if other.is_constant() {
            // subtraction by constant can be done as addition
            let right = other.get_value_fq(builder, driver)?;
            let neg_right = driver.neg_other_acvm_type::<P>(right);
            let mut summand = BigField::from_constant(
                &T::get_public_other_acvm_type(&neg_right)
                    .expect("Constant value")
                    .into_bigint()
                    .into(),
            );
            return self.add(&mut summand, builder, driver);
        }

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
            limb_0_maximum_value.bits() as usize, // get_msb() + 1
            Self::NUM_LIMB_BITS,
        );

        // Compute the maximum negative value of limb_1, including the bits limb_0 may need to borrow
        let limb_1_maximum_value = &other.binary_basis_limbs[1].maximum_value
            + (BigUint::one() << (limb_0_borrow_shift - Self::NUM_LIMB_BITS));

        // repeat the above for the remaining limbs
        let limb_1_borrow_shift =
            std::cmp::max(limb_1_maximum_value.bits() as usize, Self::NUM_LIMB_BITS);

        let limb_2_maximum_value = &other.binary_basis_limbs[2].maximum_value
            + (BigUint::one() << (limb_1_borrow_shift - Self::NUM_LIMB_BITS));
        let limb_2_borrow_shift =
            std::cmp::max(limb_2_maximum_value.bits() as usize, Self::NUM_LIMB_BITS);

        let limb_3_maximum_value = &other.binary_basis_limbs[3].maximum_value
            + (BigUint::one() << (limb_2_borrow_shift - Self::NUM_LIMB_BITS));

        // Step 2: Compute the constant value `X = m * p` we must add to the result to ensure EVERY limb is >= 0
        //
        // We need to find a value `X` where `X.limb[3] > limb_3_maximum_value`.
        // As long as the above holds, we can borrow bits from X.limb[3] to ensure less significant limbs are positive
        //
        // Start by setting constant_to_add = p
        let modulus_biguint: BigUint = Fq::MODULUS.into();
        let constant_to_add_factor = ((limb_3_maximum_value << (Self::NUM_LIMB_BITS * 3))
            / &modulus_biguint)
            + BigUint::one();
        let constant_to_add = &modulus_biguint * &constant_to_add_factor;

        // Step 3: Compute offset terms t0, t1, t2, t3 that we add to our result to ensure each limb is positive
        //
        // t3 represents the value we are BORROWING from constant_to_add.limb[3]
        // t2, t1, t0 are the terms we will ADD to constant_to_add.limb[2], constant_to_add.limb[1], constant_to_add.limb[0]
        //
        // Borrow propagation table:
        // ┌───────┬─────────────────────────────────┬──────────────────────────────────┐
        // │ Limb  │ Value received FROM next limb   │ Value given TO previous limb     │
        // ├───────┼─────────────────────────────────┼──────────────────────────────────┤
        // │   0   │ 2^limb_0_borrow_shift           │ 0                                │
        // │   1   │ 2^limb_1_borrow_shift           │ 2^(limb_0_borrow_shift - L)      │
        // │   2   │ 2^limb_2_borrow_shift           │ 2^(limb_1_borrow_shift - L)      │
        // │   3   │ 0                               │ 2^(limb_2_borrow_shift - L)      │
        // └───────┴─────────────────────────────────┴──────────────────────────────────┘
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
        let mask = (BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one();
        let to_add_0 = (constant_to_add.clone() & &mask) + &t0;
        let to_add_1 = ((constant_to_add.clone() >> Self::NUM_LIMB_BITS) & &mask) + &t1;
        let to_add_2 = ((constant_to_add.clone() >> (Self::NUM_LIMB_BITS * 2)) & &mask) + &t2;
        let to_add_3 = ((constant_to_add.clone() >> (Self::NUM_LIMB_BITS * 3)) & &mask) - &t3;

        // Update the maximum possible value of the result. We assume here that (*this.value) = 0
        let mut result = BigField::default();
        result.binary_basis_limbs[0].maximum_value =
            self.binary_basis_limbs[0].maximum_value.clone() + &to_add_0;
        result.binary_basis_limbs[1].maximum_value =
            self.binary_basis_limbs[1].maximum_value.clone() + &to_add_1;
        result.binary_basis_limbs[2].maximum_value =
            self.binary_basis_limbs[2].maximum_value.clone() + &to_add_2;
        result.binary_basis_limbs[3].maximum_value =
            self.binary_basis_limbs[3].maximum_value.clone() + &to_add_3;

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

        let both_witnesses = !self.is_constant() && !other.is_constant();
        let both_prime_limb_multiplicative_constants_one =
            self.prime_basis_limb.multiplicative_constant == F::one()
                && other.prime_basis_limb.multiplicative_constant == F::one();
        if both_witnesses && both_prime_limb_multiplicative_constants_one {
            // We are checking if this is and identical element, so we need to compare the actual indices, not normalized ones
            let limbconst = self.is_constant()
                || other.is_constant()
                || (self.prime_basis_limb.witness_index == other.prime_basis_limb.witness_index);
            if !limbconst {
                let [x0, x1, x2, x3] = result
                    .binary_basis_limbs
                    .iter()
                    .map(|limb| {
                        (
                            limb.element.witness_index,
                            limb.element.multiplicative_constant,
                        )
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have 4 limbs");
                let [y0, y1, y2, y3] = other
                    .binary_basis_limbs
                    .iter()
                    .map(|limb| {
                        (
                            limb.element.witness_index,
                            limb.element.multiplicative_constant,
                        )
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have 4 limbs");
                let [c0, c1, c2, c3] = (0..4)
                    .map(|i| {
                        result.binary_basis_limbs[i].element.additive_constant
                            - other.binary_basis_limbs[i].element.additive_constant
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have 4 limbs");

                let xp = self.prime_basis_limb.witness_index;
                let yp = other.prime_basis_limb.witness_index;

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

                for i in 0..NUM_LIMBS {
                    result.binary_basis_limbs[i].element =
                        FieldCT::from_witness_index(output_witness[i]);
                }

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

    // Evaluate a non-native field multiplication: (a * b = c mod p) where p == target_basis.modulus
    //
    // We compute quotient term `q` and remainder `c` and evaluate that:
    //
    // a * b - q * p - c = 0 mod modulus_u512 (binary basis modulus, currently 2**272)
    // a * b - q * p - c = 0 mod circuit modulus
    pub(crate) fn mul<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        self.reduction_check(builder, driver)?;
        other.reduction_check(builder, driver)?;

        // Now we can actually compute the quotient and remainder values

        let lhs_value = self.get_limb_values(builder, driver)?;
        let rhs_value = other.get_limb_values(builder, driver)?;
        let (quotient_value, remainder_value) =
            driver.madd_div_mod_acvm_limbs::<P>(&lhs_value, &rhs_value, &[])?;

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
        let (reduction_required, num_quotient_bits) = Self::get_quotient_reduction_info(
            &[self.get_maximum_value()],
            &[other.get_maximum_value()],
            &[],
            &[Self::default_maximum_remainder()],
        );

        if reduction_required {
            if self.get_maximum_value() > other.get_maximum_value() {
                self.self_reduce(builder, driver)?;
            } else {
                other.self_reduce(builder, driver)?;
            }
            return self.mul(other, builder, driver);
        }

        let quotient =
            BigField::from_acvm_limbs(&quotient_value, false, num_quotient_bits, builder, driver)?;

        let remainder_limbs = driver
            .other_acvm_type_to_acvm_type_limbs::<NUM_LIMBS, NUM_LIMB_BITS, _>(&remainder_value)?;
        let remainder = BigField::from_acvm_limbs(&remainder_limbs, false, 0, builder, driver)?;

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
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        BigField::default().sub(self, builder, driver)
    }

    pub(crate) fn div_without_denominator_check<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        numerators: &mut [Self],
        denominator: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        Self::internal_div(numerators, denominator, false, builder, driver)
    }

    // TODO CESAR: This is likely much slower than the bb version. Which works on integer types
    // Division of a sum with an optional check if divisor is zero. Should not be used outside of class.
    //
    // @param numerators Vector of numerators
    // @param denominator Denominator
    // @param check_for_zero If the zero check should be enabled
    //
    // @return The result of division
    pub(crate) fn internal_div<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        numerators: &mut [Self],
        denominator: &mut Self,
        check_for_zero: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if numerators.is_empty() {
            return Ok(Self::default());
        }

        denominator.reduction_check(builder, driver)?;

        numerators
            .iter_mut()
            .map(|n| n.reduction_check(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let numerator_values = numerators
            .iter()
            .map(|n| n.get_limb_values(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let numerator_constant = numerators.iter().all(|n| n.is_constant());
        let numerator_sum = numerator_values
            .into_iter()
            .reduce(|acc, x| driver.add_acvm_type_limbs::<P>(&acc, &x))
            .expect("At least one numerator");

        // a / b = c
        // TODO CESAR: Handle zero case
        // TODO CESAR: Batch these
        let denominator_value = denominator.get_limb_values(builder, driver)?;
        let inverse_value = driver.inverse_acvm_type_limbs::<P>(&denominator_value)?;
        let result_value = driver.mul_mod_acvm_type_limbs::<P>(&numerator_sum, &inverse_value)?;

        let zero = Self::unreduced_zero::<P, T>().get_limb_values(builder, driver)?;
        let tmp = driver.sub_acvm_type_limbs::<P>(&zero, &numerator_sum)?;
        let (quotient, _) =
            driver.madd_div_mod_acvm_limbs::<P>(&result_value, &denominator_value, &[tmp])?;

        if numerator_constant && denominator.is_constant() {
            let result_fq = driver.acvm_type_limbs_to_other_acvm_type::<P>(&result_value)?;
            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&result_fq)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        let numerators_max = numerators
            .iter()
            .map(|n| n.get_maximum_value())
            .collect::<Vec<_>>();

        let (reduction_required, num_quotient_bits) = Self::get_quotient_reduction_info(
            &[Self::default_maximum_remainder()],
            &[denominator.get_maximum_value()],
            &[Self::unreduced_zero::<P, T>()],
            &numerators_max,
        );

        if reduction_required {
            denominator.self_reduce(builder, driver)?;
            return Self::internal_div(numerators, denominator, check_for_zero, builder, driver);
        }

        // We do this after the quotient check, since this creates gates and we don't want to do this twice
        if check_for_zero {
            denominator.assert_is_not_equal(&BigField::default(), builder, driver)?;
        }

        let quotient =
            BigField::from_acvm_limbs(&quotient, false, num_quotient_bits, builder, driver)?;
        let result = BigField::from_acvm_limbs(&result_value, true, 0, builder, driver)?;
        Self::unsafe_evaluate_multiply_add(
            &denominator,
            &result,
            &[Self::unreduced_zero::<P, T>()],
            &quotient,
            &numerators,
            builder,
            driver,
        )?;

        Ok(result)
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
        input_left: &Self,
        input_to_mul: &Self,
        to_add: &[Self],
        input_quotient: &Self,
        input_remainders: &[Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        assert!(input_remainders.len() <= Self::MAXIMUM_SUMMAND_COUNT);

        // Sanity checks
        input_left.sanity_check();
        input_to_mul.sanity_check();
        input_quotient.sanity_check();
        for addend in to_add {
            addend.sanity_check();
        }
        for remainder in input_remainders {
            remainder.sanity_check();
        }

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

        let mut max_lo_bits = max_lo.bits() as usize; // get_msb() + 1
        let mut max_h1_bits = max_h1.bits() as usize; // get_msb() + 1
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
        let witnesses = NonNativeMultiplicationFieldWitnesses {
            a: left
                .binary_basis_limbs
                .map(|limb| limb.element.get_witness_index(builder, driver)),
            b: to_mul
                .binary_basis_limbs
                .map(|limb| limb.element.get_witness_index(builder, driver)),
            q: quotient
                .binary_basis_limbs
                .map(|limb| limb.element.get_witness_index(builder, driver)),
            r: remainder_limbs.map(|limb| limb.get_witness_index(builder, driver)),
            neg_modulus: neg_modulus_limbs.map(|limb| F::from(limb)),
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

        let hi_nwi = hi.get_witness_index(builder, driver);
        let lo_nwi = lo.get_witness_index(builder, driver);
        if (carry_lo_msb <= 70) && (carry_hi_msb <= 70) {
            builder.range_constrain_two_limbs(hi_nwi, lo_nwi, carry_hi_msb, carry_lo_msb)?;
        } else {
            //TACEO TODO: We can batch the two decompositions into a single one here for more efficiency
            builder.create_range_constraint(driver, hi_nwi, carry_hi_msb as u32)?;
            builder.create_range_constraint(driver, lo_nwi, carry_lo_msb as u32)?;
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

    pub(crate) fn sqr<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        self.reduction_check(builder, driver)?;

        let self_value = self.get_limb_values(builder, driver)?;
        let (quotient_value, remainder_value) =
            driver.madd_div_mod_acvm_limbs::<P>(&self_value, &self_value, &[])?;

        if self.is_constant() {
            Ok(BigField::from_constant(
                &T::get_public_other_acvm_type::<P>(&remainder_value)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ))
        } else {
            // Check the quotient fits the range proof
            let (reduction_required, num_quotient_bits) = Self::get_quotient_reduction_info(
                &[self.get_maximum_value()],
                &[self.get_maximum_value()],
                &[],
                &[Self::default_maximum_remainder()],
            );
            if reduction_required {
                self.self_reduce(builder, driver)?;
                return self.sqr(builder, driver);
            }

            let quotient = BigField::from_acvm_limbs(
                &quotient_value,
                false,
                num_quotient_bits,
                builder,
                driver,
            )?;
            let remainder_limbs = driver
                .other_acvm_type_to_acvm_type_limbs::<NUM_LIMBS, NUM_LIMB_BITS, _>(
                    &remainder_value,
                )?;
            let remainder = BigField::from_acvm_limbs(&remainder_limbs, false, 0, builder, driver)?;

            Self::unsafe_evaluate_square_add(self, &[], &quotient, &remainder, builder, driver)?;

            Ok(remainder)
        }
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
        &mut self,
        to_add: &mut [Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        self.reduction_check(builder, driver)?;

        let add_values = to_add
            .iter_mut()
            .map(|a| {
                a.reduction_check(builder, driver)
                    .expect("Reduction check should not fail");
                a.get_limb_values(builder, driver)
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let add_constant = to_add.iter().all(|a| a.is_constant());

        let self_value = self.get_limb_values(builder, driver)?;

        if self.is_constant() {
            // We don't need the quotient here

            if add_constant {
                let (q, r) =
                    driver.madd_div_mod_acvm_limbs(&self_value, &self_value, &add_values)?;

                return Ok(BigField::from_constant(
                    &T::get_public_other_acvm_type::<P>(&r)
                        .expect("Constants are public")
                        .into_bigint()
                        .into(),
                ));
            } else {
                let (_, r) = driver.madd_div_mod_acvm_limbs(&self_value, &self_value, &[])?;
                let mut new_to_add = to_add.to_vec();
                new_to_add.push(BigField::from_constant(
                    &T::get_public_other_acvm_type::<P>(&r)
                        .expect("Constants are public")
                        .into_bigint()
                        .into(),
                ));

                return Self::sum(&mut new_to_add, builder, driver);
            }
        }
        // Check the quotient fits the range proof
        let (reduction_required, num_quotient_bits) = Self::get_quotient_reduction_info(
            &[self.get_maximum_value()],
            &[self.get_maximum_value()],
            &to_add,
            &[Self::default_maximum_remainder()],
        );
        if reduction_required {
            self.self_reduce(builder, driver)?;
            return self.sqradd(to_add, builder, driver);
        }

        let (quotient, remainder) =
            driver.madd_div_mod_acvm_limbs::<P>(&self_value, &self_value, &add_values)?;

        let quotient =
            BigField::from_acvm_limbs(&quotient, false, num_quotient_bits, builder, driver)?;
        let remainder = BigField::from_witness_other_acvm_type(&remainder, driver, builder)?;

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
    pub(crate) fn sum<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        terms: &mut [Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigField<F>> {
        assert!(terms.len() > 0);

        // TODO CESAR: Implement using add_two
        let mut acc = terms[0].clone();
        for i in 1..terms.len() {
            acc = acc.add(&mut terms[i], builder, driver)?;
        }

        Ok(acc)
    }

    /**
     * Compute a * b + ...to_add = c mod p
     *
     * @param to_mul Bigfield element to multiply by
     * @param to_add Vector of elements to add
     *
     * @return New bigfield elment c
     **/
    pub(crate) fn madd<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        to_mul: &mut Self,
        to_add: &mut [Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        self.reduction_check(builder, driver)?;
        to_mul.reduction_check(builder, driver)?;

        let add_values = to_add
            .iter()
            .map(|a| a.get_limb_values(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let add_constant = to_add.iter().all(|a| a.is_constant());

        let left_value = self.get_limb_values(builder, driver)?;
        let mul_right = to_mul.get_limb_values(builder, driver)?;

        let (quotient, remainder) =
            driver.madd_div_mod_acvm_limbs::<P>(&left_value, &mul_right, &add_values)?;

        if self.is_constant() && to_mul.is_constant() && add_constant {
            return Ok(BigField::from_constant(
                &T::get_public_other_acvm_type(&remainder)
                    .expect("Constants are public")
                    .into_bigint()
                    .into(),
            ));
        }

        let (reduction_required, num_quotient_bits) = Self::get_quotient_reduction_info(
            &[self.get_maximum_value()],
            &[to_mul.get_maximum_value()],
            &to_add,
            &[Self::default_maximum_remainder()],
        );

        if reduction_required {
            if self.get_maximum_value() > to_mul.get_maximum_value() {
                self.self_reduce(builder, driver)?;
            } else {
                to_mul.self_reduce(builder, driver)?;
            }
            return self.madd(to_mul, to_add, builder, driver);
        }

        let quotient =
            BigField::from_acvm_limbs(&quotient, false, num_quotient_bits, builder, driver)?;
        let remainder = BigField::from_witness_other_acvm_type(&remainder, driver, builder)?;

        Self::unsafe_evaluate_multiply_add(
            self,
            to_mul,
            to_add,
            &quotient,
            &[remainder.clone()],
            builder,
            driver,
        )?;

        Ok(remainder)
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
            let mul_left_native = mul_left[i].get_value_fq(builder, driver)?;
            let mul_right_native = mul_right[i].get_value_fq(builder, driver)?;

            let tmp = driver.neg_other_acvm_type(mul_right_native);
            let tmp = driver.mul_other_acvm_types(mul_left_native, tmp)?;
            product_native = driver.add_other_acvm_types(product_native, tmp);

            products_constant &= mul_left[i].is_constant() && mul_right[i].is_constant();
        }

        // Compute the sum of to_sub
        let mut sub_native = T::OtherAcvmType::default();
        let mut sub_constant = true;
        for sub in to_sub {
            let sub_value = sub.get_value_fq(builder, driver)?;
            sub_native = driver.add_other_acvm_types(sub_native, sub_value);
            sub_constant &= sub.is_constant();
        }

        let divisor_native = divisor.get_value_fq(builder, driver)?;

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
        let result = BigField::from_witness_other_acvm_type(&result_value, driver, builder)?;

        let mut eval_left = vec![result.clone()];
        let mut eval_right = vec![divisor.clone()];
        for e in mul_left {
            eval_left.push(e.clone());
        }
        for e in mul_right {
            eval_right.push(e.clone());
        }

        BigField::mult_madd(
            &mut eval_left,
            &mut eval_right,
            &mut to_sub.to_vec(),
            true,
            builder,
            driver,
        )?;
        Ok(result)
    }

    /**
     * Evaluate the sum of products and additional values safely.
     *
     * @param mul_left Vector of bigfield multiplicands
     * @param mul_right Vector of bigfield multipliers
     * @param to_add Vector of bigfield elements to add to the sum of products
     *
     * @return A reduced value that is the sum of all products and to_add values
     * */
    pub(crate) fn mult_madd<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        mul_left: &mut [Self],
        mul_right: &mut [Self],
        to_add: &mut [Self],
        fix_remainder_to_zero: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        assert_eq!(mul_left.len(), mul_right.len());
        assert!(mul_left.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);

        let mutable_mul_left = mul_left.to_vec();
        let mutable_mul_right = mul_right.to_vec();

        let mut worst_case_product_sum = BigUint::zero();

        // First we do all constant optimizations
        to_add.iter_mut().for_each(|a| {
            a.reduction_check(builder, driver)
                .expect("Reduction check should not fail");
        });
        let (add_const, mut new_to_add) = to_add
            .iter()
            .cloned()
            .into_iter()
            .partition::<Vec<Self>, _>(|a| a.is_constant());
        let add_right_constant_sum =
            add_const
                .into_iter()
                .fold(T::OtherAcvmType::default(), |acc, a| {
                    let val = a.get_value_fq(builder, driver).expect("Should get value");
                    driver.add_other_acvm_types(acc, val)
                });
        let add_constant = new_to_add.is_empty();

        // Compute the product sum
        // Optimize constant use
        let (prod_const, new_mul) = mutable_mul_left
            .into_iter()
            .zip(mutable_mul_right.into_iter())
            .partition::<Vec<(Self, Self)>, _>(|(a, b)| a.is_constant() && b.is_constant());

        // TODO CESAR: Batch these
        let product_constant_sum =
            prod_const
                .into_iter()
                .fold(T::OtherAcvmType::default(), |acc, (a, b)| {
                    let a_val = a.get_value_fq(builder, driver).expect("Should get value");
                    let b_val = b.get_value_fq(builder, driver).expect("Should get value");
                    let tmp = driver
                        .mul_other_acvm_types(a_val, b_val)
                        .expect("Should multiply");
                    driver.add_other_acvm_types(acc, tmp)
                });

        let product_sum_constant = new_mul.is_empty();

        // Compute the constant term we're adding to the product sum
        let tmp = driver.add_other_acvm_types(product_constant_sum, add_right_constant_sum);
        let tmp = driver.other_acvm_type_to_acvm_type_limbs::<NUM_LIMBS, NUM_LIMB_BITS, P>(&tmp)?;
        let (q, r) = driver.div_mod_acvm_limbs(&tmp)?;
        let r_const = T::get_public_other_acvm_type::<P>(&r)
            .expect("Constants are public")
            .into_bigint()
            .into();
        if product_sum_constant {
            if add_constant {
                return Ok(BigField::from_constant(&r_const));
            } else {
                new_to_add.push(BigField::from_constant(&r_const));

                let mut result = Self::sum(&mut new_to_add, builder, driver)?;

                if fix_remainder_to_zero {
                    result.self_reduce(builder, driver)?;
                    // TODO CESAR: msg?
                    result.assert_equal(
                        &BigField::default(),
                        builder,
                        driver,
                        "Remainder should be zero",
                    )?;
                }
                return Ok(result);
            }
        }

        // TODO CESAR: What if r_const is zero?
        new_to_add.push(BigField::from_constant(&r_const));

        // Compute added sum
        let mut add_right_final_sum = array::from_fn(|_| T::AcvmType::default());
        let mut add_right_maximum = BigUint::zero();
        for a in new_to_add.iter_mut() {
            // Technically not needed, but better to leave just in case
            a.reduction_check(builder, driver)?;
            let limbs = a.get_limb_values(builder, driver)?;
            add_right_final_sum = driver.add_acvm_type_limbs::<P>(&add_right_final_sum, &limbs);
            add_right_maximum += &a.get_maximum_value();
        }

        let final_number_of_products = new_mul.len();
        // We need to check if it is possible to reduce the products enough
        worst_case_product_sum = final_number_of_products
            * Self::default_maximum_remainder()
            * Self::default_maximum_remainder();

        // Check that we can actually reduce the products enough, this assert will probably never get triggered
        debug_assert!(worst_case_product_sum + add_right_maximum < Self::get_maximum_crt_product());

        // We've collapsed all constants, checked if we can compute the sum of products in the worst case, time to check
        // if we need to reduce something
        let (mut left, mut right): (Vec<Self>, Vec<Self>) = new_mul.into_iter().unzip();
        Self::perform_reductions_for_mult_madd(
            &mut left,
            &mut right,
            &mut new_to_add,
            builder,
            driver,
        )?;

        let a = left
            .iter()
            .map(|a| a.get_limb_values(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;
        let b = right
            .iter()
            .map(|b| b.get_limb_values(builder, driver))
            .collect::<eyre::Result<Vec<_>>>()?;

        // Get the number of range proof bits for the quotient
        let num_quotient_bits = Self::get_quotient_max_bits(&[Self::default_maximum_remainder()]);

        // Compute the final quotient and remainder
        let (quotient, remainder) =
            driver.madd_div_mod_many_acvm_limbs(&a, &b, &[add_right_final_sum])?;

        // If we are establishing an identity and the remainder has to be zero, we need to check, that it actually is
        // TODO CESAR

        let quotient =
            BigField::from_acvm_limbs(&quotient, false, num_quotient_bits, builder, driver)?;

        let remainder = if fix_remainder_to_zero {
            BigField::default()
            // remainder needs to be defined as wire value and not selector values to satisfy
            // Ultra's bigfield custom gates
            // TODO CESAR: remainder.convert_constant_to_fixed_witness(ctx);
        } else {
            BigField::from_witness_other_acvm_type(&remainder, driver, builder)?
        };

        Self::unsafe_evaluate_multiple_multiply_add(
            &left,
            &right,
            &new_to_add,
            &quotient,
            std::slice::from_ref(&remainder),
            builder,
            driver,
        )?;

        Ok(remainder)
    }

    /**
     * @brief Performs individual reductions on the supplied elements as well as more complex reductions to prevent CRT
     * modulus overflow and to fit the quotient inside the range proof
     *
     *
     * @tparam Builder builder
     * @tparam T basefield
     * @param mul_left
     * @param mul_right
     * @param to_add
     */
    fn perform_reductions_for_mult_madd<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        mul_left: &mut [Self],
        mul_right: &mut [Self],
        to_add: &mut [Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // Ensure input sizes are within limits
        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        assert!(mul_left.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        assert!(mul_right.len() <= Self::MAXIMUM_SUMMAND_COUNT);

        let number_of_products = mul_left.len();

        // Get the maximum values of elements
        let mut max_values_left = Vec::with_capacity(number_of_products);
        let mut max_values_right = Vec::with_capacity(number_of_products);

        // Do regular reduction checks for all elements
        for left_element in mul_left.iter_mut() {
            left_element.reduction_check(builder, driver)?;
            max_values_left.push(left_element.get_maximum_value());
        }

        for right_element in mul_right.iter_mut() {
            right_element.reduction_check(builder, driver)?;
            max_values_right.push(right_element.get_maximum_value());
        }

        // Perform CRT checks for the whole evaluation
        // 1. Check if we can overflow CRT modulus
        // 2. Check if the quotient actually fits in our range proof.
        // 3. If we haven't passed one of the checks, reduce accordingly, starting with the largest product

        let (mut reduction_required, _) = Self::get_quotient_reduction_info(
            &max_values_left,
            &max_values_right,
            to_add,
            &[Self::default_maximum_remainder()],
        );

        if reduction_required {
            // We are out of luck and have to reduce the elements to keep the intermediate result below CRT modulus
            // For that we need to compute the maximum update - how much reducing each element is going to update the quotient.
            // Contents of the tuple: | Qmax_before-Qmax_after | product number | argument number |
            let mut maximum_value_updates: Vec<(BigUint, usize, usize)> = Vec::new();

            // Lambda to compute the maximum value update from reduction of each element
            let compute_updates = |maxval_updates: &mut Vec<(BigUint, usize, usize)>,
                                   m_left: &mut [Self],
                                   m_right: &mut [Self],
                                   number_of_products: usize| {
                maxval_updates.clear();
                maxval_updates.reserve(number_of_products * 2);
                for i in 0..number_of_products {
                    let original_left = m_left[i].get_maximum_value();
                    let original_right = m_right[i].get_maximum_value();
                    let original_product = &original_left * &original_right;
                    if m_left[i].is_constant() {
                        // If the multiplicand is constant, we can't reduce it, so the update is 0.
                        maxval_updates.push((BigUint::zero(), i, 0));
                    } else {
                        let new_product = Self::default_maximum_remainder() * &original_right;
                        assert!(
                            new_product <= original_product,
                            "bigfield: This should never happen"
                        );
                        maxval_updates.push((original_product.clone() - new_product, i, 0));
                    }
                    if m_right[i].is_constant() {
                        maxval_updates.push((BigUint::zero(), i, 1));
                    } else {
                        let new_product = Self::default_maximum_remainder() * &original_left;
                        assert!(
                            new_product <= original_product,
                            "bigfield: This should never happen"
                        );
                        maxval_updates.push((original_product - new_product, i, 1));
                    }
                }
            };

            // Compare function for sorting updates
            let compare_update_tuples =
                |left: &(BigUint, usize, usize), right: &(BigUint, usize, usize)| {
                    left.0.cmp(&right.0).reverse()
                };

            // Now we loop through, reducing 1 element each time. This is costly in code, but allows us to use fewer gates
            while reduction_required {
                // Compute the possible reduction updates
                compute_updates(
                    &mut maximum_value_updates,
                    mul_left,
                    mul_right,
                    number_of_products,
                );

                // Sort the vector, larger values first
                maximum_value_updates.sort_by(compare_update_tuples);

                // We choose the largest update
                let (update_size, largest_update_product_index, multiplicand_index) =
                    maximum_value_updates[0].clone();
                if update_size.is_zero() {
                    panic!("bigfield: Can't reduce further");
                }
                // Reduce the larger of the multiplicands that compose the product
                if multiplicand_index == 0 {
                    mul_left[largest_update_product_index].self_reduce(builder, driver)?;
                } else {
                    mul_right[largest_update_product_index].self_reduce(builder, driver)?;
                }

                // Update max values after reduction
                for i in 0..number_of_products {
                    max_values_left[i] = mul_left[i].get_maximum_value();
                    max_values_right[i] = mul_right[i].get_maximum_value();
                }
                reduction_required = Self::get_quotient_reduction_info(
                    &max_values_left,
                    &max_values_right,
                    to_add,
                    &[Self::default_maximum_remainder()],
                )
                .0;
            }
            // Now we have reduced everything exactly to the point of no overflow. There is probably a way to use even
            // fewer reductions, but for now this will suffice.
        }
        Ok(())
    }

    fn unsafe_evaluate_multiple_multiply_add<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        input_left: &[Self],
        input_right: &[Self],
        to_add: &[Self],
        input_quotient: &Self,
        input_remainders: &[Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        assert_eq!(input_left.len(), input_right.len(), "input size mismatch");
        assert!(
            input_left.len() <= Self::MAXIMUM_SUMMAND_COUNT,
            "input size exceeds MAXIMUM_SUMMAND_COUNT"
        );
        assert!(
            to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT,
            "to_add size exceeds MAXIMUM_SUMMAND_COUNT"
        );
        assert!(
            input_remainders.len() <= Self::MAXIMUM_SUMMAND_COUNT,
            "remainders size exceeds MAXIMUM_SUMMAND_COUNT"
        );

        let left_is_constant = input_left.iter().all(|a| {
            a.sanity_check();
            a.is_constant()
        });
        let right_is_constant = input_right.iter().all(|a| {
            a.sanity_check();
            a.is_constant()
        });
        to_add.iter().for_each(|a| {
            a.sanity_check();
        });
        input_quotient.sanity_check();
        input_remainders.iter().for_each(|a| {
            a.sanity_check();
        });

        // We must have at least one left or right multiplicand as witnesses.
        debug_assert!(
            !left_is_constant || !right_is_constant,
            "bigfield: At least one multiplicand must be non-constant"
        );

        let remainders = input_remainders.clone();
        let mut left = input_left.to_vec();
        let mut right = input_right.to_vec();
        let mut quotient = input_quotient.clone();

        // Step 1: Compute the maximum potential value of our product limbs
        //
        // max_lo = maximum value of limb products that span the range 0 - 2^{3L}
        // max_hi = maximum value of limb products that span the range 2^{2L} - 2^{5L}
        let mut max_lo = BigUint::zero();
        let mut max_hi = BigUint::zero();

        // Compute the maximum value that needs to be borrowed from the hi limbs to the lo limb.
        // Check the README for the explanation of the borrow.
        let mut max_remainders_lo = BigUint::zero();
        for remainder in remainders {
            max_remainders_lo += &remainder.binary_basis_limbs[0].maximum_value
                + (&remainder.binary_basis_limbs[1].maximum_value << NUM_LIMB_BITS);
        }

        // While performing the subtraction of (sum of) remainder(s) as:
        //
        // (Σi ai * bi + q * p') - (Σj rj)
        //
        // we want to ensure that the lower limbs do not underflow. So we add a borrow value
        // to the lower limbs and subtract it from the higher limbs. Naturally, such a borrow value
        // must be a multiple of 2^2L (where L = NUM_LIMB_BITS). Let borrow_lo_value be the value
        // borrowed from the hi limbs, then we must have:
        //
        // borrow_lo_value * 2^(2L) >= max_remainders_lo
        //
        // Thus, we can compute the minimum borrow_lo_value as:
        //
        // borrow_lo_value = ceil(max_remainders_lo / 2^(2L))
        //
        let two_pow_2l = BigUint::one() << (2 * NUM_LIMB_BITS);
        let borrow_lo_value =
            (&max_remainders_lo + (&two_pow_2l - BigUint::one())) >> (2 * NUM_LIMB_BITS);
        let borrow_lo = FieldCT::from_witness(F::from(borrow_lo_value).into(), builder);

        let neg_modulus_mod_binary_basis_limbs: [BigUint; NUM_LIMBS] = {
            let modulus_bin = BigUint::one() << (NUM_LIMBS * Self::NUM_LIMB_BITS);
            let modulus_fq: BigUint = Fq::MODULUS.into();
            let negative_prime_modulus_mod_binary_basis = modulus_bin - &modulus_fq;
            let mask = (BigUint::one() << Self::NUM_LIMB_BITS) - BigUint::one();
            (0..NUM_LIMBS)
                .map(|i| {
                    (&negative_prime_modulus_mod_binary_basis >> (i * Self::NUM_LIMB_BITS)) & &mask
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("We provided NUM_LIMBS elements")
        };

        // Compute the maximum value of the quotient times modulus.
        let (max_q_neg_p_lo, max_q_neg_p_hi) = Self::compute_partial_schoolbook_multiplication(
            &neg_modulus_mod_binary_basis_limbs,
            &quotient.get_binary_basis_limb_maximums(),
        );

        // update max_lo, max_hi with quotient limb product terms.
        max_lo += &max_q_neg_p_lo + &max_remainders_lo;
        max_hi += &max_q_neg_p_hi;

        // Compute maximum value of addition terms in `to_add` and add to max_lo, max_hi
        let mut max_a0 = BigUint::zero();
        let mut max_a1 = BigUint::zero();
        for add in to_add {
            max_a0 += &add.binary_basis_limbs[0].maximum_value
                + (&add.binary_basis_limbs[1].maximum_value << NUM_LIMB_BITS);
            max_a1 += &add.binary_basis_limbs[2].maximum_value
                + (&add.binary_basis_limbs[3].maximum_value << NUM_LIMB_BITS);
        }
        max_lo += &max_a0;
        max_hi += &max_a1;

        // Compute the maximum value of our multiplication products and add to max_lo, max_hi
        for i in 0..input_left.len() {
            let (product_lo, product_hi) = Self::compute_partial_schoolbook_multiplication(
                &input_left[i].get_binary_basis_limb_maximums(),
                &input_right[i].get_binary_basis_limb_maximums(),
            );
            max_lo += product_lo;
            max_hi += product_hi;
        }

        let max_lo_carry = &max_lo >> (2 * NUM_LIMB_BITS);
        max_hi += &max_lo_carry;

        // Compute the maximum number of bits in `max_lo` and `max_hi` - this defines the range constraint values we
        // will need to apply to validate our product
        let max_lo_bits = max_lo.bits() as u64; // max_lo.get_msb() + 1
        let max_hi_bits = max_hi.bits() as u64; // max_hi.get_msb() + 1

        // The custom bigfield multiplication gate requires inputs are witnesses.
        // If we're using constant values, instantiate them as circuit variables
        //
        // Explanation:
        // The bigfield multiplication gate expects witnesses and disallows circuit constants
        // because allowing circuit constants would lead to complex circuit logic to support
        // different combinations of constant and witness inputs. Particularly, bigfield multiplication
        // gate enforces constraints of the form: a * b - q * p + r = 0, where:
        //
        // input left  a = (a3 || a2 || a1 || a0)
        // input right b = (b3 || b2 || b1 || b0)
        // quotient    q = (q3 || q2 || q1 || q0)
        // remainder   r = (r3 || r2 || r1 || r0)
        //
        // | a1 | b1 | r0 | lo_0 | <-- product gate 1: check lo_0
        // | a0 | b0 | a3 | b3   |
        // | a2 | b2 | r3 | hi_0 |
        // | a1 | b1 | r2 | hi_1 |
        //
        // Example constaint: lo_0 = (a1 * b0 + a0 * b1) * 2^b   + (a0 * b0)   - r0
        //                 ==>  w4 = (w1 * w'2 + w'1 * w2) * 2^b + (w'1 * w'2) - w3
        //
        // If a, b both are witnesses, this special gate performs 3 field multiplications per gate.
        // If b was a constant, then we would need to no field multiplications, but instead update the
        // the limbs of a with multiplicative and additive constants. This just makes the circuit logic
        // more complex, so we disallow constants. If there are constants, we convert them to fixed witnesses (at the
        // expense of 1 extra gate per constant).
        //
        let mut convert_constant_to_fixed_witness =
            |input: &BigField<F>,
             builder: &mut GenericUltraCircuitBuilder<P, T>,
             driver: &mut T|
             -> eyre::Result<BigField<F>> {
                assert!(input.is_constant());
                let mut output = input.clone();
                output.prime_basis_limb = FieldCT::from_witness_index(
                    builder.put_constant_variable(
                        T::get_public(&input.prime_basis_limb.get_value(builder, driver))
                            .expect("Constant values are public"),
                    ),
                );
                for i in 0..NUM_LIMBS {
                    output.binary_basis_limbs[i].element = FieldCT::from_witness_index(
                        builder.put_constant_variable(
                            T::get_public(
                                &input.binary_basis_limbs[i]
                                    .element
                                    .get_value(builder, driver),
                            )
                            .expect("Constant values are public"),
                        ),
                    );
                }
                Ok(output)
            };

        // evalaute a nnf mul and add into existing lohi output for our extra product terms
        // we need to add the result of (left_b * right_b) into lo_1_idx and hi_1_idx
        // our custom gate evaluates: ((a * b) + (q * neg_modulus) - r) / 2^{136} = lo + hi * 2^{136}
        // where q is a 'quotient' bigfield and neg_modulus is defined by selector polynomial values
        // The custom gate costs 7 constraints, which is cheaper than computing `a * b` using multiplication +
        // addition gates But....we want to obtain `left_a * right_b + lo_1 + hi_1 * 2^{136} = lo + hi * 2^{136}` If
        // we set `neg_modulus = [2^{136}, 0, 0, 0]` and `q = [lo_1, 0, hi_1, 0]`, then we will add `lo_1` into
        // `lo`, and `lo_1/2^{136} + hi_1` into `hi`. we can then subtract off `lo_1/2^{136}` from `hi`, by setting
        // `r = [0, 0, lo_1, 0]` This saves us 2 addition gates as we don't have to add together the outputs of two
        // calls to `evaluate_non_native_field_multiplication`
        let mut limb_0_accumulator: Vec<FieldCT<F>> = Vec::new();
        let mut limb_2_accumulator: Vec<FieldCT<F>> = Vec::new();
        let mut prime_limb_accumulator: Vec<FieldCT<F>> = Vec::new();

        for i in 0..left.len() {
            let left_i = &mut left[i];
            let right_i = &mut right[i];

            if left_i.is_constant() {
                *left_i = convert_constant_to_fixed_witness(left_i, builder, driver)?;
            }
            if right_i.is_constant() {
                *right_i = convert_constant_to_fixed_witness(right_i, builder, driver)?;
            }

            if i > 0 {
                // Prepare witnesses for partial multiplication
                let left_mul_wit = left_i.get_binary_basis_limb_witness_indices(builder, driver)?;
                let right_mul_wit =
                    right_i.get_binary_basis_limb_witness_indices(builder, driver)?;

                let mul_witnesses = (left_mul_wit, right_mul_wit);

                // Call builder to queue partial non-native field multiplication
                let [lo_2_idx, hi_2_idx] =
                    builder.queue_partial_non_native_field_multiplication(mul_witnesses, driver)?;

                let lo_2 = FieldCT::from_witness_index(lo_2_idx);
                let hi_2 = FieldCT::from_witness_index(hi_2_idx);

                limb_0_accumulator.push(lo_2.neg());
                limb_2_accumulator.push(hi_2.neg());
                prime_limb_accumulator.push(
                    FieldCT::multiply(
                        &left_i.prime_basis_limb,
                        &right_i.prime_basis_limb,
                        builder,
                        driver,
                    )?
                    .neg(),
                );
            }
        }

        if quotient.is_constant() {
            quotient = convert_constant_to_fixed_witness(&quotient, builder, driver)?;
        }

        if !remainders.is_empty() {
            limb_0_accumulator.push(remainders[0].binary_basis_limbs[0].element.clone());
            limb_2_accumulator.push(remainders[0].binary_basis_limbs[2].element.clone());
            prime_limb_accumulator.push(remainders[0].prime_basis_limb.clone());
        }

        let shift_1 = FieldCT::from(F::from(BigUint::one() << NUM_LIMB_BITS));
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

        let mut accumulated_lo = FieldCT::accumulate(&limb_0_accumulator, builder, driver)?;
        let mut accumulated_hi = FieldCT::accumulate(&limb_2_accumulator, builder, driver)?;

        if accumulated_lo.is_constant() {
            let value = T::get_public(&accumulated_lo.get_value(builder, driver))
                .expect("Constant values are public");
            accumulated_lo = FieldCT::from_witness_index(builder.put_constant_variable(value));
        }
        if accumulated_hi.is_constant() {
            let value = T::get_public(&accumulated_hi.get_value(builder, driver))
                .expect("Constant values are public");
            accumulated_hi = FieldCT::from_witness_index(builder.put_constant_variable(value));
        }

        let mut remainder1 = if remainders.is_empty() {
            FieldCT::from_witness_index(builder.zero_idx)
        } else {
            remainders[0].binary_basis_limbs[1].element.clone()
        };

        if remainder1.is_constant() {
            let value = T::get_public(&remainder1.get_value(builder, driver))
                .expect("Constant values are public");
            remainder1 = FieldCT::from_witness_index(builder.put_constant_variable(value));
        }

        let mut remainder3 = if remainders.is_empty() {
            FieldCT::from_witness_index(builder.zero_idx)
        } else {
            remainders[0].binary_basis_limbs[3].element.clone()
        };

        if remainder3.is_constant() {
            let value = T::get_public(&remainder3.get_value(builder, driver))
                .expect("Constant values are public");
            remainder3 = FieldCT::from_witness_index(builder.put_constant_variable(value));
        }

        let remainder_limbs = [accumulated_lo, remainder1, accumulated_hi, remainder3];

        let remainder_prime_limb = FieldCT::accumulate(&prime_limb_accumulator, builder, driver)?;

        let a = input_left[0].get_binary_basis_limb_witness_indices(builder, driver)?;
        let b = input_right[0].get_binary_basis_limb_witness_indices(builder, driver)?;
        let q = quotient.get_binary_basis_limb_witness_indices(builder, driver)?;
        let r = [
            remainder_limbs[0].get_witness_index(builder, driver),
            remainder_limbs[1].get_witness_index(builder, driver),
            remainder_limbs[2].get_witness_index(builder, driver),
            remainder_limbs[3].get_witness_index(builder, driver),
        ];
        let neg_modulus = [
            F::from(neg_modulus_mod_binary_basis_limbs[0].clone()).into(),
            F::from(neg_modulus_mod_binary_basis_limbs[1].clone()).into(),
            F::from(neg_modulus_mod_binary_basis_limbs[2].clone()).into(),
            F::from(neg_modulus_mod_binary_basis_limbs[3].clone()).into(),
        ];
        let witnesses = NonNativeMultiplicationFieldWitnesses {
            a,
            b,
            q,
            r,
            neg_modulus,
        };

        let [lo_1_idx, hi_1_idx] =
            builder.evaluate_non_native_field_multiplication(&witnesses, driver)?;
        let negative_prime_modulus_mod_native_basis = {
            let mod_fq: BigUint = Fq::MODULUS.into();
            let mod_fr: BigUint = F::MODULUS.into();
            let tmp = (&mod_fq - &mod_fr) % &mod_fr;
            FieldCT::from(-F::from(tmp))
        };
        let tmp = quotient.prime_basis_limb.multiply(
            &negative_prime_modulus_mod_native_basis,
            builder,
            driver,
        )?;

        FieldCT::evaluate_polynomial_identity(
            &input_left[0].prime_basis_limb,
            &input_right[0].prime_basis_limb,
            &tmp,
            &remainder_prime_limb.neg(),
            builder,
            driver,
        );

        let lo = FieldCT::from_witness_index(lo_1_idx).add(&borrow_lo, builder, driver);
        let hi = FieldCT::from_witness_index(hi_1_idx);

        debug_assert!(max_lo_bits > (2 * NUM_LIMB_BITS) as u64);
        debug_assert!(max_hi_bits > (2 * NUM_LIMB_BITS) as u64);

        let mut carry_lo_msb = max_lo_bits as usize - (2 * NUM_LIMB_BITS);
        let mut carry_hi_msb = max_hi_bits as usize - (2 * NUM_LIMB_BITS);

        if max_lo_bits < (2 * NUM_LIMB_BITS) as u64 {
            carry_lo_msb = 0;
        }
        if max_hi_bits < (2 * NUM_LIMB_BITS) as u64 {
            carry_hi_msb = 0;
        }

        // if both the hi and lo output limbs have less than 70 bits, we can use our custom
        // limb accumulation gate (accumulates 2 field elements, each composed of 5 14-bit limbs, in 3 gates)
        if carry_lo_msb <= 70 && carry_hi_msb <= 70 {
            let h1_wi = hi.get_witness_index(builder, driver);
            let l1_wi = lo.get_witness_index(builder, driver);
            builder.range_constrain_two_limbs(h1_wi, l1_wi, carry_hi_msb, carry_lo_msb)?;
        } else {
            hi.create_range_constraint(carry_hi_msb, builder, driver)?;
            lo.create_range_constraint(carry_lo_msb, builder, driver)?;
        }

        Ok(())
    }

    pub(crate) fn conditional_assign<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        predicate: &BoolCT<F, T>,
        lhs: &mut Self,
        rhs: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        rhs.conditional_select(lhs, predicate, builder, driver)
    }

    pub(crate) fn conditional_negate<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &mut self,
        predicate: &BoolCT<F, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if self.is_constant() && predicate.is_constant() {
            if predicate.get_value(driver) == P::ScalarField::ONE.into() {
                return self.neg(builder, driver);
            }
            return Ok(self.clone());
        }

        self.reduction_check(builder, driver)?;

        // We want to check:
        // predicate = 1 ==> (0 - *this)
        // predicate = 0 ==> *this
        //
        // We just use the conditional_assign method to do this as it costs the same number of gates as computing
        // p * (0 - *this) + (1 - p) * (*this)
        //
        let negative_this = self.neg(builder, driver)?;
        Self::conditional_assign(
            predicate,
            &mut negative_this.clone(),
            &mut self.clone(),
            builder,
            driver,
        )
    }

    // TODO CESAR: Batch FieldCT ops
    pub(crate) fn conditional_select<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        predicate: &BoolCT<F, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if predicate.is_constant() {
            if predicate.get_value(driver) == P::ScalarField::ONE.into() {
                return Ok(other.clone());
            } else {
                return Ok(self.clone());
            }
        }

        // AZTEC TODO: use field_t::conditional_assign method
        let binary_limbs = (0..NUM_LIMBS)
            .map(|i| {
                predicate.to_field_ct(driver).madd(
                    &other.binary_basis_limbs[i].element.sub(
                        &self.binary_basis_limbs[i].element,
                        builder,
                        driver,
                    ),
                    &self.binary_basis_limbs[i].element,
                    builder,
                    driver,
                )
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let prime_basis_limb = predicate.to_field_ct(driver).madd(
            &other
                .prime_basis_limb
                .sub(&self.prime_basis_limb, builder, driver),
            &self.prime_basis_limb,
            builder,
            driver,
        )?;

        let binary_basis_limbs = (0..NUM_LIMBS)
            .map(|i| {
                Limb::new(
                    binary_limbs[i].clone(),
                    max(
                        self.binary_basis_limbs[i].maximum_value.clone(),
                        other.binary_basis_limbs[i].maximum_value.clone(),
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

    /// Computes the maximum possible quotient value for a sum of products plus additional terms.
    ///
    /// # Arguments
    /// * `as_max` - Vector of multiplicands' maximum values
    /// * `bs_max` - Vector of multipliers' maximum values
    /// * `to_add` - Vector of values to add
    ///
    /// # Returns
    /// The maximum possible quotient value as a `BigUint`.
    fn compute_maximum_quotient_value(
        as_max: &[BigUint],
        bs_max: &[BigUint],
        to_add: &[BigUint],
    ) -> BigUint {
        assert_eq!(as_max.len(), bs_max.len());
        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);

        // Sum all additional values
        let mut add_values = BigUint::zero();
        for add_element in to_add {
            add_values += add_element;
        }

        // Compute the sum of products as a BigUint with enough capacity
        let mut product_sum = BigUint::zero();
        for i in 0..as_max.len() {
            product_sum += &as_max[i] * &bs_max[i];
        }

        let sum = &product_sum + &add_values;
        let modulus: BigUint = Fq::MODULUS.into();

        // Compute quotient and remainder
        let quotient = &sum / &modulus;

        quotient
    }

    fn get_quotient_reduction_info(
        as_max: &[BigUint],
        bs_max: &[BigUint],
        to_add: &[Self],
        remainders_max: &[BigUint],
    ) -> (bool, usize) {
        assert_eq!(as_max.len(), bs_max.len());

        assert!(to_add.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        assert!(as_max.len() <= Self::MAXIMUM_SUMMAND_COUNT);
        assert!(remainders_max.len() <= Self::MAXIMUM_SUMMAND_COUNT);

        // Check if the product sum can overflow CRT modulus
        if Self::mul_product_overflows_crt_modulus(&as_max, &bs_max, to_add) {
            return (true, 0);
        }
        let num_quotient_bits = Self::get_quotient_max_bits(&remainders_max);
        let to_add_max: Vec<BigUint> = to_add
            .iter()
            .map(|added_element| added_element.get_maximum_value())
            .collect();

        // Get maximum value of quotient
        let maximum_quotient = Self::compute_maximum_quotient_value(&as_max, &bs_max, &to_add_max);

        // Check if the quotient can fit into the range proof
        if maximum_quotient >= (BigUint::one() << num_quotient_bits) {
            return (true, 0);
        }
        (false, num_quotient_bits)
    }

    /// Check that the maximum value of a sum of bigfield products with added values overflows CRT modulus.
    ///
    /// # Arguments
    /// * `as_max` - Vector of multiplicands' maximum values
    /// * `bs_max` - Vector of multipliers' maximum values
    /// * `to_add` - Vector of field elements to be added
    ///
    /// # Returns
    /// * `true` if there is an overflow, `false` otherwise
    fn mul_product_overflows_crt_modulus(
        as_max: &[BigUint],
        bs_max: &[BigUint],
        to_add: &[Self],
    ) -> bool {
        assert_eq!(as_max.len(), bs_max.len());
        // Computing individual products
        let mut product_sum = BigUint::zero();
        let mut add_term = BigUint::zero();
        for i in 0..as_max.len() {
            product_sum += &as_max[i] * &bs_max[i];
        }
        for add in to_add {
            add_term += add.get_maximum_value();
        }

        let maximum_default_bigint =
            BigUint::one() << (Self::NUM_LIMB_BITS * 6 + Self::NUM_LAST_LIMB_BITS * 2);

        // check that the add terms alone cannot overflow the crt modulus. v. unlikely so just forbid circuits that
        // trigger this case
        assert!(
            add_term.clone() + maximum_default_bigint.clone() < Self::get_maximum_crt_product()
        );

        (product_sum + add_term) >= Self::get_maximum_crt_product()
    }

    /// Returns the maximum CRT product for the bigfield.
    ///
    /// This is the product of the binary basis modulus (2^(NUM_LIMB_BITS * NUM_LIMBS))
    /// and the prime basis modulus (the field modulus).
    fn get_maximum_crt_product() -> BigUint {
        let binary_basis_modulus = BigUint::one() << (Self::NUM_LIMB_BITS * NUM_LIMBS);
        let prime_basis_modulus: BigUint = F::MODULUS.into();
        binary_basis_modulus * prime_basis_modulus
    }

    /// Compute the maximum number of bits for quotient range proof to protect against CRT underflow
    ///
    /// # Arguments
    /// * `remainders_max` - Maximum sizes of resulting remainders
    /// # Returns
    /// Desired length of range proof
    fn get_quotient_max_bits(remainders_max: &[BigUint]) -> usize {
        // find q_max * p + ...remainders_max < nT
        let mut base = Self::get_maximum_crt_product();
        for r in remainders_max {
            base -= r;
        }
        // modulus_u512 is the modulus of the prime field (Fq::MODULUS)
        let modulus_u512: BigUint = Fq::MODULUS.into();
        base /= &modulus_u512;
        // Return msb - 1
        let msb_plus_one = base.bits(); // static_cast<size_t>(base.get_msb() - 1);
        if msb_plus_one > 1 {
            (msb_plus_one - 2) as usize
        } else {
            // TODO CESAR: Check if this is correct
            usize::MAX
        }
    }

    /// Computes the partial schoolbook multiplication of two arrays of limbs.
    /// Returns (lo, hi) as BigUint values, where:
    ///   lo = c0 + c1 * 2^b
    ///   hi = c2 + c3 * 2^b
    /// where c0..c3 are the schoolbook products as described.
    fn compute_partial_schoolbook_multiplication(
        a_limbs: &[BigUint; NUM_LIMBS],
        b_limbs: &[BigUint; NUM_LIMBS],
    ) -> (BigUint, BigUint) {
        let b0_inner = &a_limbs[1] * &b_limbs[0];
        let b1_inner = &a_limbs[0] * &b_limbs[1];
        let c0_inner = &a_limbs[1] * &b_limbs[1];
        let c1_inner = &a_limbs[2] * &b_limbs[0];
        let c2_inner = &a_limbs[0] * &b_limbs[2];
        let d0_inner = &a_limbs[3] * &b_limbs[0];
        let d1_inner = &a_limbs[2] * &b_limbs[1];
        let d2_inner = &a_limbs[1] * &b_limbs[2];
        let d3_inner = &a_limbs[0] * &b_limbs[3];

        let r0_inner = &a_limbs[0] * &b_limbs[0];
        let r1_inner = &b0_inner + &b1_inner;
        let r2_inner = &c0_inner + &c1_inner + &c2_inner;
        let r3_inner = &d0_inner + &d1_inner + &d2_inner + &d3_inner;

        let lo_val = &r0_inner + (&r1_inner << NUM_LIMB_BITS);
        let hi_val = &r2_inner + (&r3_inner << NUM_LIMB_BITS);

        (lo_val, hi_val)
    }

    pub(crate) fn debug_print<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> String {
        let value = self.get_unreduced_value(builder, driver);
        let value_dec_str = format!("{:?}", value);
        let big_uint = BigUint::parse_bytes(value_dec_str.as_bytes(), 10).unwrap();
        format!("0x{:x}", big_uint)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use co_acvm::PlainAcvmSolver;
    use rand::thread_rng;

    use crate::transcript_ct::Bn254G1;

    use super::*;

    #[test]
    fn test_add_sub_bigfield() {
        let mut rng = thread_rng();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let mut driver = PlainAcvmSolver::<Fr>::new();

        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let c = a + b;
        let d = a - b;

        let mut a_const = BigField::from_constant(&a.into_bigint().into());
        let mut b_const = BigField::from_constant(&b.into_bigint().into());
        let add_const = a_const
            .add(&mut b_const, &mut builder, &mut driver)
            .unwrap();
        let sub_const = a_const
            .sub(&mut b_const, &mut builder, &mut driver)
            .unwrap();

        assert_eq!(
            c,
            add_const.get_value_fq(&mut builder, &mut driver).unwrap()
        );
        assert_eq!(
            d,
            sub_const.get_value_fq(&mut builder, &mut driver).unwrap()
        );

        let mut a_wit =
            BigField::from_witness_other_acvm_type(&a, &mut driver, &mut builder).unwrap();
        let mut b_wit =
            BigField::from_witness_other_acvm_type(&b, &mut driver, &mut builder).unwrap();

        let add_wit = a_wit.add(&mut b_wit, &mut builder, &mut driver).unwrap();
        let sub_wit = a_wit.sub(&mut b_wit, &mut builder, &mut driver).unwrap();

        assert_eq!(c, add_wit.get_value_fq(&mut builder, &mut driver).unwrap());
        assert_eq!(d, sub_wit.get_value_fq(&mut builder, &mut driver).unwrap());
    }

    #[test]
    fn test_mul_bigfield() {
        let mut rng = thread_rng();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let mut driver = PlainAcvmSolver::<Fr>::new();

        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let c = a * b;

        let mut a_const = BigField::from_constant(&a.into_bigint().into());
        let mut b_const = BigField::from_constant(&b.into_bigint().into());
        let c_bf = a_const
            .mul(&mut b_const, &mut builder, &mut driver)
            .unwrap();

        assert_eq!(c, c_bf.get_value_fq(&mut builder, &mut driver).unwrap());

        let mut a_wit =
            BigField::from_witness_other_acvm_type(&a, &mut driver, &mut builder).unwrap();
        let mut b_wit =
            BigField::from_witness_other_acvm_type(&b, &mut driver, &mut builder).unwrap();
        let c_bf_wit = a_wit.mul(&mut b_wit, &mut builder, &mut driver).unwrap();

        assert_eq!(c, c_bf_wit.get_value_fq(&mut builder, &mut driver).unwrap());
    }

    #[test]
    fn test_sqradd_bigfield() {
        let mut rng = thread_rng();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let mut driver = PlainAcvmSolver::<Fr>::new();

        let a = Fq::rand(&mut rng);
        let to_add = (0..10).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let mut expected = a * a;
        for add in &to_add {
            expected += add;
        }

        let mut a_const = BigField::from_constant(&a.into_bigint().into());
        let mut to_add_const = to_add
            .iter()
            .map(|add| BigField::from_constant(&add.into_bigint().into()))
            .collect::<Vec<_>>();
        let c_bf = a_const
            .sqradd(&mut to_add_const, &mut builder, &mut driver)
            .unwrap();

        assert_eq!(
            expected,
            c_bf.get_value_fq(&mut builder, &mut driver).unwrap()
        );

        let mut a_wit =
            BigField::from_witness_other_acvm_type(&a, &mut driver, &mut builder).unwrap();
        let mut to_add_wit = to_add
            .iter()
            .map(|add| {
                BigField::from_witness_other_acvm_type(add, &mut driver, &mut builder).unwrap()
            })
            .collect::<Vec<_>>();
        let c_bf_wit = a_wit
            .sqradd(&mut to_add_wit, &mut builder, &mut driver)
            .unwrap();

        assert_eq!(
            expected,
            c_bf_wit.get_value_fq(&mut builder, &mut driver).unwrap()
        );
    }

    #[test]
    fn test_madd_bigfield() {
        let mut rng = thread_rng();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let mut driver = PlainAcvmSolver::<Fr>::new();

        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let to_add = (0..10).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let mut expected = a * b;
        for add in &to_add {
            expected += add;
        }
        let mut a_const = BigField::from_constant(&a.into_bigint().into());
        let mut b_const = BigField::from_constant(&b.into_bigint().into());
        let mut to_add_const = to_add
            .iter()
            .map(|add| BigField::from_constant(&add.into_bigint().into()))
            .collect::<Vec<_>>();
        let c_bf = a_const
            .madd(&mut b_const, &mut to_add_const, &mut builder, &mut driver)
            .unwrap();

        assert_eq!(
            expected,
            c_bf.get_value_fq(&mut builder, &mut driver).unwrap()
        );

        let mut a_wit =
            BigField::from_witness_other_acvm_type(&a, &mut driver, &mut builder).unwrap();
        let mut b_wit =
            BigField::from_witness_other_acvm_type(&b, &mut driver, &mut builder).unwrap();
        let mut to_add_wit = to_add
            .iter()
            .map(|add| {
                BigField::from_witness_other_acvm_type(add, &mut driver, &mut builder).unwrap()
            })
            .collect::<Vec<_>>();
        let c_bf_wit = a_wit
            .madd(&mut b_wit, &mut to_add_wit, &mut builder, &mut driver)
            .unwrap();

        assert_eq!(
            expected,
            c_bf_wit.get_value_fq(&mut builder, &mut driver).unwrap()
        );
    }

    #[test]
    fn test_internal_div() {
        let mut rng = thread_rng();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let mut driver = PlainAcvmSolver::<Fr>::new();

        let numerators = (0..10).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let denominator = Fq::rand(&mut rng);
        let mut c = Fq::zero();
        for num in &numerators {
            c += num;
        }
        c /= &denominator;

        let mut numerators_const = numerators
            .iter()
            .map(|num| BigField::from_constant(&num.into_bigint().into()))
            .collect::<Vec<_>>();
        let mut denominator_const = BigField::from_constant(&denominator.into_bigint().into());
        let c_bf = BigField::internal_div(
            &mut numerators_const.clone(),
            &mut denominator_const,
            true,
            &mut builder,
            &mut driver,
        )
        .unwrap();

        assert_eq!(c, c_bf.get_value_fq(&mut builder, &mut driver).unwrap());

        let mut numerators_wit = numerators
            .iter()
            .map(|num| {
                BigField::from_witness_other_acvm_type(num, &mut driver, &mut builder).unwrap()
            })
            .collect::<Vec<_>>();
        let mut denominator_wit =
            BigField::from_witness_other_acvm_type(&denominator, &mut driver, &mut builder)
                .unwrap();
        let c_bf_wit = BigField::internal_div(
            &mut numerators_wit,
            &mut denominator_wit,
            true,
            &mut builder,
            &mut driver,
        )
        .unwrap();
        assert_eq!(c, c_bf_wit.get_value_fq(&mut builder, &mut driver).unwrap());
    }

    #[test]
    fn test_msub_div() {
        let mut rng = thread_rng();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let mut driver = PlainAcvmSolver::<Fr>::new();

        let mul_left = (0..5).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let mul_right = (0..5).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let to_add = (0..5).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let divisor = Fq::rand(&mut rng);

        let mut expected = Fq::zero();
        for i in 0..5 {
            expected += mul_left[i] * mul_right[i];
        }
        for add in &to_add {
            expected += add;
        }
        expected = -expected;
        expected /= &divisor;

        let mul_left_bf = mul_left
            .iter()
            .map(|num| {
                BigField::from_witness_other_acvm_type(num, &mut driver, &mut builder).unwrap()
            })
            .collect::<Vec<_>>();
        let mul_right_bf = mul_right
            .iter()
            .map(|num| {
                BigField::from_witness_other_acvm_type(num, &mut driver, &mut builder).unwrap()
            })
            .collect::<Vec<_>>();
        let to_add_bf = to_add
            .iter()
            .map(|num| {
                BigField::from_witness_other_acvm_type(num, &mut driver, &mut builder).unwrap()
            })
            .collect::<Vec<_>>();
        let divisor_bf =
            BigField::from_witness_other_acvm_type(&divisor, &mut driver, &mut builder).unwrap();

        let c_bf = BigField::msub_div(
            &mul_left_bf,
            &mul_right_bf,
            &divisor_bf,
            &to_add_bf,
            false,
            &mut builder,
            &mut driver,
        )
        .unwrap();

        assert_eq!(
            expected,
            c_bf.get_value_fq(&mut builder, &mut driver).unwrap()
        );
    }
}
