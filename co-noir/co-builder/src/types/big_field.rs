use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;

use super::field_ct::BoolCT;

pub(crate) const NUM_LIMBS: usize = 4;

#[derive(Debug)]
#[expect(dead_code)]
pub(crate) struct BigField<F: PrimeField> {
    pub(crate) binary_basis_limbs: [Limb<F>; NUM_LIMBS],
    pub(crate) prime_basis_limb: FieldCT<F>,
}

#[derive(Clone, Debug)]
#[expect(dead_code)]
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
        P: Pairing<ScalarField = F>,
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

    pub(crate) fn from_witness<
        P: Pairing<ScalarField = F>,
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

    pub(crate) fn from_slices<
        P: Pairing<ScalarField = F>,
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
}
#[expect(dead_code)]
pub(crate) struct BigGroup<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) x: BigField<P::ScalarField>,
    pub(crate) y: BigField<P::ScalarField>,
    pub(crate) is_infinity: BoolCT<P, T>,
}
impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> BigGroup<P, T> {
    pub(crate) fn new(x: BigField<P::ScalarField>, y: BigField<P::ScalarField>) -> Self {
        BigGroup {
            x,
            y,
            is_infinity: BoolCT::<P, T>::from(false),
        }
    }

    /// Set the witness indices for the x and y coordinates to public
    ///
    /// Returns the index at which the representation is stored in the public inputs.
    pub(crate) fn set_public(
        &self,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> usize {
        let start_idx = self.x.set_public(driver, builder);
        self.y.set_public(driver, builder);

        start_idx
    }
}
