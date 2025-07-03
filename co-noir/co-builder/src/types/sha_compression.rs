use crate::{
    TranscriptFieldType, builder::GenericUltraCircuitBuilder, prelude::HonkCurve, utils::Utils,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;
use std::{array, marker::PhantomData};

use super::{
    field_ct::{FieldCT, WitnessCT},
    plookup::{ColumnIdx, MultiTableId, Plookup},
};
pub struct SHA256<F: PrimeField> {
    phantom: PhantomData<F>,
}

#[derive(Clone)]
pub(crate) struct SparseValue<F: PrimeField> {
    pub normal: FieldCT<F>,
    pub sparse: FieldCT<F>,
}

impl<F: PrimeField> SparseValue<F> {
    pub fn new<P: Pairing<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        input: FieldCT<F>,
        builder: &GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let sparse = if input.is_constant() {
            let value: BigUint = T::get_public(&input.get_value(builder, driver))
                .expect("Constants should be public")
                .into();
            let sparse_value = Utils::map_into_sparse_form::<16>(
                value.iter_u64_digits().next().unwrap_or_default(),
            );
            FieldCT::from(F::from(sparse_value))
        } else {
            FieldCT::default()
        };

        Self {
            normal: input,
            sparse,
        }
    }
}

pub struct SparseWitnessLimbs<F: PrimeField> {
    pub normal: FieldCT<F>,
    pub sparse_limbs: [FieldCT<F>; 4],
    pub rotated_limbs: [FieldCT<F>; 4],
    pub has_sparse_limbs: bool,
}

impl<F: PrimeField> SparseWitnessLimbs<F> {
    pub fn new(normal: FieldCT<F>) -> Self {
        Self {
            normal,
            sparse_limbs: Default::default(),
            rotated_limbs: Default::default(),
            has_sparse_limbs: false,
        }
    }
    pub fn convert_witness<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        w: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = SparseWitnessLimbs::new(w.clone());

        let lookup = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::Sha256WitnessInput,
            w,
            &FieldCT::default(),
            false,
        )?;

        result.sparse_limbs = [
            lookup[ColumnIdx::C2][0].clone(),
            lookup[ColumnIdx::C2][1].clone(),
            lookup[ColumnIdx::C2][2].clone(),
            lookup[ColumnIdx::C2][3].clone(),
        ];

        result.rotated_limbs = [
            lookup[ColumnIdx::C3][0].clone(),
            lookup[ColumnIdx::C3][1].clone(),
            lookup[ColumnIdx::C3][2].clone(),
            lookup[ColumnIdx::C3][3].clone(),
        ];

        result.has_sparse_limbs = true;

        Ok(result)
    }
}

impl<F: PrimeField> SHA256<F> {
    pub(crate) fn sha256_block<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        h_init: [FieldCT<F>; 8],
        input: [FieldCT<F>; 16],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[FieldCT<F>; 8]> {
        const ROUND_CONSTANTS: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        // Initialize round variables with previous block output
        let mut a = SparseValue::new(h_init[0].clone(), builder, driver);
        let mut b = Self::map_into_maj_sparse_form(h_init[1].clone(), builder, driver)?;
        let mut c = Self::map_into_maj_sparse_form(h_init[2].clone(), builder, driver)?;
        let mut d = SparseValue::new(h_init[3].clone(), builder, driver);
        let mut e = SparseValue::new(h_init[4].clone(), builder, driver);
        let mut f = Self::map_into_choose_sparse_form(h_init[5].clone(), builder, driver)?;
        let mut g = Self::map_into_choose_sparse_form(h_init[6].clone(), builder, driver)?;
        let mut h = SparseValue::new(h_init[7].clone(), builder, driver);
        // Extend witness
        let w = Self::extend_witness(input, builder, driver)?;

        // Apply SHA-256 compression function to the message schedule
        for i in 0..64 {
            let ch = Self::choose(&mut e, &f, &g, builder, driver)?;
            let maj = Self::majority(&mut a, &b, &c, builder, driver)?;
            let added = w[i].add(&FieldCT::from(F::from(ROUND_CONSTANTS[i])), builder, driver);
            let temp1 = ch.add_two(&h.normal, &added, builder, driver);

            h = g;
            g = f;
            f = e.clone();
            e.normal = Self::add_normalize(&d.normal, &temp1, builder, driver)?;
            d = c;
            c = b;
            b = a.clone();
            a.normal = Self::add_normalize(&temp1, &maj, builder, driver)?;
        }

        // Add into previous block output and return
        let mut output: [FieldCT<P::ScalarField>; 8] =
            array::from_fn(|_| FieldCT::<P::ScalarField>::default());
        output[0] = Self::add_normalize(&a.normal, &h_init[0], builder, driver)?;
        output[1] = Self::add_normalize(&b.normal, &h_init[1], builder, driver)?;
        output[2] = Self::add_normalize(&c.normal, &h_init[2], builder, driver)?;
        output[3] = Self::add_normalize(&d.normal, &h_init[3], builder, driver)?;
        output[4] = Self::add_normalize(&e.normal, &h_init[4], builder, driver)?;
        output[5] = Self::add_normalize(&f.normal, &h_init[5], builder, driver)?;
        output[6] = Self::add_normalize(&g.normal, &h_init[6], builder, driver)?;
        output[7] = Self::add_normalize(&h.normal, &h_init[7], builder, driver)?;
        // Apply 32-bit range checks on the outputs
        for output_elem in &mut output {
            output_elem.create_range_constraint(32, builder, driver)?;
        }

        Ok(output)
    }

    fn extend_witness<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        w_in: [FieldCT<F>; 16],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[FieldCT<F>; 64]> {
        let mut w_sparse: [SparseWitnessLimbs<F>; 64] =
            array::from_fn(|_| SparseWitnessLimbs::new(FieldCT::default()));

        for i in 0..16 {
            w_sparse[i] = SparseWitnessLimbs::new(w_in[i].clone());
        }

        for i in 16..64 {
            if !w_sparse[i - 15].has_sparse_limbs {
                w_sparse[i - 15] =
                    SparseWitnessLimbs::convert_witness(&w_sparse[i - 15].normal, builder, driver)?;
            }
            if !w_sparse[i - 2].has_sparse_limbs {
                w_sparse[i - 2] =
                    SparseWitnessLimbs::convert_witness(&w_sparse[i - 2].normal, builder, driver)?;
            }

            let base = F::from(16u64);
            let left_multipliers = [
                base.pow([32 - 7]) + base.pow([32 - 18]),
                base.pow([32 - 18 + 3]) + F::one(),
                base.pow([32 - 18 + 10]) + base.pow([10 - 7]) + base.pow([10 - 3]),
                base.pow([18 - 7]) + base.pow([18 - 3]) + F::one(),
            ];

            let right_multipliers = [
                base.pow([32 - 17]) + base.pow([32 - 19]),
                base.pow([32 - 17 + 3]) + base.pow([32 - 19 + 3]),
                base.pow([32 - 19 + 10]) + F::one(),
                base.pow([18 - 17]) + base.pow([18 - 10]),
            ];

            let left = [
                w_sparse[i - 15].sparse_limbs[0].multiply(
                    &FieldCT::from(left_multipliers[0]),
                    builder,
                    driver,
                )?,
                w_sparse[i - 15].sparse_limbs[1].multiply(
                    &FieldCT::from(left_multipliers[1]),
                    builder,
                    driver,
                )?,
                w_sparse[i - 15].sparse_limbs[2].multiply(
                    &FieldCT::from(left_multipliers[2]),
                    builder,
                    driver,
                )?,
                w_sparse[i - 15].sparse_limbs[3].multiply(
                    &FieldCT::from(left_multipliers[3]),
                    builder,
                    driver,
                )?,
            ];

            let right = [
                w_sparse[i - 2].sparse_limbs[0].multiply(
                    &FieldCT::from(right_multipliers[0]),
                    builder,
                    driver,
                )?,
                w_sparse[i - 2].sparse_limbs[1].multiply(
                    &FieldCT::from(right_multipliers[1]),
                    builder,
                    driver,
                )?,
                w_sparse[i - 2].sparse_limbs[2].multiply(
                    &FieldCT::from(right_multipliers[2]),
                    builder,
                    driver,
                )?,
                w_sparse[i - 2].sparse_limbs[3].multiply(
                    &FieldCT::from(right_multipliers[3]),
                    builder,
                    driver,
                )?,
            ];

            let added_two = left[0].add_two(&left[1], &left[2], builder, driver);
            let added_two = added_two.add_two(
                &left[3],
                &w_sparse[i - 15].rotated_limbs[1],
                builder,
                driver,
            );
            let left_xor_sparse =
                added_two.multiply(&FieldCT::from(F::from(4)), builder, driver)?;

            let added_two = right[0].add_two(&right[1], &right[2], builder, driver);
            let added_two = added_two.add_two(
                &right[3],
                &w_sparse[i - 2].rotated_limbs[2],
                builder,
                driver,
            );
            let added_two = added_two.add_two(
                &w_sparse[i - 2].rotated_limbs[3],
                &left_xor_sparse,
                builder,
                driver,
            );
            let xor_result_sparse = added_two.normalize(builder, driver);

            let xor_result = Plookup::read_from_1_to_2_table(
                builder,
                driver,
                MultiTableId::Sha256WitnessOutput,
                &xor_result_sparse,
            )?;

            // AZTEC TODO NORMALIZE WITH RANGE CHECK

            let w_out_raw = xor_result.add_two(
                &w_sparse[i - 16].normal,
                &w_sparse[i - 7].normal,
                builder,
                driver,
            );

            let w_out = if w_out_raw.is_constant() {
                let value = w_out_raw.get_value(builder, driver);
                let tmp = F::from((1u64 << 32) - 1);
                let res = T::integer_bitwise_and(driver, value, tmp.into(), 64)?;
                FieldCT::from(T::get_public(&res).expect("Constant should be public"))
            } else {
                let value = w_out_raw.get_value(builder, driver);
                let tmp = F::from((1u64 << 32) - 1);
                let res = T::integer_bitwise_and(driver, value, tmp.into(), 64)?;
                let w_out = FieldCT::from(WitnessCT::from_acvm_type(res, builder));

                let inv_pow_two = F::from(2u64).pow([32]).inverse().unwrap();
                // If we multiply the field elements by constants separately and then subtract, then the divisor is going to
                // be in a normalized state right after subtraction and the call to .normalize() won't add gates
                let w_out_raw_inv_pow_two =
                    w_out_raw.multiply(&FieldCT::from(inv_pow_two), builder, driver)?;
                let w_out_inv_pow_two =
                    w_out.multiply(&FieldCT::from(inv_pow_two), builder, driver)?;
                let divisor = (w_out_raw_inv_pow_two.sub(&w_out_inv_pow_two, builder, driver))
                    .normalize(builder, driver);
                builder.create_new_range_constraint(divisor.witness_index, 3);
                w_out
            };

            w_sparse[i] = SparseWitnessLimbs::new(w_out);
        }

        let mut w_extended = array::from_fn(|_| FieldCT::default());
        for i in 0..64 {
            w_extended[i] = w_sparse[i].normal.clone();
        }
        Ok(w_extended)
    }

    fn choose<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        e: &mut SparseValue<F>,
        f: &SparseValue<F>,
        g: &SparseValue<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        let lookup = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::Sha256ChInput,
            &e.normal,
            &FieldCT::default(),
            false,
        )?;

        let rotation_coefficients: [F; 3] = get_choose_rotation_multipliers();

        let rotation_result = lookup[ColumnIdx::C3][0].clone();

        e.sparse = lookup[ColumnIdx::C2][0].clone();

        let sparse_limb_3 = lookup[ColumnIdx::C2][2].clone();

        // where is the middle limb used
        let xor_result = rotation_result
            .multiply(&FieldCT::from(F::from(7)), builder, driver)?
            .add_two(
                &e.sparse.multiply(
                    &FieldCT::from(rotation_coefficients[0] * F::from(7) + F::one()),
                    builder,
                    driver,
                )?,
                &sparse_limb_3.multiply(
                    &FieldCT::from(rotation_coefficients[2] * F::from(7)),
                    builder,
                    driver,
                )?,
                builder,
                driver,
            );

        let choose_result_sparse = xor_result
            .add_two(
                &f.sparse.add(&f.sparse, builder, driver),
                &g.sparse
                    .add(&g.sparse, builder, driver)
                    .add(&g.sparse, builder, driver),
                builder,
                driver,
            )
            .normalize(builder, driver);

        let choose_result = Plookup::read_from_1_to_2_table(
            builder,
            driver,
            MultiTableId::Sha256ChOutput,
            &choose_result_sparse,
        )?;

        Ok(choose_result)
    }

    fn majority<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        a: &mut SparseValue<F>,
        b: &SparseValue<F>,
        c: &SparseValue<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        let lookup = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::Sha256MajInput,
            &a.normal,
            &FieldCT::default(),
            false,
        )?;

        let rotation_coefficients: [F; 3] = get_majority_rotation_multipliers();

        let rotation_result = lookup[ColumnIdx::C3][0].clone();

        a.sparse = lookup[ColumnIdx::C2][0].clone();

        let sparse_accumulator_2 = lookup[ColumnIdx::C2][1].clone();

        let xor_result = rotation_result
            .multiply(&FieldCT::from(F::from(4)), builder, driver)?
            .add_two(
                &a.sparse.multiply(
                    &FieldCT::from(rotation_coefficients[0] * F::from(4) + F::one()),
                    builder,
                    driver,
                )?,
                &sparse_accumulator_2.multiply(
                    &FieldCT::from(rotation_coefficients[1] * F::from(4)),
                    builder,
                    driver,
                )?,
                builder,
                driver,
            );

        let majority_result_sparse = xor_result
            .add_two(&b.sparse, &c.sparse, builder, driver)
            .normalize(builder, driver);

        let majority_result = Plookup::read_from_1_to_2_table(
            builder,
            driver,
            MultiTableId::Sha256MajOutput,
            &majority_result_sparse,
        )?;

        Ok(majority_result)
    }

    fn add_normalize<P: Pairing<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        a: &FieldCT<F>,
        b: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        if a.is_constant() && b.is_constant() {
            let a_value = a.get_value(builder, driver);
            let b_value = b.get_value(builder, driver);

            let a_val = T::get_public(&a_value).expect("Already checked it is public");
            let b_val = T::get_public(&b_value).expect("Already checked it is public");

            let sum: BigUint = (a_val + b_val).into();

            let normalized_sum = F::from(sum % (1u64 << 32));

            Ok(FieldCT::from(normalized_sum))
        } else {
            let a_value = a.get_value(builder, driver);
            let b_value = b.get_value(builder, driver);

            let sum = T::add(driver, a_value, b_value);
            let overflow = if T::is_shared(&sum) {
                let sum_val = T::get_shared(&sum).expect("Already checked it is shared");
                FieldCT::from_witness(T::sha256_get_overflow_bit(driver, sum_val)?.into(), builder)
            } else {
                let sum_val: BigUint = T::get_public(&sum)
                    .expect("Already checked it is public")
                    .into();
                let normalized_sum = sum_val.iter_u32_digits().next().unwrap_or_default();
                let overflow = (sum_val - normalized_sum) >> 32;
                FieldCT::from_witness(F::from(overflow).into(), builder)
            };

            let result = a.add_two(
                b,
                &overflow.multiply(&FieldCT::from(-F::from(1u64 << 32)), builder, driver)?,
                builder,
                driver,
            );

            overflow.create_range_constraint(3, builder, driver)?;
            Ok(result)
        }
    }

    fn map_into_maj_sparse_form<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        e: FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<SparseValue<F>> {
        let sparse =
            Plookup::read_from_1_to_2_table(builder, driver, MultiTableId::Sha256MajInput, &e)?;
        let normal = e;

        Ok(SparseValue { normal, sparse })
    }

    fn map_into_choose_sparse_form<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        e: FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<SparseValue<F>> {
        let sparse =
            Plookup::read_from_1_to_2_table(builder, driver, MultiTableId::Sha256ChInput, &e)?;
        let normal = e;

        Ok(SparseValue { normal, sparse })
    }
}

fn get_choose_rotation_multipliers<F: PrimeField>() -> [F; 3] {
    let base: u64 = 28;
    let column_2_row_3_coefficients = [F::one(), F::from(base.pow(11)), F::from(base).pow([22])];

    // Scaling factors applied to a's sparse limbs, excluding the rotated limb
    let rot6_coefficients = [
        F::zero(),
        F::from(base.pow(11 - 6)),
        F::from(base).pow([22 - 6]),
    ];
    let rot11_coefficients = [
        F::from(base).pow([32 - 11]),
        F::zero(),
        F::from(base.pow(22 - 11)),
    ];
    let rot25_coefficients = [
        F::from(base.pow(32 - 25)),
        F::from(base).pow([32 - 25 + 11]),
        F::zero(),
    ];

    // These are the coefficients that we want
    let target_rotation_coefficients = [
        rot6_coefficients[0] + rot11_coefficients[0] + rot25_coefficients[0],
        rot6_coefficients[1] + rot11_coefficients[1] + rot25_coefficients[1],
        rot6_coefficients[2] + rot11_coefficients[2] + rot25_coefficients[2],
    ];

    let column_2_row_1_multiplier = target_rotation_coefficients[0];

    // This gives us the correct scaling factor for a0's 1st limb
    let current_coefficients = [
        column_2_row_3_coefficients[0] * column_2_row_1_multiplier,
        column_2_row_3_coefficients[1] * column_2_row_1_multiplier,
        column_2_row_3_coefficients[2] * column_2_row_1_multiplier,
    ];

    let column_2_row_3_multiplier = -current_coefficients[2] + target_rotation_coefficients[2];

    [
        column_2_row_1_multiplier,
        F::zero(),
        column_2_row_3_multiplier,
    ]
}

fn get_majority_rotation_multipliers<F: PrimeField>() -> [F; 3] {
    let base: u64 = 16;

    // Scaling factors applied to a's sparse limbs, excluding the rotated limb
    let rot2_coefficients = [
        F::zero(),
        F::from(base.pow(11 - 2)),
        F::from(base).pow([22 - 2]),
    ];
    let rot13_coefficients = [
        F::from(base).pow([32 - 13]),
        F::zero(),
        F::from(base.pow(22 - 13)),
    ];
    let rot22_coefficients = [
        F::from(base.pow(32 - 22)),
        F::from(base).pow([32 - 22 + 11]),
        F::zero(),
    ];

    // These are the coefficients that we want
    let target_rotation_coefficients = [
        rot2_coefficients[0] + rot13_coefficients[0] + rot22_coefficients[0],
        rot2_coefficients[1] + rot13_coefficients[1] + rot22_coefficients[1],
        rot2_coefficients[2] + rot13_coefficients[2] + rot22_coefficients[2],
    ];

    let column_2_row_1_multiplier = target_rotation_coefficients[0];
    let column_2_row_2_multiplier = target_rotation_coefficients[0] * (-F::from(base.pow(11)))
        + target_rotation_coefficients[1];

    [
        column_2_row_1_multiplier,
        column_2_row_2_multiplier,
        F::zero(),
    ]
}
