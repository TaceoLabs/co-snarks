use core::num;
use std::cmp::max;
use std::{array, clone};

use crate::prelude::offset_generator;
use crate::types::big_field::BigField;
use crate::types::field_ct::WitnessCT;
use crate::types::rom_ram::TwinRomTable;
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;

use super::field_ct::BoolCT;

pub struct BigGroup<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> {
    pub(crate) x: BigField<F>,
    pub(crate) y: BigField<F>,
    pub(crate) is_infinity: BoolCT<F, T>,
}

impl<F, T> Clone for BigGroup<F, T>
where
    F: PrimeField,
    T: NoirWitnessExtensionProtocol<F>,
{
    fn clone(&self) -> Self {
        BigGroup {
            x: BigField {
                binary_basis_limbs: self.x.binary_basis_limbs.clone(),
                prime_basis_limb: self.x.prime_basis_limb.clone(),
            },
            y: BigField {
                binary_basis_limbs: self.y.binary_basis_limbs.clone(),
                prime_basis_limb: self.y.prime_basis_limb.clone(),
            },
            is_infinity: self.is_infinity.clone(),
        }
    }
}

impl<F, T> Default for BigGroup<F, T>
where
    F: PrimeField,
    T: NoirWitnessExtensionProtocol<F>,
{
    fn default() -> Self {
        todo!();
    }
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> BigGroup<F, T> {
    pub(crate) fn new(x: BigField<F>, y: BigField<F>) -> Self {
        BigGroup {
            x,
            y,
            is_infinity: BoolCT::from(false),
        }
    }

    /// Set the witness indices for the x and y coordinates to public
    ///
    /// Returns the index at which the representation is stored in the public inputs.
    pub(crate) fn set_public<P: CurveGroup<ScalarField = F>>(
        &self,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> usize {
        let start_idx = self.x.set_public(driver, builder);
        self.y.set_public(driver, builder);

        start_idx
    }

    pub fn set_is_infinity(&mut self, is_infinity: BoolCT<F, T>) {
        self.is_infinity = is_infinity;
    }

    pub fn one<P: CurveGroup<ScalarField = F>>(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        Ok(BigGroup {
            x: BigField::from_witness(&F::ONE.into(), driver, builder)?,
            y: BigField::from_witness(&F::from(2).into(), driver, builder)?,
            is_infinity: BoolCT::from(false),
        })
    }

    /**
     * @brief Generic batch multiplication that works for all elliptic curve types.
     *
     * @details Implementation is identical to `bn254_endo_batch_mul` but WITHOUT the endomorphism transforms OR support for
     * short scalars See `bn254_endo_batch_mul` for description of algorithm.
     *
     * @tparam C The circuit builder type.
     * @tparam Fq The field of definition of the points in `_points`.
     * @tparam Fr The field of scalars acting on `_points`.
     * @tparam G The group whose arithmetic is emulated by `element`.
     * @param _points
     * @param _scalars
     * @param max_num_bits The max of the bit lengths of the scalars.
     * @param with_edgecases Use when points are linearly dependent. Randomises them.
     * @return element<C, Fq, Fr, G>
     */
    pub fn batch_mul<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        points: &[Self],
        scalars: &[FieldCT<F>],
        max_num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let (points, scalars) =
            BigGroup::handle_points_at_infinity(points, scalars, builder, driver)?;

        // TODO TACEO: Origin tags?

        // Perform goblinized batched mul if available; supported only for BN254
        // with_edgecases == true
        let (points, scalars) = BigGroup::mask_points(&points, &scalars, builder, driver)?;

        assert_eq!(points.len(), scalars.len());
        let mut point_table = BatchLookupTablePlookup::new(&points, builder, driver)?;

        let mut naf_entries = Vec::with_capacity(points.len());
        for i in 0..points.len() {
            naf_entries.push(Self::compute_naf(
                &scalars[i],
                max_num_bits,
                builder,
                driver,
            )?);
        }

        let offset_generators = Self::compute_offset_generators::<P>(max_num_bits)?;

        let mut accumulator = Self::chain_add_end(
            Self::chain_add(
                &offset_generators.0,
                &point_table.get_chain_initial_entry(builder, driver)?,
                builder,
                driver,
            )?,
            builder,
            driver,
        )?;

        let num_rounds = if max_num_bits == 0 {
            (P::ScalarField::MODULUS_BIT_SIZE + 1) as usize
        } else {
            max_num_bits
        };
        let num_rounds_per_iteration = 4;
        let mut num_iterations = num_rounds / num_rounds_per_iteration;
        num_iterations += if num_rounds % num_rounds_per_iteration != 0 {
            1
        } else {
            0
        };
        let num_rounds_per_final_iteration =
            (num_rounds - 1) - ((num_iterations - 1) * num_rounds_per_iteration);

        for i in 0..num_iterations {
            let mut nafs = Vec::with_capacity(points.len());
            let mut to_add = Vec::with_capacity(points.len());
            let inner_num_rounds = if i != num_iterations - 1 {
                num_rounds_per_iteration
            } else {
                num_rounds_per_final_iteration
            };
            for j in 0..inner_num_rounds {
                for k in 0..points.len() {
                    nafs.push(naf_entries[k][i * num_rounds_per_iteration + j + 1].clone());
                }
                to_add.push(point_table.get_chain_add_accumulator(&nafs, builder, driver)?);
            }
            accumulator = accumulator.multiple_montgomery_ladder(&to_add, builder, driver)?;
        }

        for i in 0..points.len() {
            let skew = accumulator.sub(&points[i], builder, driver)?;
            let out_x = BigField::conditional_select(
                &naf_entries[i][0],
                &accumulator.x,
                &skew.x,
                builder,
                driver,
            )?;

            let out_y = BigField::conditional_select(
                &naf_entries[i][0],
                &accumulator.y,
                &skew.y,
                builder,
                driver,
            )?;
            accumulator = BigGroup::new(out_x, out_y);
        }
        accumulator.sub(&offset_generators.1, builder, driver)
    }

    /**
     * @brief Perform repeated iterations of the montgomery ladder algorithm.
     *
     * For points P, Q, montgomery ladder computes R = (P + Q) + P
     * i.e. it's "double-and-add" without explicit doublings.
     *
     * This method can apply repeated iterations of the montgomery ladder.
     * Each iteration reduces the number of field multiplications by 1, at the cost of more additions.
     * (i.e. we don't compute intermediate y-coordinates).
     *
     * The number of additions scales with the size of the input vector. The optimal input size appears to be 4.
     *
     * @tparam C
     * @tparam Fq
     * @tparam Fr
     * @tparam G
     * @param add
     * @return element<C, Fq, Fr, G>
     */
    fn multiple_montgomery_ladder<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        add: &[ChainAddAccumulator<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        struct CompositeY<F: PrimeField> {
            mul_left: Vec<BigField<F>>,
            mul_right: Vec<BigField<F>>,
            add: Vec<BigField<F>>,
            is_negative: bool,
        }

        let mut previous_x = self.x.clone();
        let mut previous_y = CompositeY {
            mul_left: vec![],
            mul_right: vec![],
            add: vec![],
            is_negative: false,
        };

        for i in 0..add.len() {
            previous_x.assert_is_not_equal(&add[i].x3_prev, builder, driver)?;

            // composite y add_y
            let negate_add_y = (i > 0) && previous_y.is_negative;
            let mut lambda1_left = Vec::new();
            let mut lambda1_right = Vec::new();
            let mut lambda1_add = Vec::new();

            if i == 0 {
                lambda1_add.push(self.y.neg(builder, driver)?);
            } else {
                lambda1_left = previous_y.mul_left.clone();
                lambda1_right = previous_y.mul_right.clone();
                lambda1_add = previous_y.add.clone();
            }

            if !add[i].is_element {
                lambda1_left.push(add[i].lambda_prev.clone());
                lambda1_right.push(if negate_add_y {
                    add[i].x3_prev.sub(&add[i].x1_prev, builder, driver)?
                } else {
                    add[i].x1_prev.sub(&add[i].x3_prev, builder, driver)?
                });
                lambda1_add.push(if negate_add_y {
                    add[i].y1_prev.neg(builder, driver)?
                } else {
                    add[i].y1_prev.clone()
                });
            } else {
                lambda1_add.push(if negate_add_y {
                    add[i].y3_prev.neg(builder, driver)?
                } else {
                    add[i].y3_prev.clone()
                });
            }

            // if previous_y is negated then add stays positive
            // if previous_y is positive then add stays negated
            // | add.y is negated | previous_y is negated | output of msub_div is -lambda |
            // | --- | --- | --- |
            // | no  | yes | yes |
            // | yes | no  | no  |

            let lambda1 = if (!add[i].is_element || i > 0) {
                let denominator = if !negate_add_y {
                    previous_x.sub(&add[i].x3_prev, builder, driver)?
                } else {
                    add[i].x3_prev.sub(&previous_x, builder, driver)?
                };
                BigField::msub_div(
                    &lambda1_left,
                    &lambda1_right,
                    &denominator,
                    &lambda1_add,
                    false,
                    builder,
                    driver,
                )?
            } else {
                BigField::div_without_denominator_check(
                    &[add[i].y3_prev.sub(&self.y, builder, driver)?],
                    &add[i].x3_prev.sub(&self.x, builder, driver)?,
                    builder,
                    driver,
                )?
            };

            let x_3 = lambda1.madd(
                &lambda1,
                &[
                    add[i].x3_prev.neg(builder, driver)?,
                    previous_x.neg(builder, driver)?,
                ],
                builder,
                driver,
            )?;

            // We can avoid computing y_4, instead substituting the expression `minus_lambda_2 * (x_4 - x) - y` where
            // needed. This is cheaper, because we can evaluate two field multiplications (or a field multiplication + a
            // field division) with only one non-native field reduction. E.g. evaluating (a * b) + (c * d) = e mod p only
            // requires 1 quotient and remainder, which is the major cost of a non-native field multiplication
            let lambda2 = if i == 0 {
                BigField::div_without_denominator_check(
                    &[self.y.add(&self.y, builder, driver)?],
                    &previous_x.sub(&x_3, builder, driver)?,
                    builder,
                    driver,
                )?
                .sub(&lambda1, builder, driver)?
            } else {
                let l2_denominator = if previous_y.is_negative {
                    previous_x.sub(&x_3, builder, driver)?
                } else {
                    x_3.sub(&previous_x, builder, driver)?
                };
                let partial_lambda2 = BigField::msub_div(
                    &previous_y.mul_left,
                    &previous_y.mul_right,
                    &l2_denominator,
                    &previous_y.add,
                    false,
                    builder,
                    driver,
                )?;
                let partial_lambda2 = partial_lambda2.add(&partial_lambda2, builder, driver)?;
                partial_lambda2.sub(&lambda1, builder, driver)?
            };

            let x_4 = lambda2.sqradd(
                &[x_3.neg(builder, driver)?, previous_x.neg(builder, driver)?],
                builder,
                driver,
            )?;

            let mut y_4 = CompositeY {
                mul_left: vec![],
                mul_right: vec![],
                add: vec![],
                is_negative: false,
            };

            if i == 0 {
                // We want to make sure that at the final iteration, `y_previous.is_negative = false`
                // Each iteration flips the sign of y_previous.is_negative.
                // i.e. whether we store y_4 or -y_4 depends on the number of points we have
                let num_points_even = add.len() % 2 == 0;
                y_4.add.push(if num_points_even {
                    self.y.clone()
                } else {
                    self.y.neg(builder, driver)?
                });
                y_4.mul_left.push(lambda2.clone());
                y_4.mul_right.push(if num_points_even {
                    x_4.sub(&previous_x, builder, driver)?
                } else {
                    previous_x.sub(&x_4, builder, driver)?
                });
                y_4.is_negative = num_points_even;
            } else {
                y_4.is_negative = !previous_y.is_negative;
                y_4.mul_left.push(lambda2.clone());
                y_4.mul_right.push(if previous_y.is_negative {
                    previous_x.sub(&x_4, builder, driver)?
                } else {
                    x_4.sub(&previous_x, builder, driver)?
                });

                // append terms in previous_y to y_4. We want to make sure the terms above are added into the start of y_4.
                // This is to ensure they are cached correctly when
                // `builder::evaluate_partial_non_native_field_multiplication` is called.
                // (the 1st mul_left, mul_right elements will trigger builder::evaluate_non_native_field_multiplication
                //  when Fq::mult_madd is called - this term cannot be cached so we want to make sure it is unique)
                // TODO CESAR: Verify this is correct
                y_4.mul_left.extend(previous_y.mul_left.iter().cloned());
                y_4.mul_right.extend(previous_y.mul_right.iter().cloned());
                y_4.add.extend(previous_y.add.iter().cloned());
            }
            previous_x = x_4;
            previous_y = y_4;
        }
        let x_out = previous_x;
        assert!(
            !previous_y.is_negative,
            "Final y coordinate cannot be negative"
        );
        let y_out = BigField::mult_madd(
            previous_y.mul_left.as_slice(),
            previous_y.mul_right.as_slice(),
            previous_y.add.as_slice(),
            // TODO CESAR: What should this boolean flag be?
            false,
            builder,
            driver,
        )?;

        Ok(BigGroup::new(x_out, y_out))
    }

    pub fn compute_offset_generators<P: CurveGroup<ScalarField = F>>(
        num_rounds: usize,
    ) -> eyre::Result<(Self, Self)> {
        let offset_generator = offset_generator::<P>("biggroup batch mul offset generator");
        let offset_multiplier = F::from(2u64).pow([(num_rounds - 1) as u64]);
        let offset_generator_end = (offset_generator * offset_multiplier).into();
        todo!("convert to BigGroup")
    }

    pub fn compute_naf<P: CurveGroup<ScalarField = F>>(
        scalar: &FieldCT<F>,
        max_num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Vec<BoolCT<F, T>>> {
        // We are not handling the case of odd bit lengths here.
        assert!(max_num_bits % 2 == 0);

        let num_rounds = if max_num_bits == 0 {
            (P::ScalarField::MODULUS_BIT_SIZE + 1) as usize
        } else {
            max_num_bits
        };

        let scalar_value = scalar.get_value(builder, driver);
        let naf_entries_acvm_type = driver.compute_naf_entries(&scalar_value, max_num_bits)?;
        let mut naf_entries = Vec::with_capacity(num_rounds + 1);
        naf_entries[num_rounds] = BoolCT::from_witness_ct(
            WitnessCT::from_acvm_type(naf_entries_acvm_type[num_rounds].clone(), builder),
            builder,
        );

        for i in 0..num_rounds - 1 {
            // if the next entry is false, we need to flip the sign of the current entry. i.e. make negative
            // This is a VERY hacky workaround to ensure that UltraPlonkBuilder will apply a basic
            // range constraint per bool, and not a full 1-bit range gate
            // TODO CESAR: Check if this is correct
            let bit = BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(
                    naf_entries_acvm_type[num_rounds - i - 1].clone(),
                    builder,
                ),
                builder,
            );

            builder.create_new_range_constraint(bit.witness_index, 1);
        }
        naf_entries[0] = BoolCT::from(false);

        // Validate correctness of NAF
        // TODO CESAR: Fr is composite?
        let mut accumulators = Vec::with_capacity(num_rounds + 1);
        let minus_two = FieldCT::from_witness(F::from(2u64).into(), builder);
        let one = FieldCT::from_witness(F::ONE.into(), builder);
        for i in 0..num_rounds {
            // bit = 1 - 2 * naf
            let shift = FieldCT::from_witness(F::from(1u64 << (2 * i as u32)).into(), builder);

            let entry = naf_entries[naf_entries.len() - 2 - i]
                .to_field_ct(driver)
                .multiply(&minus_two, builder, driver)?
                .add(&one, builder, driver)
                .multiply(&shift, builder, driver)?;

            accumulators.push(entry);
        }

        let minus_one = FieldCT::from_witness((-F::from(1)).into(), builder);
        accumulators.push(
            naf_entries[num_rounds]
                .to_field_ct(driver)
                .multiply(&minus_one, builder, driver)?,
        );

        // TODO CESAR: FieldCT::accumulate
        let mut total = FieldCT::from_witness(F::ZERO.into(), builder);
        for acc in accumulators.iter() {
            total = total.add(acc, builder, driver);
        }
        scalar.assert_equal(&total, builder, driver);

        // TACEO TODO: Origin tags?
        Ok(naf_entries)
    }

    /**
     * @brief Compute (*this) + other AND (*this) - other as a size-2 array
     *
     * @details We require this operation when computing biggroup lookup tables for
     *          multi-scalar-multiplication. This combined method reduces the number of
     *          field additions, field subtractions required (as well as 1 less assert_is_not_equal check)
     *
     * @tparam C
     * @tparam Fq
     * @tparam Fr
     * @tparam G
     * @param other
     * @return std::array<element<C, Fq, Fr, G>, 2>
     */
    // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/657): This function is untested
    pub fn checked_unconditional_add_sub<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(Self, Self)> {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/971): This will fail when the two elements are the
        // same even in the case of a valid circuit
        other.x.assert_is_not_equal(&self.x, builder, driver)?;

        let denominator = other.x.sub(&self.x, builder, driver)?;
        let x2x1 = other
            .x
            .add(&self.x, builder, driver)?
            .neg(builder, driver)?;

        let lambda1 = BigField::div_without_denominator_check(
            &[other.y.clone(), self.y.neg(builder, driver)?],
            &denominator,
            builder,
            driver,
        )?;
        let x_3 = lambda1.sqradd(&[x2x1.clone()], builder, driver)?;
        let y_3 = lambda1.madd(
            &self.x.sub(&x_3, builder, driver)?,
            &[self.y.neg(builder, driver)?],
            builder,
            driver,
        )?;

        let lambda2 = BigField::div_without_denominator_check(
            &[other.y.neg(builder, driver)?, self.y.neg(builder, driver)?],
            &denominator,
            builder,
            driver,
        )?;
        let x_4 = lambda2.sqradd(&[x2x1], builder, driver)?;
        let y_4 = lambda2.madd(
            &other.x.sub(&x_4, builder, driver)?,
            &[other.y.neg(builder, driver)?],
            builder,
            driver,
        )?;

        Ok((BigGroup::new(x_3, y_3), BigGroup::new(x_4, y_4)))
    }

    fn add<P: CurveGroup<ScalarField = F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // Adding in `x_coordinates_match` ensures that lambda will always be well-formed
        // Our curve has the form y^2 = x^3 + b.
        // If (x_1, y_1), (x_2, y_2) have x_1 == x_2, and the generic formula for lambda has a division by 0.
        // Then y_1 == y_2 (i.e. we are doubling) or y_2 == y_1 (the sum is infinity).
        // The cases have a special addition formula. The following booleans allow us to handle these cases uniformly.
        todo!();
    }

    fn sub<P: CurveGroup<ScalarField = F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        todo!();
    }

    pub fn neg<P: CurveGroup<ScalarField = F>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        todo!();
    }

    fn normalize_in_place<P: CurveGroup<ScalarField = F>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        todo!();
    }

    fn conditional_negate<P: CurveGroup<ScalarField = F>>(
        &self,
        cond: &BoolCT<F, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        todo!();
    }

    /**
     * @brief Given two lists of points that need to be multiplied by scalars, create a new list of length +1 with original
     * points masked, but the same scalar product sum
     * @details Add +1G, +2G, +4G etc to the original points and adds a new point 2ⁿ⋅G and scalar x to the lists. By
     * doubling the point every time, we ensure that no +-1 combination of 6 sequential elements run into edgecases, unless
     * the points are deliberately constructed to trigger it.
     */
    fn mask_points<P: CurveGroup<ScalarField = F>>(
        points: &[Self],
        scalars: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(Vec<Self>, Vec<FieldCT<F>>)> {
        let mut masked_points = Vec::new();
        let mut masked_scalars = Vec::new();

        debug_assert!(points.len() == scalars.len());
        let mut running_scalar = F::ONE;

        // Get the offset generator G_offset in native and in-circuit form
        let native_offset_generator = offset_generator::<P>("biggroup table offset generator");
        let generator_coefficient = F::from(2u64).pow([points.len() as u64]);
        let generator_coefficient_inverse = generator_coefficient
            .inverse()
            .expect("Generator coefficient should have an inverse");

        let mut last_scalar = FieldCT::from_witness(F::ZERO.into(), builder);

        // For each point and scalar
        for (point, scalar) in points.iter().zip(scalars.iter()) {
            masked_scalars.push(scalar.clone());

            // Convert point into point + 2ⁱ⋅G_offset
            masked_points.push(point.add_native_point(
                &(native_offset_generator * running_scalar).into(),
                builder,
                driver,
            )?);

            // Add \frac{2ⁱ⋅scalar}{2ⁿ} to the last scalar
            let tmp = FieldCT::from_witness(
                (running_scalar * generator_coefficient_inverse).into(),
                builder,
            );
            last_scalar.add_assign(&scalar.multiply(&tmp, builder, driver)?, builder, driver);

            // Double the running_scalar
            running_scalar *= F::from(2u64);
        }

        // Add a scalar -(<(1,2,4,...,2ⁿ⁻¹ ),(scalar₀,...,scalarₙ₋₁)> / 2ⁿ)
        masked_scalars.push(last_scalar.neg());

        // TODO CESAR: Fr is composite?

        // Add in-circuit G_offset to points
        let g_offset = native_offset_generator * generator_coefficient;
        masked_points.push(todo!());

        Ok((masked_points, masked_scalars))
    }

    fn add_native_point<P: CurveGroup<ScalarField = F>>(
        &self,
        native_point_to_add: &P::Affine,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        todo!();
    }

    /**
     * @brief Replace all pairs (∞, scalar) by the pair (one, 0) where one is a fixed generator of the curve
     * @details This is a step in enabling our our multiscalar multiplication algorithms to hande points at infinity.
     */
    // TODO CESAR: Batch FieldCT ops
    fn handle_points_at_infinity<P: CurveGroup<ScalarField = F>>(
        points: &[Self],
        scalars: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(Vec<Self>, Vec<FieldCT<F>>)> {
        let one = Self::one(builder, driver)?;
        let mut new_points = Vec::new();
        let mut new_scalars = Vec::new();

        for (point, scalar) in points.iter().zip(scalars.iter()) {
            let is_infinity = &point.is_infinity;

            if is_infinity.is_constant() && is_infinity.get_value(driver) == F::ONE.into() {
                // if point is at infinity and a circuit constant we can just skip.
                continue;
            }

            if scalar.is_constant()
                && scalar.get_value(builder, driver) == P::ScalarField::ZERO.into()
            {
                // if scalar is zero and a circuit constant we can just skip.
                continue;
            }

            let updated_x =
                BigField::conditional_select(is_infinity, &one.x, &point.x, builder, driver)?;
            let updated_y =
                BigField::conditional_select(is_infinity, &one.y, &point.y, builder, driver)?;

            let updated_scalar = FieldCT::conditional_assign(
                is_infinity,
                &FieldCT::from_witness(F::ZERO.into(), builder),
                &scalar,
                builder,
                driver,
            )?;

            new_points.push(BigGroup::new(updated_x, updated_y));
            new_scalars.push(updated_scalar);

            // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1002): if both point and scalar are constant,
            // don't bother adding constraints
        }

        return Ok((new_points, new_scalars));
    }

    /**
     * Evaluate a chain addition!
     *
     * When adding a set of points P_1 + ... + P_N, we do not need to compute the y-coordinate of intermediate addition
     *terms.
     *
     * i.e. we substitute `acc.y` with `acc.y = acc.lambda_prev * (acc.x1_prev - acc.x) - acc.y1_prev`
     *
     * `lambda_prev, x1_prev, y1_prev` are the `lambda, x1, y1` terms from the previous addition operation.
     *
     * `chain_add` requires 1 less non-native field reduction than a regular add operation.
     **/

    /**
     * begin a chain of additions
     * input points p1 p2
     * output accumulator = x3_prev (output x coordinate), x1_prev, y1_prev (p1), lambda_prev (y2 - y1) / (x2 - x1)
     **/
    pub(crate) fn chain_add_start<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        p1: &Self,
        p2: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        p1.x.assert_is_not_equal(&p2.x, builder, driver);
        let lambda = BigField::div_without_denominator_check(
            &[p2.y.clone(), p1.y.neg(builder, driver)?],
            &p2.x.sub(&p1.x, builder, driver)?,
            builder,
            driver,
        )?;

        let x3 = lambda.sqradd(
            &[p2.x.neg(builder, driver)?, p1.x.neg(builder, driver)?],
            builder,
            driver,
        )?;

        Ok(ChainAddAccumulator {
            x1_prev: p1.x.clone(),
            y1_prev: p1.y.clone(),
            lambda_prev: lambda,
            x3_prev: x3,
            y3_prev: Default::default(),
            is_element: false,
        })
    }

    pub(crate) fn chain_add<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        p1: &Self,
        acc: &ChainAddAccumulator<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        // use `chain_add_start` to start an addition chain (i.e. if acc has a y-coordinate)
        if acc.is_element {
            Self::chain_add_start(
                p1,
                &BigGroup {
                    x: acc.x3_prev.clone(),
                    y: acc.y3_prev.clone(),
                    is_infinity: BoolCT::from(false),
                },
                builder,
                driver,
            )
        } else {
            // validate we can use incomplete addition formulae
            p1.x.assert_is_not_equal(&acc.x3_prev, builder, driver)?;

            // lambda = (y2 - y1) / (x2 - x1)
            // but we don't have y2!
            // however, we do know that y2 = lambda_prev * (x1_prev - x2) - y1_prev
            // => lambda * (x2 - x1) = lambda_prev * (x1_prev - x2) - y1_prev - y1
            // => lambda * (x2 - x1) + lambda_prev * (x2 - x1_prev) + y1 + y1_prev = 0
            // => lambda = lambda_prev * (x1_prev - x2) - y1_prev - y1 / (x2 - x1)
            // => lambda = - (lambda_prev * (x2 - x1_prev) + y1_prev + y1) / (x2 - x1)

            let x2 = &acc.x3_prev;
            let lambda = BigField::msub_div(
                std::slice::from_ref(&acc.lambda_prev),
                &[x2.sub(&acc.x1_prev, builder, driver)?],
                &x2.sub(&p1.x, builder, driver)?,
                &[acc.y1_prev.clone(), p1.y.clone()],
                false,
                builder,
                driver,
            )?;

            let x3 = lambda.sqradd(
                &[x2.neg(builder, driver)?, p1.x.neg(builder, driver)?],
                builder,
                driver,
            )?;

            Ok(ChainAddAccumulator {
                x1_prev: p1.x.clone(),
                y1_prev: p1.y.clone(),
                lambda_prev: lambda,
                x3_prev: x3,
                y3_prev: Default::default(),
                is_element: false,
            })
        }
    }

    /**
     * End an addition chain. Produces a full output group element with a y-coordinate
     **/
    fn chain_add_end<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        acc: ChainAddAccumulator<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigGroup<F, T>> {
        if acc.is_element {
            return Ok(BigGroup::new(acc.x3_prev, acc.y3_prev));
        }
        let x3 = acc.x3_prev;
        let lambda = acc.lambda_prev;

        let y3 = lambda.madd(
            &acc.x1_prev.sub(&x3, builder, driver)?,
            &[acc.y1_prev.neg(builder, driver)?],
            builder,
            driver,
        )?;

        Ok(BigGroup::new(x3, y3))
    }
}

pub struct LookupTablePlookup<const SIZE: usize, F: PrimeField, T: NoirWitnessExtensionProtocol<F>>
{
    element_table: [BigGroup<F, T>; SIZE],
    coordinates: [TwinRomTable<F>; 5],
    limb_max: [BigUint; 8],
}

impl<const SIZE: usize, F: PrimeField, T: NoirWitnessExtensionProtocol<F>>
    LookupTablePlookup<SIZE, F, T>
{
    pub fn new<const LENGTH: usize, P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        inputs: [BigGroup<F, T>; LENGTH],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        assert_eq!(1 << LENGTH, SIZE);
        let mut element_table = array::from_fn(|_| BigGroup::default());

        if LENGTH == 2 {
            let (a0, a1) = inputs[1].checked_unconditional_add_sub(&inputs[0], builder, driver)?;
            element_table[0] = a0;
            element_table[1] = a1;
        } else if LENGTH == 3 {
            let (r0, r1) = inputs[1].checked_unconditional_add_sub(&inputs[0], builder, driver)?;
            let (t0, t1) = inputs[2].checked_unconditional_add_sub(&r0, builder, driver)?;
            let (t2, t3) = inputs[2].checked_unconditional_add_sub(&r1, builder, driver)?;

            element_table[0] = t0;
            element_table[1] = t2;
            element_table[2] = t3;
            element_table[3] = t1;
        } else if LENGTH == 4 {
            let (t0, t1) = inputs[1].checked_unconditional_add_sub(&inputs[0], builder, driver)?;
            let (t2, t3) = inputs[3].checked_unconditional_add_sub(&inputs[2], builder, driver)?;

            let (f0, f3) = t2.checked_unconditional_add_sub(&t0, builder, driver)?;
            let (f1, f2) = t2.checked_unconditional_add_sub(&t1, builder, driver)?;
            let (f4, f7) = t3.checked_unconditional_add_sub(&t0, builder, driver)?;
            let (f5, f6) = t3.checked_unconditional_add_sub(&t1, builder, driver)?;

            element_table[0] = f0;
            element_table[1] = f1;
            element_table[2] = f2;
            element_table[3] = f3;
            element_table[4] = f4;
            element_table[5] = f5;
            element_table[6] = f6;
            element_table[7] = f7;
        } else if LENGTH == 5 {
            let (a0, a1) = inputs[1].checked_unconditional_add_sub(&inputs[0], builder, driver)?;
            let (t2, t3) = inputs[3].checked_unconditional_add_sub(&inputs[2], builder, driver)?;

            let (e0, e3) = inputs[4].checked_unconditional_add_sub(&t2, builder, driver)?;
            let (e1, e2) = inputs[4].checked_unconditional_add_sub(&t3, builder, driver)?;

            let (f0, f3) = e0.checked_unconditional_add_sub(&a0, builder, driver)?;
            let (f1, f2) = e0.checked_unconditional_add_sub(&a1, builder, driver)?;
            let (f4, f7) = e1.checked_unconditional_add_sub(&a0, builder, driver)?;
            let (f5, f6) = e1.checked_unconditional_add_sub(&a1, builder, driver)?;
            let (f8, f11) = e2.checked_unconditional_add_sub(&a0, builder, driver)?;
            let (f9, f10) = e2.checked_unconditional_add_sub(&a1, builder, driver)?;
            let (f12, f15) = e3.checked_unconditional_add_sub(&a0, builder, driver)?;
            let (f13, f14) = e3.checked_unconditional_add_sub(&a1, builder, driver)?;

            element_table[0] = f0;
            element_table[1] = f1;
            element_table[2] = f2;
            element_table[3] = f3;
            element_table[4] = f4;
            element_table[5] = f5;
            element_table[6] = f6;
            element_table[7] = f7;
            element_table[8] = f8;
            element_table[9] = f9;
            element_table[10] = f10;
            element_table[11] = f11;
            element_table[12] = f12;
            element_table[13] = f13;
            element_table[14] = f14;
            element_table[15] = f15;
        } else if LENGTH == 6 {
            // 44 adds! Only use this if it saves us adding another table to a multi-scalar-multiplication

            let (a0, a1) = inputs[1].checked_unconditional_add_sub(&inputs[0], builder, driver)?;
            let (e0, e1) = inputs[4].checked_unconditional_add_sub(&inputs[3], builder, driver)?;
            let (c0, c3) = inputs[2].checked_unconditional_add_sub(&a0, builder, driver)?;
            let (c1, c2) = inputs[2].checked_unconditional_add_sub(&a1, builder, driver)?;

            let (f0, f3) = inputs[5].checked_unconditional_add_sub(&e0, builder, driver)?;
            let (f1, f2) = inputs[5].checked_unconditional_add_sub(&e1, builder, driver)?;

            let (r0, r7) = f0.checked_unconditional_add_sub(&c0, builder, driver)?;
            let (r1, r6) = f0.checked_unconditional_add_sub(&c1, builder, driver)?;
            let (r2, r5) = f0.checked_unconditional_add_sub(&c2, builder, driver)?;
            let (r3, r4) = f0.checked_unconditional_add_sub(&c3, builder, driver)?;

            let (s0, s7) = f1.checked_unconditional_add_sub(&c0, builder, driver)?;
            let (s1, s6) = f1.checked_unconditional_add_sub(&c1, builder, driver)?;
            let (s2, s5) = f1.checked_unconditional_add_sub(&c2, builder, driver)?;
            let (s3, s4) = f1.checked_unconditional_add_sub(&c3, builder, driver)?;

            let (u0, u7) = f2.checked_unconditional_add_sub(&c0, builder, driver)?;
            let (u1, u6) = f2.checked_unconditional_add_sub(&c1, builder, driver)?;
            let (u2, u5) = f2.checked_unconditional_add_sub(&c2, builder, driver)?;
            let (u3, u4) = f2.checked_unconditional_add_sub(&c3, builder, driver)?;

            let (w0, w7) = f3.checked_unconditional_add_sub(&c0, builder, driver)?;
            let (w1, w6) = f3.checked_unconditional_add_sub(&c1, builder, driver)?;
            let (w2, w5) = f3.checked_unconditional_add_sub(&c2, builder, driver)?;
            let (w3, w4) = f3.checked_unconditional_add_sub(&c3, builder, driver)?;

            element_table[0] = r0;
            element_table[1] = r1;
            element_table[2] = r2;
            element_table[3] = r3;
            element_table[4] = r4;
            element_table[5] = r5;
            element_table[6] = r6;
            element_table[7] = r7;

            element_table[8] = s0;
            element_table[9] = s1;
            element_table[10] = s2;
            element_table[11] = s3;
            element_table[12] = s4;
            element_table[13] = s5;
            element_table[14] = s6;
            element_table[15] = s7;

            element_table[16] = u0;
            element_table[17] = u1;
            element_table[18] = u2;
            element_table[19] = u3;
            element_table[20] = u4;
            element_table[21] = u5;
            element_table[22] = u6;
            element_table[23] = u7;

            element_table[24] = w0;
            element_table[25] = w1;
            element_table[26] = w2;
            element_table[27] = w3;
            element_table[28] = w4;
            element_table[29] = w5;
            element_table[30] = w6;
            element_table[31] = w7;
        }

        for i in 0..SIZE / 2 {
            element_table[i + SIZE / 2] = element_table[SIZE / 2 - 1 - i].neg(builder, driver)?;
        }

        let limb_max = array::from_fn(|_| BigUint::from(0u64));
        let coordinates = Self::create_group_element_rom_tables(&element_table, &limb_max)?;

        Ok(LookupTablePlookup {
            element_table,
            coordinates,
            limb_max,
        })
    }

    /**
     * @brief Constructs a ROM table to look up linear combinations of group elements
     *
     * @tparam C
     * @tparam Fq
     * @tparam Fr
     * @tparam G
     * @tparam num_elements
     * @tparam typename
     * @param rom_data the ROM table we are writing into
     * @param limb_max the maximum size of each limb in the ROM table.
     *
     * @details When reading a group element *out* of the ROM table, we must know the maximum value of each coordinate's
     * limbs. We take this value to be the maximum of the maximum values of the input limbs into the table!
     * @return std::array<twin_rom_table<C>, 5>
     **/
    fn create_group_element_rom_tables(
        rom_data: &[BigGroup<F, T>],
        limb_max: &[BigUint; 8],
    ) -> eyre::Result<[TwinRomTable<F>; 5]> {
        let num_elements = rom_data.len();

        let mut x_lo_limbs = Vec::with_capacity(num_elements);
        let mut x_hi_limbs = Vec::with_capacity(num_elements);
        let mut y_lo_limbs = Vec::with_capacity(num_elements);
        let mut y_hi_limbs = Vec::with_capacity(num_elements);
        let mut prime_limbs = Vec::with_capacity(num_elements);

        let mut limb_max = limb_max.clone();

        for i in 0..num_elements {
            for j in 0..4 {
                limb_max[j] = max(
                    limb_max[j].clone(),
                    rom_data[i].x.binary_basis_limbs[j].maximum_value.clone(),
                );
                limb_max[j + 4] = max(
                    limb_max[j + 4].clone(),
                    rom_data[i].y.binary_basis_limbs[j].maximum_value.clone(),
                );
            }

            x_lo_limbs.push([
                rom_data[i].x.binary_basis_limbs[0].element.clone(),
                rom_data[i].x.binary_basis_limbs[1].element.clone(),
            ]);
            x_hi_limbs.push([
                rom_data[i].x.binary_basis_limbs[2].element.clone(),
                rom_data[i].x.binary_basis_limbs[3].element.clone(),
            ]);
            y_lo_limbs.push([
                rom_data[i].y.binary_basis_limbs[0].element.clone(),
                rom_data[i].y.binary_basis_limbs[1].element.clone(),
            ]);
            y_hi_limbs.push([
                rom_data[i].y.binary_basis_limbs[2].element.clone(),
                rom_data[i].y.binary_basis_limbs[3].element.clone(),
            ]);
            prime_limbs.push([
                rom_data[i].x.prime_basis_limb.clone(),
                rom_data[i].y.prime_basis_limb.clone(),
            ]);
        }

        let output_tables = [
            TwinRomTable::new(x_lo_limbs),
            TwinRomTable::new(x_hi_limbs),
            TwinRomTable::new(y_lo_limbs),
            TwinRomTable::new(y_hi_limbs),
            TwinRomTable::new(prime_limbs),
        ];

        Ok(output_tables)
    }

    fn read_group_element_rom_tables<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        tables: &mut [TwinRomTable<F>; 5],
        index: &FieldCT<F>,
        limb_max: &[BigUint; 8],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigGroup<F, T>> {
        let xlo = tables[0].get(index, builder, driver)?;
        let xhi = tables[1].get(index, builder, driver)?;
        let ylo = tables[2].get(index, builder, driver)?;
        let yhi = tables[3].get(index, builder, driver)?;
        let xyprime = tables[4].get(index, builder, driver)?;

        // We assign maximum_value of each limb here, so we can use the unsafe API from element construction
        let mut x_fq = BigField::unsafe_construct_from_limbs(
            &xlo[0],
            &xlo[1],
            &xhi[0],
            &xhi[1],
            &xyprime[0],
            false,
        );
        let mut y_fq = BigField::unsafe_construct_from_limbs(
            &ylo[0],
            &ylo[1],
            &yhi[0],
            &yhi[1],
            &xyprime[1],
            false,
        );

        for j in 0..4 {
            x_fq.binary_basis_limbs[j].maximum_value = limb_max[j].clone();
            y_fq.binary_basis_limbs[j].maximum_value = limb_max[j + 4].clone();
        }

        Ok(BigGroup::new(x_fq, y_fq))
    }

    pub(crate) fn get<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        bits: &[BoolCT<F, T>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigGroup<F, T>> {
        assert_eq!(bits.len(), SIZE.trailing_zeros() as usize);
        let mut accumulators = Vec::new();
        for (i, bit) in bits.iter().enumerate() {
            accumulators.push(
                FieldCT::from_witness(F::from(1u64 << i).into(), builder).multiply(
                    &bit.to_field_ct(driver),
                    builder,
                    driver,
                )?,
            );
        }

        let index = FieldCT::accumulate(&accumulators, builder, driver)?;
        Self::read_group_element_rom_tables(
            &mut self.coordinates,
            &index,
            &self.limb_max,
            builder,
            driver,
        )
    }
}

pub struct BatchLookupTablePlookup<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> {
    num_points: usize,
    num_sixes: usize,
    num_fives: usize,
    has_quad: bool,
    has_triple: bool,
    has_twin: bool,
    has_singleton: bool,

    six_tables: Vec<LookupTablePlookup<64, F, T>>,
    five_tables: Vec<LookupTablePlookup<32, F, T>>,
    quad_tables: Vec<LookupTablePlookup<16, F, T>>,
    triple_tables: Vec<LookupTablePlookup<8, F, T>>,
    twin_tables: Vec<LookupTablePlookup<4, F, T>>,
    singletons: Vec<BigGroup<F, T>>,
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> BatchLookupTablePlookup<F, T> {
    pub fn new<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        points: &[BigGroup<F, T>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let num_points = points.len();
        let mut num_sixes = 0;
        let mut num_fives = num_points / 5;

        // size-6 table is expensive and only benefits us if creating them reduces the number of total tables

        if num_points == 1 {
            num_fives = 0;
            num_sixes = 0;
        } else if num_fives * 5 == (num_points - 1) {
            num_fives -= 1;
            num_sixes = 1;
        } else if num_fives * 5 == (num_points - 2) && num_fives >= 2 {
            num_fives -= 2;
            num_sixes = 2;
        } else if num_fives * 5 == (num_points - 3) && num_fives >= 3 {
            num_fives -= 3;
            num_sixes = 3;
        }

        let has_quad = ((num_fives * 5 + num_sixes * 6) < num_points - 3) && (num_points >= 4);
        let has_triple = ((num_fives * 5 + num_sixes * 6 + if has_quad { 4 } else { 0 })
            < num_points - 2)
            && (num_points >= 3);
        let has_twin = ((num_fives * 5
            + num_sixes * 6
            + if has_quad { 4 } else { 0 }
            + if has_triple { 3 } else { 0 })
            < num_points - 1)
            && (num_points >= 2);
        let has_singleton = num_points
            != ((num_fives * 5 + num_sixes * 6)
                + if has_quad { 4 } else { 0 }
                + if has_triple { 3 } else { 0 }
                + if has_twin { 2 } else { 0 });

        let mut offset = 0;
        let mut six_tables = Vec::new();
        let mut five_tables = Vec::new();
        let mut quad_tables = Vec::new();
        let mut triple_tables = Vec::new();
        let mut twin_tables = Vec::new();
        let mut singletons = Vec::new();

        for i in 0..num_sixes {
            let idx = offset + 6 * i;
            six_tables.push(LookupTablePlookup::<64, F, T>::new(
                [
                    points[idx].clone(),
                    points[idx + 1].clone(),
                    points[idx + 2].clone(),
                    points[idx + 3].clone(),
                    points[idx + 4].clone(),
                    points[idx + 5].clone(),
                ],
                builder,
                driver,
            )?);
        }
        offset += 6 * num_sixes;
        for i in 0..num_fives {
            let idx = offset + 5 * i;
            five_tables.push(LookupTablePlookup::<32, F, T>::new(
                [
                    points[idx].clone(),
                    points[idx + 1].clone(),
                    points[idx + 2].clone(),
                    points[idx + 3].clone(),
                    points[idx + 4].clone(),
                ],
                builder,
                driver,
            )?);
        }
        offset += 5 * num_fives;

        if has_quad {
            quad_tables.push(LookupTablePlookup::<16, F, T>::new(
                [
                    points[offset].clone(),
                    points[offset + 1].clone(),
                    points[offset + 2].clone(),
                    points[offset + 3].clone(),
                ],
                builder,
                driver,
            )?);
        }
        if has_triple {
            triple_tables.push(LookupTablePlookup::<8, F, T>::new(
                [
                    points[offset].clone(),
                    points[offset + 1].clone(),
                    points[offset + 2].clone(),
                ],
                builder,
                driver,
            )?);
        }

        if has_twin {
            twin_tables.push(LookupTablePlookup::<4, F, T>::new(
                [points[offset].clone(), points[offset + 1].clone()],
                builder,
                driver,
            )?);
        }

        if has_singleton {
            singletons.push(points[points.len() - 1].clone());
        }

        Ok(BatchLookupTablePlookup {
            num_points,
            num_sixes,
            num_fives,
            has_quad,
            has_triple,
            has_twin,
            has_singleton,
            six_tables,
            five_tables,
            quad_tables,
            triple_tables,
            twin_tables,
            singletons,
        })
    }

    pub(crate) fn get_initial_entry<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> BigGroup<F, T> {
        let mut add_accumulator = Vec::new();
        for six_table in &self.six_tables {
            add_accumulator.push(six_table.element_table[0].clone());
        }
        for five_table in &self.five_tables {
            add_accumulator.push(five_table.element_table[0].clone());
        }
        if self.has_quad {
            add_accumulator.push(self.quad_tables[0].element_table[0].clone());
        }
        if self.has_triple {
            add_accumulator.push(self.triple_tables[0].element_table[0].clone());
        }
        if self.has_twin {
            add_accumulator.push(self.twin_tables[0].element_table[0].clone());
        }
        if self.has_singleton {
            add_accumulator.push(self.singletons[0].clone());
        }

        add_accumulator
            .into_iter()
            .reduce(|acc, item| {
                acc.add(&item, builder, driver)
                    .expect("Addition of elements in batch lookup table failed")
            })
            .expect("At least one element should be present in batch lookup table")
    }

    pub(crate) fn get_chain_initial_entry<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        {
            let mut add_accumulator = Vec::new();

            for quad_table in &self.quad_tables {
                add_accumulator.push(quad_table.element_table[0].clone());
            }
            if self.has_twin {
                add_accumulator.push(self.twin_tables[0].element_table[0].clone());
            }
            if self.has_triple {
                add_accumulator.push(self.triple_tables[0].element_table[0].clone());
            }
            if self.has_singleton {
                add_accumulator.push(self.singletons[0].clone());
            }

            if add_accumulator.len() >= 2 {
                let mut output = BigGroup::chain_add_start(
                    &add_accumulator[0],
                    &add_accumulator[1],
                    builder,
                    driver,
                )?;
                for acc in add_accumulator.iter().skip(2) {
                    output = BigGroup::chain_add(acc, &output, builder, driver)?;
                }
                return Ok(output);
            }
            Ok(ChainAddAccumulator {
                x3_prev: add_accumulator[0].x.clone(),
                y3_prev: add_accumulator[0].y.clone(),
                is_element: true,
                x1_prev: Default::default(),
                y1_prev: Default::default(),
                lambda_prev: Default::default(),
            })
        }
    }

    pub(crate) fn get_chain_add_accumulator<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        naf_entries: &[BoolCT<F, T>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        let mut round_accumulator = Vec::new();
        for i in 0..self.num_sixes {
            round_accumulator.push(self.six_tables[i].get(
                &[
                    naf_entries[6 * i].clone(),
                    naf_entries[6 * i + 1].clone(),
                    naf_entries[6 * i + 2].clone(),
                    naf_entries[6 * i + 3].clone(),
                    naf_entries[6 * i + 4].clone(),
                    naf_entries[6 * i + 5].clone(),
                ],
                builder,
                driver,
            )?);
        }
        let mut offset = 6 * self.num_sixes;
        for i in 0..self.num_fives {
            round_accumulator.push(self.five_tables[i].get(
                &[
                    naf_entries[5 * i].clone(),
                    naf_entries[5 * i + 1].clone(),
                    naf_entries[5 * i + 2].clone(),
                    naf_entries[5 * i + 3].clone(),
                    naf_entries[5 * i + 4].clone(),
                ],
                builder,
                driver,
            )?);
        }
        offset += 5 * self.num_fives;
        if self.has_quad {
            round_accumulator.push(self.quad_tables[0].get(
                &[
                    naf_entries[offset].clone(),
                    naf_entries[offset + 1].clone(),
                    naf_entries[offset + 2].clone(),
                    naf_entries[offset + 3].clone(),
                ],
                builder,
                driver,
            )?);
        }
        if self.has_triple {
            round_accumulator.push(self.triple_tables[0].get(
                &[
                    naf_entries[offset].clone(),
                    naf_entries[offset + 1].clone(),
                    naf_entries[offset + 2].clone(),
                ],
                builder,
                driver,
            )?);
        }
        if self.has_twin {
            round_accumulator.push(self.twin_tables[0].get(
                &[naf_entries[offset].clone(), naf_entries[offset + 1].clone()],
                builder,
                driver,
            )?);
        }
        if self.has_singleton {
            round_accumulator.push(self.singletons[0].conditional_negate(
                &naf_entries[self.num_points - 1],
                builder,
                driver,
            )?);
        }

        if round_accumulator.len() == 1 {
            return Ok(ChainAddAccumulator {
                x3_prev: round_accumulator[0].x.clone(),
                y3_prev: round_accumulator[0].y.clone(),
                is_element: true,
                x1_prev: Default::default(),
                y1_prev: Default::default(),
                lambda_prev: Default::default(),
            });
        } else if round_accumulator.len() == 2 {
            return BigGroup::chain_add_start(
                &round_accumulator[0],
                &round_accumulator[1],
                builder,
                driver,
            );
        }
        let mut output = BigGroup::chain_add_start(
            &round_accumulator[0],
            &round_accumulator[1],
            builder,
            driver,
        )?;

        for acc in round_accumulator.iter().skip(2) {
            output = BigGroup::chain_add(acc, &output, builder, driver)?;
        }
        Ok(output)
    }
}

pub(crate) struct ChainAddAccumulator<F: PrimeField> {
    x1_prev: BigField<F>,
    y1_prev: BigField<F>,
    lambda_prev: BigField<F>,
    x3_prev: BigField<F>,
    y3_prev: BigField<F>,
    is_element: bool,
}

#[cfg(test)]
mod test {

    #[test]
    fn test_handle_points_at_infinity() {}
}
