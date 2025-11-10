use core::num;
use std::cmp::max;
use std::{array, clone};

use crate::prelude::offset_generator;
use crate::types::big_field::BigField;
use crate::types::big_group_tables::BatchLookupTablePlookup;
use crate::types::field_ct::WitnessCT;
use crate::types::plookup::LookupHashMap;
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
    pub const NUM_BN254_FRS: usize = BigField::<F>::NUM_BN254_SCALARS as usize * 2;
    pub fn new(x: BigField<F>, y: BigField<F>) -> Self {
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
        let (mut points, scalars) = BigGroup::mask_points(&points, &scalars, builder, driver)?;

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

        let mut offset_generators = Self::compute_offset_generators::<P>(max_num_bits)?;

        let mut accumulator = Self::chain_add_end(
            Self::chain_add(
                &mut offset_generators.0,
                &mut point_table.get_chain_initial_entry(builder, driver)?,
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
            accumulator = accumulator.multiple_montgomery_ladder(&mut to_add, builder, driver)?;
        }

        for i in 0..points.len() {
            let skew = accumulator.sub(&mut points[i], builder, driver)?;
            let out_x = accumulator.x.conditional_select(
                &skew.x,
                &naf_entries[i][num_rounds],
                builder,
                driver,
            )?;

            let out_y = accumulator.y.conditional_select(
                &skew.y,
                &naf_entries[i][num_rounds],
                builder,
                driver,
            )?;
            accumulator = BigGroup::new(out_x, out_y);
        }
        accumulator.sub(&mut offset_generators.1, builder, driver)
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
        &mut self,
        add: &mut [ChainAddAccumulator<F>],
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
                    add[i].x3_prev.sub(&mut add[i].x1_prev, builder, driver)?
                } else {
                    add[i].x1_prev.sub(&mut add[i].x3_prev, builder, driver)?
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

            let mut lambda1 = if (!add[i].is_element || i > 0) {
                let denominator = if !negate_add_y {
                    previous_x.sub(&mut add[i].x3_prev, builder, driver)?
                } else {
                    add[i].x3_prev.sub(&mut previous_x, builder, driver)?
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
                    &mut [add[i].y3_prev.sub(&mut self.y, builder, driver)?],
                    &mut add[i].x3_prev.sub(&mut self.x, builder, driver)?,
                    builder,
                    driver,
                )?
            };

            // TODO CESAR: Verify if this is correct
            let mut x_3 = lambda1.sqradd(
                &mut [
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
            let mut lambda2 = if i == 0 {
                let two_y = self.y.clone().add(&mut self.y, builder, driver)?;
                BigField::div_without_denominator_check(
                    &mut [two_y],
                    &mut previous_x.sub(&mut x_3, builder, driver)?,
                    builder,
                    driver,
                )?
                .sub(&mut lambda1, builder, driver)?
            } else {
                let l2_denominator = if previous_y.is_negative {
                    previous_x.sub(&mut x_3, builder, driver)?
                } else {
                    x_3.sub(&mut previous_x, builder, driver)?
                };
                let mut partial_lambda2 = BigField::msub_div(
                    &previous_y.mul_left,
                    &previous_y.mul_right,
                    &l2_denominator,
                    &previous_y.add,
                    false,
                    builder,
                    driver,
                )?;
                let mut partial_lambda2 =
                    partial_lambda2
                        .clone()
                        .add(&mut partial_lambda2, builder, driver)?;
                partial_lambda2.sub(&mut lambda1, builder, driver)?
            };

            let mut x_4 = lambda2.sqradd(
                &mut [x_3.neg(builder, driver)?, previous_x.neg(builder, driver)?],
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
                    x_4.sub(&mut previous_x, builder, driver)?
                } else {
                    previous_x.sub(&mut x_4, builder, driver)?
                });
                y_4.is_negative = num_points_even;
            } else {
                y_4.is_negative = !previous_y.is_negative;
                y_4.mul_left.push(lambda2.clone());
                y_4.mul_right.push(if previous_y.is_negative {
                    previous_x.sub(&mut x_4, builder, driver)?
                } else {
                    x_4.sub(&mut previous_x, builder, driver)?
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
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(Self, Self)> {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/971): This will fail when the two elements are the
        // same even in the case of a valid circuit
        other.x.assert_is_not_equal(&self.x, builder, driver)?;

        let mut denominator = other.x.sub(&mut self.x, builder, driver)?;
        let x2x1 = other
            .x
            .add(&mut self.x, builder, driver)?
            .neg(builder, driver)?;

        let mut lambda1 = BigField::div_without_denominator_check(
            &mut [other.y.clone(), self.y.neg(builder, driver)?],
            &mut denominator,
            builder,
            driver,
        )?;
        let mut x_3 = lambda1.sqradd(&mut [x2x1.clone()], builder, driver)?;
        let y_3 = lambda1.madd(
            &mut self.x.sub(&mut x_3, builder, driver)?,
            &mut [self.y.neg(builder, driver)?],
            builder,
            driver,
        )?;

        let mut lambda2 = BigField::div_without_denominator_check(
            &mut [other.y.neg(builder, driver)?, self.y.neg(builder, driver)?],
            &mut denominator,
            builder,
            driver,
        )?;
        let mut x_4 = lambda2.sqradd(&mut [x2x1], builder, driver)?;
        let y_4 = lambda2.madd(
            &mut other.x.sub(&mut x_4, builder, driver)?,
            &mut [other.y.neg(builder, driver)?],
            builder,
            driver,
        )?;

        Ok((BigGroup::new(x_3, y_3), BigGroup::new(x_4, y_4)))
    }

    pub(crate) fn add<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // Adding in `x_coordinates_match` ensures that lambda will always be well-formed
        // Our curve has the form y^2 = x^3 + b.
        // If (x_1, y_1), (x_2, y_2) have x_1 == x_2, and the generic formula for lambda has a division by 0.
        // Then y_1 == y_2 (i.e. we are doubling) or y_2 == y_1 (the sum is infinity).
        // The cases have a special addition formula. The following booleans allow us to handle these cases uniformly.
        let x_coordinates_match = self.x.equals(&mut other.x, builder, driver)?;
        let y_coordinates_match = self.y.equals(&mut other.y, builder, driver)?;
        let infinity_predicate =
            x_coordinates_match.and(&y_coordinates_match.not(), builder, driver)?;
        let double_predicate = x_coordinates_match.and(&y_coordinates_match, builder, driver)?;
        let lhs_infinity = self.is_infinity.clone();
        let rhs_infinity = other.is_infinity.clone();

        // Compute the gradient `lambda`. If we add, `lambda = (y2 - y1)/(x2 - x1)`, else `lambda = 3x1*x1/2y1
        let mut add_lambda_numerator = other.y.sub(&mut self.y, builder, driver)?;
        let mut xx = self.x.clone().mul(&mut self.x, builder, driver)?;
        let mut dbl_lambda_numerator = xx
            .clone()
            .add(&mut xx.clone(), builder, driver)?
            .add(&mut xx, builder, driver)?;
        let lambda_numerator = BigField::conditional_assign(
            &double_predicate,
            &mut dbl_lambda_numerator,
            &mut add_lambda_numerator,
            builder,
            driver,
        )?;

        let mut add_lambda_denominator = other.x.sub(&mut self.x, builder, driver)?;
        let mut dbl_lambda_denominator = self.y.clone().add(&mut self.y, builder, driver)?;
        let mut lambda_denominator = BigField::conditional_assign(
            &double_predicate,
            &mut dbl_lambda_denominator,
            &mut add_lambda_denominator,
            builder,
            driver,
        )?;

        // If either inputs are points at infinity, we set lambda_denominator to be 1. This ensures we never trigger a
        // divide by zero error.
        // Note: if either inputs are points at infinity we will not use the result of this computation.
        let mut safe_edgecase_denominator = BigField::from_constant(&BigUint::from(1u64));
        lambda_denominator = BigField::conditional_assign(
            &infinity_predicate,
            &mut safe_edgecase_denominator,
            &mut lambda_denominator,
            builder,
            driver,
        )?;
        let mut lambda = BigField::div_without_denominator_check(
            &mut [lambda_numerator],
            &mut lambda_denominator,
            builder,
            driver,
        )?;

        let mut x3 = lambda.sqradd(
            &mut [self.x.neg(builder, driver)?, other.x.neg(builder, driver)?],
            builder,
            driver,
        )?;

        let y3 = lambda.madd(
            &mut self.x.sub(&mut x3, builder, driver)?,
            &mut [self.y.neg(builder, driver)?],
            builder,
            driver,
        )?;
        let mut result = BigGroup::new(x3, y3);

        // if lhs infinity, return rhs
        result.x = BigField::conditional_assign(
            &lhs_infinity,
            &mut other.x,
            &mut result.x,
            builder,
            driver,
        )?;
        result.y = BigField::conditional_assign(
            &lhs_infinity,
            &mut other.y,
            &mut result.y,
            builder,
            driver,
        )?;

        // if rhs infinity, return lhs
        result.x = BigField::conditional_assign(
            &rhs_infinity,
            &mut self.x,
            &mut result.x,
            builder,
            driver,
        )?;
        result.y = BigField::conditional_assign(
            &rhs_infinity,
            &mut self.y,
            &mut result.y,
            builder,
            driver,
        )?;

        // is result point at infinity?
        // yes = infinity_predicate && !lhs_infinity && !rhs_infinity
        // yes = lhs_infinity && rhs_infinity
        // n.b. can likely optimize this
        let mut result_is_infinity = infinity_predicate
            .and(&lhs_infinity.not(), builder, driver)?
            .and(&rhs_infinity.not(), builder, driver)?
            .or(
                &lhs_infinity.and(&rhs_infinity, builder, driver)?,
                builder,
                driver,
            )?;

        // We are in the UltraBuilder case
        // TODO CESAR: What about this call?
        // builder.update_used_witnesses(result_is_infinity.witness_index);
        let tmp = lhs_infinity.and(&rhs_infinity, builder, driver)?;
        result_is_infinity = result_is_infinity.or(&tmp, builder, driver)?;
        result.is_infinity = result_is_infinity;

        Ok(result)
    }

    fn sub<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // if x_coordinates match, lambda triggers a divide by zero error.
        // Adding in `x_coordinates_match` ensures that lambda will always be well-formed
        let x_coordinates_match = self.x.equals(&mut other.x, builder, driver)?;
        let y_coordinates_match = self.y.equals(&mut other.y, builder, driver)?;
        let infinity_predicate =
            x_coordinates_match.and(&y_coordinates_match.not(), builder, driver)?;
        let double_predicate = x_coordinates_match.and(&y_coordinates_match, builder, driver)?;
        let lhs_infinity = self.is_infinity.clone();
        let rhs_infinity = other.is_infinity.clone();

        // Compute the gradient `lambda`. If we add, `lambda = (y2 - y1)/(x2 - x1)`, else `lambda = 3x1*x1/2y1
        let mut add_lambda_numerator =
            other
                .y
                .neg(builder, driver)?
                .sub(&mut self.y, builder, driver)?;
        let mut xx = self.x.clone().mul(&mut self.x, builder, driver)?;
        let mut dbl_lambda_numerator = xx
            .clone()
            .add(&mut xx.clone(), builder, driver)?
            .add(&mut xx, builder, driver)?;
        let lambda_numerator = BigField::conditional_assign(
            &double_predicate,
            &mut dbl_lambda_numerator,
            &mut add_lambda_numerator,
            builder,
            driver,
        )?;

        let mut add_lambda_denominator = other.x.sub(&mut self.x, builder, driver)?;
        let mut dbl_lambda_denominator = self.y.clone().add(&mut self.y, builder, driver)?;
        let mut lambda_denominator = BigField::conditional_assign(
            &double_predicate,
            &mut dbl_lambda_denominator,
            &mut add_lambda_denominator,
            builder,
            driver,
        )?;

        // If either inputs are points at infinity, we set lambda_denominator to be 1. This ensures we never trigger a
        // divide by zero error.
        // Note: if either inputs are points at infinity we will not use the result of this computation.
        let mut safe_edgecase_denominator = BigField::from_constant(&BigUint::from(1u64));
        lambda_denominator = BigField::conditional_assign(
            &lhs_infinity.or(&rhs_infinity, builder, driver)?.or(
                &infinity_predicate,
                builder,
                driver,
            )?,
            &mut safe_edgecase_denominator,
            &mut lambda_denominator,
            builder,
            driver,
        )?;
        let mut lambda = BigField::div_without_denominator_check(
            &mut [lambda_numerator],
            &mut lambda_denominator,
            builder,
            driver,
        )?;

        let mut x3 = lambda.sqradd(
            &mut [self.x.neg(builder, driver)?, other.x.neg(builder, driver)?],
            builder,
            driver,
        )?;

        let y3 = lambda.madd(
            &mut self.x.sub(&mut x3, builder, driver)?,
            &mut [self.y.neg(builder, driver)?],
            builder,
            driver,
        )?;

        let mut result = BigGroup::new(x3, y3);

        // if lhs infinity, return rhs
        result.x = BigField::conditional_assign(
            &lhs_infinity,
            &mut other.x,
            &mut result.x,
            builder,
            driver,
        )?;
        result.y = BigField::conditional_assign(
            &lhs_infinity,
            &mut other.y.neg(builder, driver)?,
            &mut result.y,
            builder,
            driver,
        )?;

        // if rhs infinity, return lhs
        result.x = BigField::conditional_assign(
            &rhs_infinity,
            &mut self.x,
            &mut result.x,
            builder,
            driver,
        )?;
        result.y = BigField::conditional_assign(
            &rhs_infinity,
            &mut self.y,
            &mut result.y,
            builder,
            driver,
        )?;

        // is result point at infinity?
        // yes = infinity_predicate && !lhs_infinity && !rhs_infinity
        // yes = lhs_infinity && rhs_infinity
        // n.b. can likely optimize this
        let mut result_is_infinity = infinity_predicate
            .and(&lhs_infinity.not(), builder, driver)?
            .and(&rhs_infinity.not(), builder, driver)?
            .or(
                &lhs_infinity.and(&rhs_infinity, builder, driver)?,
                builder,
                driver,
            )?;

        // We are in the UltraBuilder case
        // TODO CESAR: What about this call?
        // builder.update_used_witnesses(result_is_infinity.witness_index);
        let tmp = lhs_infinity.and(&rhs_infinity, builder, driver)?;
        result_is_infinity = result_is_infinity.or(&tmp, builder, driver)?;
        result.is_infinity = result_is_infinity;

        Ok(result)
    }

    pub fn neg<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let negated_y = self.y.neg(builder, driver)?;
        Ok(BigGroup::new(self.x.clone(), negated_y))
    }

    pub(crate) fn conditional_negate<P: CurveGroup<ScalarField = F>>(
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
        let mut one = Self::one(builder, driver)?;
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

            let updated_x = BigField::conditional_assign(
                is_infinity,
                &mut one.x,
                &mut point.x.clone(),
                builder,
                driver,
            )?;
            let updated_y = BigField::conditional_assign(
                is_infinity,
                &mut one.y,
                &mut point.y.clone(),
                builder,
                driver,
            )?;

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

    /*
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
     * begin a chain of additions
     * input points p1 p2
     * output accumulator = x3_prev (output x coordinate), x1_prev, y1_prev (p1), lambda_prev (y2 - y1) / (x2 - x1)
     */
    pub(crate) fn chain_add_start<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        p1: &mut Self,
        p2: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        p1.x.assert_is_not_equal(&p2.x, builder, driver);
        let mut lambda = BigField::div_without_denominator_check(
            &mut [p2.y.clone(), p1.y.neg(builder, driver)?],
            &mut p2.x.sub(&mut p1.x, builder, driver)?,
            builder,
            driver,
        )?;

        let x3 = lambda.sqradd(
            &mut [p2.x.neg(builder, driver)?, p1.x.neg(builder, driver)?],
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
        p1: &mut Self,
        acc: &mut ChainAddAccumulator<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        // use `chain_add_start` to start an addition chain (i.e. if acc has a y-coordinate)
        if acc.is_element {
            Self::chain_add_start(
                p1,
                &mut BigGroup {
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

            let x2 = &mut acc.x3_prev;
            let mut lambda = BigField::msub_div(
                &[acc.lambda_prev.clone()],
                &[x2.sub(&mut acc.x1_prev, builder, driver)?],
                &x2.sub(&mut p1.x, builder, driver)?,
                &[acc.y1_prev.clone(), p1.y.clone()],
                false,
                builder,
                driver,
            )?;

            let x3 = lambda.sqradd(
                &mut [x2.neg(builder, driver)?, p1.x.neg(builder, driver)?],
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
        mut acc: ChainAddAccumulator<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigGroup<F, T>> {
        if acc.is_element {
            return Ok(BigGroup::new(acc.x3_prev, acc.y3_prev));
        }
        let mut x3 = acc.x3_prev;
        let mut lambda = acc.lambda_prev;

        let y3 = lambda.madd(
            &mut acc.x1_prev.sub(&mut x3, builder, driver)?,
            &mut [acc.y1_prev.neg(builder, driver)?],
            builder,
            driver,
        )?;

        Ok(BigGroup::new(x3, y3))
    }

    pub fn reconstruct_from_public<P: CurveGroup<ScalarField = F>>(
        limbs: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        debug_assert_eq!(limbs.len(), 2 * crate::types::big_field::NUM_LIMBS);
        Ok(BigGroup {
            x: BigField::reconstruct_from_public(&limbs[0..4], builder, driver)?,
            y: BigField::reconstruct_from_public(&limbs[4..8], builder, driver)?,
            is_infinity: BoolCT::from(false),
        })
    }

    pub fn scalar_mul<P: CurveGroup<ScalarField = F>>(
        &self,
        scalar: &FieldCT<F>,
        max_num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        debug_assert_eq!(max_num_bits % 2, 0);
        /*
         *
         * Let's say we have some curve E defined over a field Fq. The order of E is p, which is prime.
         *
         * Now lets say we are constructing a SNARK circuit over another curve E2, whose order is r.
         *
         * All of our addition / multiplication / custom gates are going to be evaluating low degree multivariate
         * polynomials modulo r.
         *
         * E.g. our addition/mul gate (for wires a, b, c and selectors q_m, q_l, q_r, q_o, q_c) is:
         *
         *  q_m * a * b + q_l * a + q_r * b + q_o * c + q_c = 0 mod r
         *
         * We want to construct a circuit that evaluates scalar multiplications of curve E. Where q > r and p > r.
         *
         * i.e. we need to perform arithmetic in one prime field, using prime field arithmetic in a completely
         *different prime field.
         *
         * To do *this*, we need to emulate a binary (or in our case quaternary) number system in Fr, so that we can
         * use the binary/quaternary basis to emulate arithmetic in Fq. Which is very messy. See bigfield.hpp for
         *the specifics.
         */

        let num_rounds = if max_num_bits == 0 {
            P::ScalarField::MODULUS_BIT_SIZE as usize + 1
        } else {
            max_num_bits
        };

        let mut result: Self = todo!(); //if max_num_bits != 0 {
        //     // The case of short scalars
        // element::bn254_endo_batch_mul({}, {}, { *this }, { scalar }, num_rounds);
        // } else {
        //     // The case of arbitrary length scalars
        // element::bn254_endo_batch_mul({ *this }, { scalar }, {}, {}, num_rounds);
        // };

        // Handle point at infinity
        result.x = BigField::conditional_assign(
            &self.is_infinity,
            &mut self.x.clone(),
            &mut result.x,
            builder,
            driver,
        )?;
        result.y = BigField::conditional_assign(
            &self.is_infinity,
            &mut self.y.clone(),
            &mut result.y,
            builder,
            driver,
        )?;

        result.set_is_infinity(self.is_infinity);

        Ok(result)
    }
}

pub(crate) struct ChainAddAccumulator<F: PrimeField> {
    pub(crate) x1_prev: BigField<F>,
    pub(crate) y1_prev: BigField<F>,
    pub(crate) lambda_prev: BigField<F>,
    pub(crate) x3_prev: BigField<F>,
    pub(crate) y3_prev: BigField<F>,
    pub(crate) is_element: bool,
}

mod tests {
    use ark_bn254::{Fq, Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use co_acvm::PlainAcvmSolver;

    use crate::{
        prelude::GenericUltraCircuitBuilder,
        transcript_ct::Bn254G1,
        types::{big_field::BigField, big_group::BigGroup},
    };

    fn affine_to_biggroup(
        point: &G1Affine,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, PlainAcvmSolver<Fr>>,
        driver: &mut PlainAcvmSolver<Fr>,
        constant: bool,
    ) -> BigGroup<Fr, PlainAcvmSolver<Fr>> {
        let (x, y) = point.xy().unwrap();
        let (x, y) = if constant {
            (
                BigField::from_constant(&x.into()),
                BigField::from_constant(&y.into()),
            )
        } else {
            (
                BigField::from_witness_other_acvm_type(&x, driver, builder).unwrap(),
                BigField::from_witness_other_acvm_type(&y, driver, builder).unwrap(),
            )
        };
        BigGroup::new(x, y)
    }

    fn biggroup_to_affine(
        point: &BigGroup<Fr, PlainAcvmSolver<Fr>>,
        driver: &mut PlainAcvmSolver<Fr>,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, PlainAcvmSolver<Fr>>,
    ) -> G1Affine {
        let x_value = point.x.get_value_fq(builder, driver).unwrap();
        let y_value = point.y.get_value_fq(builder, driver).unwrap();
        G1Affine::new(x_value, y_value)
    }

    #[test]
    fn test_biggroup_add_sub() {
        let mut rng = rand::thread_rng();
        let builder = &mut GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let driver = &mut PlainAcvmSolver::<Fr>::new();

        let point_x = G1Affine::rand(&mut rng);
        let point_y = G1Affine::rand(&mut rng);

        let point_add = point_x + point_y;
        let point_sub = point_x - point_y;

        let mut x_const = affine_to_biggroup(&point_x, builder, driver, true);
        let y_const = affine_to_biggroup(&point_y, builder, driver, true);

        let add_const = x_const.add(&mut y_const.clone(), builder, driver).unwrap();
        let sub_const = x_const.sub(&mut y_const.clone(), builder, driver).unwrap();

        let add_const_affine = biggroup_to_affine(&add_const, driver, builder);
        let sub_const_affine = biggroup_to_affine(&sub_const, driver, builder);

        assert_eq!(add_const_affine, point_add.into_affine());
        assert_eq!(sub_const_affine, point_sub.into_affine());

        let mut x_wit = affine_to_biggroup(&point_x, builder, driver, false);
        let y_wit = affine_to_biggroup(&point_y, builder, driver, false);

        let add_wit = x_wit.add(&mut y_wit.clone(), builder, driver).unwrap();
        let sub_wit = x_wit.sub(&mut y_wit.clone(), builder, driver).unwrap();

        let add_wit_affine = biggroup_to_affine(&add_wit, driver, builder);
        let sub_wit_affine = biggroup_to_affine(&sub_wit, driver, builder);

        assert_eq!(add_wit_affine, point_add.into_affine());
        assert_eq!(sub_wit_affine, point_sub.into_affine());
    }
}
