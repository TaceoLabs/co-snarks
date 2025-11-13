use std::any::TypeId;
use std::mem;

use super::field_ct::BoolCT;
use crate::prelude::offset_generator;
use crate::transcript_ct::Bn254G1;
use crate::types::big_field::BigField;
use crate::types::big_group_tables::BatchLookupTablePlookup;
use crate::types::field_ct::WitnessCT;
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use mpc_core::gadgets::field_from_hex_string;
use num_bigint::BigUint;

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
        BigGroup {
            x: BigField::default(),
            y: BigField::default(),
            is_infinity: BoolCT::from(false),
        }
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

    pub fn point_at_infinity() -> Self {
        BigGroup {
            x: BigField::default(),
            y: BigField::default(),
            is_infinity: BoolCT::from(true),
        }
    }

    pub(crate) fn from_witness<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        point: &P::Affine,
        driver: &mut T,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> eyre::Result<Self> {
        let (x, y, i) = match point.xy() {
            Some((x, y)) => (x, y, false),
            None => (P::BaseField::zero(), P::BaseField::zero(), true),
        };

        // TODO CESAR: Use affine one when point is infinity
        Ok(BigGroup {
            x: BigField::from_witness_other_acvm_type(&x.into(), driver, builder)?,
            y: BigField::from_witness_other_acvm_type(&y.into(), driver, builder)?,
            is_infinity: BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(F::from(i as u64).into(), builder),
                builder,
            ),
        })
    }

    /// Checks that the point is on the curve.
    /// If the point is at infinity, the check is skipped.
    /// Returns an error if the point is not on the curve.
    pub fn validate_on_curve<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // TACEO TODO: Has circuit failed

        // Get curve parameters
        let b = P::BaseField::from(3u64); // TACEO TODO: Magic constant BN254 curve b coefficient I think we have this in HonkCurve @Cesar199999
        let adjusted_b = BigField::conditional_assign(
            &self.is_infinity,
            &mut BigField::default(),
            &mut BigField::from_constant(&b.into()),
            builder,
            driver,
        )?;
        let adjusted_x = BigField::conditional_assign(
            &self.is_infinity,
            &mut BigField::default(),
            &mut self.x.clone(),
            builder,
            driver,
        )?;
        let mut adjusted_y = BigField::conditional_assign(
            &self.is_infinity,
            &mut BigField::default(),
            &mut self.y.clone(),
            builder,
            driver,
        )?;

        // Bn254G1::has_a == false
        BigField::mult_madd(
            &mut [adjusted_x.clone().sqr(builder, driver)?, adjusted_y.clone()],
            &mut [adjusted_x.clone(), adjusted_y.neg(builder, driver)?],
            &mut [adjusted_b],
            true,
            builder,
            driver,
        )?;

        // TACEO TODO: has circuit_failed?
        Ok(())
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

    pub(crate) fn from_constant_coordinates<P: CurveGroup<ScalarField = F>>(
        x: &BigUint,
        y: &BigUint,
        is_infinity: bool,
    ) -> eyre::Result<Self> {
        Ok(BigGroup {
            x: BigField::from_constant(x),
            y: BigField::from_constant(y),
            is_infinity: BoolCT::from(is_infinity),
        })
    }

    pub(crate) fn from_constant_affine<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        native_point: &P::Affine,
    ) -> eyre::Result<Self> {
        let (x, y, i) = match native_point.xy() {
            Some((x, y)) => (x.into(), y.into(), false),
            None => (BigUint::from(0u64), BigUint::from(0u64), true),
        };
        BigGroup::from_constant_coordinates::<P>(&x, &y, i)
    }

    /**
     * @brief Generic batch multiplication that works for all elliptic curve types.
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
     *
     * @details This is an implementation of the Strauss algorithm for multi-scalar-multiplication (MSM).
     *          It uses the Non-Adjacent Form (NAF) representation of scalars and ROM lookups to
     *          efficiently compute the MSM. The algorithm processes 4 bits of each scalar per iteration,
     *          accumulating the results in an accumulator point. The first NAF entry (I, see below) is used to
     *          -------------------------------
     *          Point  NAF(scalar)
     *          G1    [+1, -1, -1, -1, +1, ...]
     *          G2    [+1, +1, -1, -1, +1, ...]
     *          G3    [-1, +1, +1, -1, +1, ...]
     *                  ↑  ↑____________↑
     *                  I    Iteration 1
     *          -------------------------------
     *          select the initial point to add to the offset generator. Thereafter, we process 4 NAF entries
     *          per iteration. For one NAF entry, we lookup the corresponding points to add, and accumulate
     *          them using `chain_add_accumulator`. After processing 4 NAF entries, we perform a single
     *          `multiple_montgomery_ladder` call to update the accumulator. For example, in iteration 1 above,
     *          for the second NAF entry, the lookup output is:
     *          table(-1, +1, +1) = (-G1 + G2 + G3)
     *          This lookup output is accumulated with the lookup outputs from the other 3 NAF entries.
     */
    pub fn batch_mul<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        points: &[Self],
        scalars: &[FieldCT<F>],
        max_num_bits: usize,
        with_edgecases: bool,
        masking_scalar: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // Sanity checks input sizes
        debug_assert!(
            points.len() > 0,
            "biggroup batch_mul: no points provided for batch multiplication"
        );
        debug_assert_eq!(
            points.len(),
            scalars.len(),
            "biggroup batch_mul: points and scalars have different lengths"
        );

        // Replace (∞, scalar) pairs by the pair (G, 0).
        let (mut points, mut scalars) =
            BigGroup::handle_points_at_infinity(points, scalars, builder, driver)?;

        // If with_edgecases is false, masking_scalar must be constant and equal to 1 (as it is unused).
        if !with_edgecases {
            debug_assert!(
                masking_scalar.is_constant()
                    && masking_scalar.get_value(builder, driver) == F::ONE.into(),
            );
        }

        if with_edgecases {
            // If points are linearly dependent, we randomise them using a masking scalar.
            // We do this to ensure that the x-coordinates of the points are all distinct. This is required
            // while creating the ROM lookup table with the points.
            (points, scalars) =
                BigGroup::mask_points(&mut points, &scalars, &masking_scalar, builder, driver)?;
        }

        debug_assert_eq!(
            points.len(),
            scalars.len(),
            "biggroup batch_mul: points and scalars size mismatch after handling edgecases"
        );

        // Separate out zero scalars and corresponding points (because NAF(0) = NAF(modulus) which is 254 bits long)
        // Also add the last point and scalar to big_points and big_scalars (because its a 254-bit scalar)
        // We do this only if max_num_bits != 0 (i.e. we are not forced to use 254 bits anyway)
        let original_size = scalars.len();
        let mut big_scalars = Vec::new();
        let mut big_points = Vec::new();
        let mut small_scalars = Vec::new();
        let mut small_points = Vec::new();
        for i in 0..original_size {
            if max_num_bits == 0 {
                big_points.push(points[i].clone());
                big_scalars.push(scalars[i].clone());
            } else {
                let is_last_scalar_big = (i == original_size - 1) && with_edgecases;
                let scalar_value = scalars[i].get_value(builder, driver);

                // TODO CESAR: But here we are not checking whether the scalar is constant
                if scalar_value == F::zero().into() || is_last_scalar_big {
                    big_points.push(points[i].clone());
                    big_scalars.push(scalars[i].clone());
                } else {
                    small_points.push(points[i].clone());
                    small_scalars.push(scalars[i].clone());
                }
            }
        }

        debug_assert_eq!(
            original_size,
            small_points.len() + big_points.len(),
            "biggroup batch_mul: points size mismatch after separating big scalars"
        );
        debug_assert_eq!(
            big_points.len(),
            big_scalars.len(),
            "biggroup batch_mul: big points and scalars size mismatch after separating big scalars"
        );
        debug_assert_eq!(
            small_points.len(),
            small_scalars.len(),
            "biggroup batch_mul: small points and scalars size mismatch after separating big scalars"
        );

        let max_num_bits_in_field = F::MODULUS_BIT_SIZE as usize;
        let mut accumulator = BigGroup::default();
        if !big_points.is_empty() {
            // Process big scalars separately
            let big_result = BigGroup::process_strauss_msm_rounds(
                &mut big_points,
                &big_scalars,
                max_num_bits_in_field,
                builder,
                driver,
            )?;
            accumulator = big_result;
        }

        if !small_points.is_empty() {
            // Process small scalars
            let effective_max_num_bits = if max_num_bits == 0 {
                max_num_bits_in_field
            } else {
                max_num_bits
            };
            let mut small_result = BigGroup::process_strauss_msm_rounds(
                &mut small_points,
                &small_scalars,
                effective_max_num_bits,
                builder,
                driver,
            )?;
            accumulator = if big_points.len() > 0 {
                accumulator.add(&mut small_result, builder, driver)?
            } else {
                small_result
            };
        }

        Ok(accumulator)
    }

    fn process_strauss_msm_rounds<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        points: &mut [Self],
        scalars: &[FieldCT<F>],
        max_num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // Sanity checks
        debug_assert!(
            points.len() > 0,
            "biggroup process_strauss_msm_rounds: no points provided for batch multiplication"
        );
        debug_assert_eq!(
            points.len(),
            scalars.len(),
            "biggroup process_strauss_msm_rounds: points and scalars have different lengths"
        );

        // TACEO TODO: Check that all scalars are in range?

        // Constant parameters
        let num_rounds = max_num_bits;
        let msm_size = scalars.len();

        // Compute ROM lookup table for points. Example if we have 3 points G1, G2, G3:
        // ┌───────┬─────────────────┐
        // │ Index │ Point           │
        // ├───────┼─────────────────┤
        // │   0   │  G1 + G2 + G3   │
        // │   1   │  G1 + G2 - G3   │
        // │   2   │  G1 - G2 + G3   │
        // │   3   │  G1 - G2 - G3   │
        // │   4   │ -G1 + G2 + G3   │
        // │   5   │ -G1 + G2 - G3   │
        // │   6   │ -G1 - G2 + G3   │
        // │   7   │ -G1 - G2 - G3   │
        // └───────┴─────────────────┘
        let mut point_table = BatchLookupTablePlookup::new(&points, builder, driver)?;

        // Compute NAF representation of scalars
        let mut naf_entries = Vec::with_capacity(msm_size);
        for i in 0..msm_size {
            naf_entries.push(Self::compute_naf(&scalars[i], num_rounds, builder, driver)?);
        }

        // We choose a deterministic offset generator based on the number of rounds.
        // We compute both the initial and final offset generators: G_offset, 2ⁿ⁻¹ * G_offset.
        let (mut offset_generator_start, mut offset_generator_end) =
            Self::precomputed_offset_generators::<P>(num_rounds)?;

        // Initialize accumulator with initial offset generator + first NAF column
        let mut inital_entry: ChainAddAccumulator<F> =
            point_table.get_chain_initial_entry(builder, driver)?;

        let tmp = Self::chain_add(
            &mut offset_generator_start,
            &mut inital_entry,
            builder,
            driver,
        )?;

        let mut accumulator = Self::chain_add_end(tmp, builder, driver)?;

        // Process 4 NAF entries per iteration (for the remaining (num_rounds - 1) rounds)
        let num_rounds_per_iteration = 4;
        let num_iterations =
            ((num_rounds - 1) as u64).div_ceil(num_rounds_per_iteration as u64) as usize;
        let num_rounds_per_final_iteration =
            (num_rounds - 1) - ((num_iterations - 1) * num_rounds_per_iteration);

        for i in 0..num_iterations {
            let mut to_add = Vec::with_capacity(msm_size);
            let inner_num_rounds = if i != num_iterations - 1 {
                num_rounds_per_iteration
            } else {
                num_rounds_per_final_iteration
            };

            for j in 0..inner_num_rounds {
                let mut nafs = vec![BoolCT::from(false); msm_size];
                for k in 0..msm_size {
                    nafs[k] = naf_entries[k][i * num_rounds_per_iteration + j + 1].clone();
                }
                to_add.push(point_table.get_chain_add_accumulator(&nafs, builder, driver)?);
            }

            // Once we have looked-up all points from the four NAF columns, we update the accumulator as:
            // accumulator = 2.(2.(2.(2.accumulator + to_add[0]) + to_add[1]) + to_add[2]) + to_add[3]
            //             = 2⁴.accumulator + 2³.to_add[0] + 2².to_add[1] + 2¹.to_add[2] + to_add[3]
            accumulator = accumulator.multiple_montgomery_ladder(&mut to_add, builder, driver)?;
        }

        // Subtract the skew factors (if any)
        for i in 0..msm_size {
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

        // Subtract the scaled offset generator
        accumulator.sub(&mut offset_generator_end, builder, driver)
    }

    // Perform repeated iterations of the montgomery ladder algorithm.
    // For points P, Q, montgomery ladder computes R = (P + Q) + P
    // i.e. it's "double-and-add" without explicit doublings.
    // This method can apply repeated iterations of the montgomery ladder.
    // Each iteration reduces the number of field multiplications by 1, at the cost of more additions.
    // (i.e. we don't compute intermediate y-coordinates).
    // The number of additions scales with the size of the input vector. The optimal input size appears to be 4.
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

        // Handle edge case of empty input
        if add.is_empty() {
            return Ok(self.clone());
        }

        // Let A = (x, y) and P = (x₁, y₁)
        // For the first point P, we want to compute: (2A + P) = (A + P) + A
        // We first need to check if x ≠ x₁.
        self.x
            .assert_is_not_equal(&add[0].x3_prev, builder, driver)?;

        // Compute λ₁ for computing the first addition: (A + P)
        let mut lambda1 = if !add[0].is_element {
            // Case 1: P is an accumulator (i.e., it lacks a y-coordinate)
            //         λ₁ = (y - y₁) / (x - x₁)
            //            = -(y₁ - y) / (x - x₁)
            //            = -(λ₁_ₚᵣₑᵥ * (x₁_ₚᵣₑᵥ - x₁) - y₁_ₚᵣₑᵥ - y) / (x - x₁)
            //
            // NOTE: msub_div computes -(∑ᵢ aᵢ * bᵢ + ∑ⱼcⱼ) / d
            // TODO CESAR: Use variables for the arguments for readability
            BigField::msub_div(
                &mut [add[0].lambda_prev.clone()],
                &mut [add[0]
                    .x1_prev
                    .clone()
                    .sub(&mut add[0].x3_prev, builder, driver)?],
                &mut self.x.sub(&mut add[0].x3_prev, builder, driver)?,
                &mut [
                    add[0].y1_prev.neg(builder, driver)?,
                    self.y.neg(builder, driver)?,
                ],
                false,
                builder,
                driver,
            )?
        } else {
            // Case 2: P is a full element (i.e., it has a y-coordinate)
            //         λ₁ = (y - y₁) / (x - x₁)
            //
            BigField::div_without_denominator_check(
                &mut [self.y.sub(&mut add[0].y3_prev, builder, driver)?],
                &mut self.x.sub(&mut add[0].x3_prev, builder, driver)?,
                builder,
                driver,
            )?
        };

        // Using λ₁, compute x₃ for (A + P):
        // x₃ = λ₁.λ₁ - x₁ - x
        let mut x_3 = lambda1.madd(
            &mut lambda1.clone(),
            &mut [
                add[0].x3_prev.neg(builder, driver)?,
                self.x.neg(builder, driver)?,
            ],
            builder,
            driver,
        )?;

        // Compute λ₂ for the addition (A + P) + A:
        // λ₂ = (y - y₃) / (x - x₃)
        //    = (y - (λ₁ * (x - x₃) - y)) / (x - x₃)    (substituting y₃)
        //    = (2y) / (x - x₃) - λ₁
        //
        self.x.assert_is_not_equal(&x_3, builder, driver)?;
        let mut lambda_2 = BigField::div_without_denominator_check(
            &mut [self.y.clone().add(&mut self.y, builder, driver)?],
            &mut self.x.sub(&mut x_3, builder, driver)?,
            builder,
            driver,
        )?
        .sub(&mut lambda1, builder, driver)?;

        // Using λ₂, compute x₄ for the final result:
        // x₄ = λ₂.λ₂ - x₃ - x
        let mut x_4 = lambda_2.sqradd(
            &mut [x_3.neg(builder, driver)?, self.x.neg(builder, driver)?],
            builder,
            driver,
        )?;

        // Compute y₄ for the final result:
        // y₄ = λ₂ * (x - x₄) - y
        //
        // However, we don't actually compute y₄ here. Instead, we build a "composite" y value that contains
        // the components needed to compute y₄ later. This is done to avoid the explicit multiplication here.
        //
        // We store the result as either y₄ or -y₄, depending on whether the number of points added
        // is even or odd. This sign adjustment simplifies the handling of subsequent additions in the loop below.
        // +y₄ = λ₂ * (x - x₄) - y
        // -y₄ = λ₂ * (x₄ - x) + y
        let num_points_even = (add.len() % 2) == 0;
        let tmp_add = if num_points_even {
            self.y.clone()
        } else {
            self.y.neg(builder, driver)?
        };
        let mul_left = vec![lambda_2];
        let tmp_mul_right = if num_points_even {
            x_4.sub(&mut self.x, builder, driver)?
        } else {
            self.x.sub(&mut x_4, builder, driver)?
        };
        let mut previous_y = CompositeY {
            mul_left,
            mul_right: vec![tmp_mul_right],
            add: vec![tmp_add],
            is_negative: num_points_even,
        };

        // Handle remaining iterations (i > 0) in a loop
        let mut previous_x = x_4;
        for i in 1..add.len() {
            // Let x = previous_x, y = previous_y
            // Let P = (xᵢ, yᵢ) be the next point to add (represented by add[i])
            // Ensure x-coordinates are distinct: x ≠ xᵢ
            previous_x.assert_is_not_equal(&add[i].x3_prev, builder, driver)?;

            // Determine sign adjustment based on previous y's sign
            // If the previous y was positive, we need to negate the y-component from add[i]
            let negate_add_y = !previous_y.is_negative;

            // Build λ₁ numerator components from previous composite y and current accumulator
            // TODO CESAR: Clones here?
            let mut lambda1_left = previous_y.mul_left.clone();
            let mut lambda1_right = previous_y.mul_right.clone();
            let mut lambda1_add = previous_y.add.clone();

            if !add[i].is_element {
                // Case 1: add[i] is an accumulator (lacks y-coordinate)
                //         λ₁ = (y - yᵢ) / (x - xᵢ)
                //            = -(yᵢ - y) / (x - xᵢ)
                //            = -(λᵢ_ₚᵣₑᵥ * (xᵢ_ₚᵣₑᵥ - xᵢ) - yᵢ_ₚᵣₑᵥ - y) / (x - xᵢ)
                //
                // If (previous) y is stored as positive, we compute λ₁ as:
                //         λ₁ = -(λᵢ_ₚᵣₑᵥ * (xᵢ - xᵢ_ₚᵣₑᵥ) + yᵢ_ₚᵣₑᵥ + y) / (xᵢ - x)
                //
                lambda1_left.push(add[i].lambda_prev.clone());
                let tmp = if negate_add_y {
                    add[i].x3_prev.sub(&mut add[i].x1_prev, builder, driver)?
                } else {
                    add[i].x1_prev.sub(&mut add[i].x3_prev, builder, driver)?
                };

                lambda1_right.push(tmp);
                let tmp = if negate_add_y {
                    add[i].y1_prev.clone()
                } else {
                    add[i].y1_prev.neg(builder, driver)?
                };

                lambda1_add.push(tmp);
            } else {
                // Case 2: add[i] is a full element (has y-coordinate)
                //         λ₁ = (yᵢ - y) / (xᵢ - x)
                //
                // If previous y is positive, we compute λ₁ as:
                //         λ₁ = -(y - yᵢ) / (xᵢ - x)
                //
                let tmp = if negate_add_y {
                    add[i].y3_prev.neg(builder, driver)?
                } else {
                    add[i].y3_prev.clone()
                };
                lambda1_add.push(tmp);
            }

            // Compute λ₁
            let denominator = if negate_add_y {
                add[i].x3_prev.sub(&mut previous_x, builder, driver)?
            } else {
                previous_x.sub(&mut add[i].x3_prev, builder, driver)?
            };
            let mut lambda1 = BigField::msub_div(
                &lambda1_left,
                &lambda1_right,
                &denominator,
                &lambda1_add,
                false,
                builder,
                driver,
            )?;

            // Using λ₁, compute x₃ for (previous + P):
            // x₃ = λ₁.λ₁ - xᵢ - x
            // y₃ = λ₁ * (x - x₃) - y (we don't compute this explicitly)
            let mut x_3 = lambda1.clone().madd(
                &mut lambda1.clone(),
                &mut [
                    add[i].x3_prev.neg(builder, driver)?,
                    previous_x.neg(builder, driver)?,
                ],
                builder,
                driver,
            )?;

            // Compute λ₂ using previous composite y
            // λ₂ = (y - y₃) / (x - x₃)
            //    = (y - (λ₁ * (x - x₃) - y)) / (x - x₃)    (substituting y₃)
            //    = (2y) / (x - x₃) - λ₁
            //    = -2(y / (x₃ - x)) - λ₁
            //
            previous_x.assert_is_not_equal(&x_3, builder, driver)?;
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
            let mut lambda_2 = partial_lambda2.sub(&mut lambda1, builder, driver)?;

            // Using λ₂, compute x₄ for the final result of this iteration:
            // x₄ = λ₂.λ₂ - x₃ - x
            let mut x_4 = lambda_2.sqradd(
                &mut [x_3.neg(builder, driver)?, previous_x.neg(builder, driver)?],
                builder,
                driver,
            )?;

            // Build composite y for this iteration
            // y₄ = λ₂ * (x - x₄) - y
            // However, we don't actually compute y₄ explicitly, we rather store components to compute it later.
            // We store the result as either y₄ or -y₄, depending on the sign of previous_y.
            // +y₄ = λ₂ * (x - x₄) - y
            // -y₄ = λ₂ * (x₄ - x) + y

            let mut y_4 = CompositeY {
                mul_left: vec![lambda_2],
                mul_right: vec![if previous_y.is_negative {
                    previous_x.sub(&mut x_4, builder, driver)?
                } else {
                    x_4.sub(&mut previous_x, builder, driver)?
                }],
                add: vec![],
                is_negative: !previous_y.is_negative,
            };

            // append terms in previous_y to y_4. We want to make sure the terms above are added into the start of y_4.
            // This is to ensure they are cached correctly when
            // `builder::evaluate_partial_non_native_field_multiplication` is called.
            // (the 1st mul_left, mul_right elements will trigger builder::evaluate_non_native_field_multiplication
            //  when Fq::mult_madd is called - this term cannot be cached so we want to make sure it is unique)
            // TODO CESAR: Verify this is correct
            y_4.mul_left.extend(previous_y.mul_left.iter().cloned());
            y_4.mul_right.extend(previous_y.mul_right.iter().cloned());
            y_4.add.extend(previous_y.add.iter().cloned());

            previous_x = x_4;
            previous_y = y_4;
        }
        let x_out = previous_x;

        assert!(
            !previous_y.is_negative,
            "Final y coordinate cannot be negative"
        );

        let y_out = BigField::mult_madd(
            &mut previous_y.mul_left.clone(),
            &mut previous_y.mul_right.clone(),
            &mut previous_y.add.clone(),
            false,
            builder,
            driver,
        )?;

        Ok(BigGroup::new(x_out, y_out))
    }

    fn precomputed_native_table_offset_generator<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >() -> eyre::Result<P::Affine> {
        let offset_generator = if TypeId::of::<P::Affine>() == TypeId::of::<G1Affine>() {
            let offset_generator_bn254 = G1Affine::new(
                field_from_hex_string(
                    "0x240d420bc60418af2206bdf32238eee77a8c46772f2679881a1858aab7b8927f",
                )
                .expect("Invalid hex string for offset generator"),
                field_from_hex_string(
                    "0x04ffcf276f8bc77315c2674207a3f55861b09acebd1ea9623883613f538e3822",
                )
                .expect("Invalid hex string for offset generator"),
            );

            // TACEO TODO: This will only work for BN254, hence the unsafe cast to P::Affine
            *unsafe { std::mem::transmute::<&G1Affine, &P::Affine>(&offset_generator_bn254) }
        } else {
            eyre::bail!("Precomputed offset generators not available for this curve");
        };

        Ok(offset_generator)
    }

    fn precomputed_offset_generators_native<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        num_rounds: usize,
    ) -> eyre::Result<(P::Affine, P::Affine)> {
        let offset_generator = if TypeId::of::<P::Affine>() == TypeId::of::<G1Affine>() {
            let offset_generator_bn254 = G1Affine::new(
                field_from_hex_string(
                    "0x169b33374f53b95f16edf369c34509da6485297ee10452a62af4bd2820d6fb33",
                )
                .expect("Invalid hex string for offset generator"),
                field_from_hex_string(
                    "0x019d6e473e9b638cfe2b8f232288a075050a381b745cffaa9f9264121567315b",
                )
                .expect("Invalid hex string for offset generator"),
            );

            // TACEO TODO: This will only work for BN254, hence the unsafe cast to P::Affine
            *unsafe { std::mem::transmute::<&G1Affine, &P::Affine>(&offset_generator_bn254) }
        } else {
            eyre::bail!("Precomputed offset generators not available for this curve");
        };

        let offset_multiplier = F::from(BigUint::one() << (num_rounds - 1));
        let offset_generator_end = offset_generator * offset_multiplier;
        Ok((offset_generator, offset_generator_end.into_affine()))
    }

    fn precomputed_offset_generators<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        num_rounds: usize,
    ) -> eyre::Result<(Self, Self)> {
        let (offset_generator, offset_generator_end) =
            Self::precomputed_offset_generators_native::<P>(num_rounds)?;
        Ok((
            BigGroup::from_constant_affine::<P>(&offset_generator)?,
            BigGroup::from_constant_affine::<P>(&offset_generator_end)?,
        ))
    }

    pub fn compute_naf<P: CurveGroup<ScalarField = F>>(
        scalar: &FieldCT<F>,
        max_num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Vec<BoolCT<F, T>>> {
        let num_rounds = if max_num_bits == 0 {
            (P::ScalarField::MODULUS_BIT_SIZE) as usize
        } else {
            max_num_bits
        };

        let scalar_value = scalar.get_value(builder, driver);
        let naf_entries_acvm_type = driver.compute_naf_entries(&scalar_value, num_rounds)?;

        // NAF representation consists of num_rounds bits and a skew bit.
        // Given a scalar k, we compute the NAF representation as follows:
        //
        // k = -skew + ₀∑ⁿ⁻¹ (1 - 2 * naf_i) * 2^i
        //
        // where naf_i = (1 - k_{i + 1}) ∈ {0, 1} and k_{i + 1} is the (i + 1)-th bit of the scalar k.
        // If naf_i = 0, then the i-th NAF entry is +1, otherwise it is -1. See the README for more details.
        //
        let mut naf_entries = vec![BoolCT::from(false); num_rounds + 1];
        // TODO CESAR: Use range constraint
        naf_entries[num_rounds] = BoolCT::from_witness_ct(
            WitnessCT::from_acvm_type(naf_entries_acvm_type[0].clone(), builder),
            builder,
        );

        for i in 0..num_rounds - 1 {
            // if the next entry is false, we need to flip the sign of the current entry. i.e. make negative
            // This is a VERY hacky workaround to ensure that UltraPlonkBuilder will apply a basic
            // range constraint per bool, and not a full 1-bit range gate
            // TODO CESAR: Check if this is correct
            let bit = BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(naf_entries_acvm_type[i + 1].clone(), builder),
                builder,
            );

            builder.create_new_range_constraint(bit.witness_index, 1);
            naf_entries[num_rounds - 1 - i] = bit;
        }

        // The most significant NAF entry is always (+1) as we are working with scalars < 2^{max_num_bits}.
        // Recall that true represents (-1) and false represents (+1).
        naf_entries[0] = BoolCT::from_witness_ct(
            WitnessCT::from_acvm_type(F::zero().into(), builder),
            builder,
        );
        // TODO CESAR: Range constraint

        // Validate correctness of NAF
        // TODO CESAR: Fr is composite?
        let mut accumulators = Vec::with_capacity(num_rounds + 1);
        let minus_two = FieldCT::from(F::from(2u64));
        let one = FieldCT::from(F::one());
        for i in 0..num_rounds {
            // bit = 1 - 2 * naf
            let shift = FieldCT::from(F::from(BigUint::one() << i));

            let entry = naf_entries[num_rounds - 1 - i]
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
            &mut self.x.sub(&mut x_4, builder, driver)?,
            &mut [self.y.neg(builder, driver)?],
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

    /// Doubles the point (i.e., computes 2P).
    /// This is the elliptic curve point doubling operation.
    /// Handles the point at infinity case.
    pub fn dbl<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // two_x = x + x
        let mut two_x = self.x.clone().add(&mut self.x.clone(), builder, driver)?;

        // TODO(): handle y = 0 case.

        // neg_lambda = -((x * (two_x + x)) / (y + y))
        let three_x = two_x.clone().add(&mut self.x.clone(), builder, driver)?;
        let mut denominator = self.y.clone().add(&mut self.y.clone(), builder, driver)?;
        let mut neg_lambda = BigField::msub_div(
            &mut [self.x.clone()],
            &mut [three_x],
            &mut denominator,
            &mut [],
            false,
            builder,
            driver,
        )?;

        // x_3 = neg_lambda^2 - two_x
        let x_3 = neg_lambda.sqradd(&mut [two_x.neg(builder, driver)?], builder, driver)?;

        // y_3 = neg_lambda * (x_3 - x) - y
        let mut x_3_minus_x = x_3.clone().sub(&mut self.x.clone(), builder, driver)?;
        let y_3 = neg_lambda.madd(
            &mut x_3_minus_x,
            &mut [self.y.neg(builder, driver)?],
            builder,
            driver,
        )?;

        let mut result = BigGroup::new(x_3, y_3);
        // Set point at infinity flag if input is at infinity
        result.set_is_infinity(self.is_infinity.clone());
        Ok(result)
    }

    pub(crate) fn conditional_negate<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        cond: &BoolCT<F, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let new_y = self.y.conditional_negate(cond, builder, driver)?;
        Ok(BigGroup::new(self.x.clone(), new_y))
    }

    /**
     * @brief Given two lists of points that need to be multiplied by scalars, create a new list of length +1 with original
     * points masked, but the same scalar product sum
     * @details Add +1G, +2G, +4G etc to the original points and adds a new point 2ⁿ⋅G and scalar x to the lists. By
     * doubling the point every time, we ensure that no +-1 combination of 6 sequential elements run into edgecases, unless
     * the points are deliberately constructed to trigger it.
     */
    fn mask_points<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        points: &mut [Self],
        scalars: &[FieldCT<F>],
        masking_scalar: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(Vec<Self>, Vec<FieldCT<F>>)> {
        let mut masked_points = Vec::new();
        let mut masked_scalars = Vec::new();

        debug_assert!(points.len() == scalars.len());

        // Get the offset generator G_offset in native and in-circuit form
        let native_offset_generator = Self::precomputed_native_table_offset_generator::<P>()?;
        let offset_generator_element =
            BigGroup::from_witness(&native_offset_generator, driver, builder)?;

        // Compute initial point to be added: (δ)⋅G_offset
        let mut running_point =
            offset_generator_element.scalar_mul(masking_scalar, 128, builder, driver)?;

        // Start the running scalar at 1
        let mut running_scalar = FieldCT::from(F::ONE);
        let mut last_scalar = FieldCT::from(F::ZERO);

        // For each point and scalar
        for (point, scalar) in points.iter_mut().zip(scalars.iter()) {
            masked_scalars.push(scalar.clone());

            // Convert point into point + 2ⁱ⋅G_offset
            masked_points.push(point.add(&mut running_point, builder, driver)?);

            // Add 2ⁱ⋅scalar_i to the last scalar
            let tmp = scalar.multiply(&running_scalar, builder, driver)?;
            last_scalar.add_assign(&tmp, builder, driver);

            // Double the running scalar and point for next iteration
            running_scalar.add_assign(&running_scalar.clone(), builder, driver);

            // Double the running point
            running_point = running_point.dbl(builder, driver)?;
        }

        // Add a scalar -(<(1,2,4,...,2ⁿ⁻¹ ),(scalar₀,...,scalarₙ₋₁)> / 2ⁿ)
        let n = points.len();
        let two_power_n = F::from(BigUint::one() << n);
        let two_power_n_inv = two_power_n.inverse().expect("Scalar inversion failed");
        last_scalar = last_scalar.multiply(&FieldCT::from(two_power_n_inv), builder, driver)?;
        masked_scalars.push(last_scalar.neg());

        // Add in-circuit 2ⁿ.(δ.G_offset) to points
        masked_points.push(running_point);

        Ok((masked_points, masked_scalars))
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

    /// Implements scalar multiplication that supports short scalars.
    /// For multiple scalar multiplication use `batch_mul` to save gates.
    /// `scalar` is a field element. If `max_num_bits` > 0, the length of the scalar must not exceed `max_num_bits`.
    /// `max_num_bits` should be even and < 254. Default value 0 corresponds to unspecified scalar length.
    pub fn scalar_mul<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        scalar: &FieldCT<F>,
        max_num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // Ensure max_num_bits is even
        assert!(max_num_bits % 2 == 0);

        // Check if the point is at infinity
        let is_point_at_infinity = self.is_infinity.clone();

        // Use batch_mul for single scalar multiplication
        let mut result = Self::batch_mul(
            &[self.clone()],
            &[scalar.clone()],
            max_num_bits,
            false,
            &FieldCT::from(F::ONE),
            builder,
            driver,
        )?;

        // If the input point is at infinity, propagate its coordinates and infinity flag
        let x = BigField::conditional_assign(
            &is_point_at_infinity,
            &mut self.x.clone(),
            &mut result.x,
            builder,
            driver,
        )?;
        let y = BigField::conditional_assign(
            &is_point_at_infinity,
            &mut self.y.clone(),
            &mut result.y,
            builder,
            driver,
        )?;

        let mut out = Self::new(x, y);
        out.is_infinity = is_point_at_infinity;

        Ok(out)
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
        p1.x.assert_is_not_equal(&p2.x, builder, driver)?;
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

    pub fn debug_print<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> String {
        let x_hex = self.x.debug_print(builder, driver);
        let y_hex = self.y.debug_print(builder, driver);

        format!("({},{})", x_hex, y_hex)
    }

    pub fn to_affine<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<P::Affine> {
        let x_value = self.x.get_value_fq(builder, driver)?;
        let y_value = self.y.get_value_fq(builder, driver)?;
        let [x, y] = driver
            .open_many_other(&[x_value, y_value])?
            .try_into()
            .unwrap();

        if TypeId::of::<P>() == TypeId::of::<Bn254G1>() {
            let (x_bn254, y_bn254) = unsafe {
                (
                    *mem::transmute::<&P::BaseField, &ark_bn254::Fq>(&x),
                    *mem::transmute::<&P::BaseField, &ark_bn254::Fq>(&y),
                )
            };
            let point_bn254 = ark_bn254::G1Affine::new(x_bn254, y_bn254);
            let point: P::Affine =
                unsafe { *mem::transmute::<&ark_bn254::G1Affine, &P::Affine>(&point_bn254) };
            return Ok(point);
        }

        eyre::bail!("to_affine not implemented for this curve")
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

impl<F: PrimeField> ChainAddAccumulator<F> {
    pub(crate) fn debug_print<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> String {
        format!(
            "ChainAddAccumulator(\n\tx3_prev: {},\n\t y3_prev: {},\n\t x1_prev: {},\n\t y1_prev: {},\n\t lambda_prev: {},\n\t is_element: {}\n)",
            self.x3_prev.debug_print(builder, driver),
            self.y3_prev.debug_print(builder, driver),
            self.x1_prev.debug_print(builder, driver),
            self.y1_prev.debug_print(builder, driver),
            self.lambda_prev.debug_print(builder, driver),
            self.is_element
        )
    }
}

mod tests {
    use ark_bn254::{Fq, Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::One;
    use ark_ff::Zero;
    use ark_ff::{PrimeField, UniformRand};
    use co_acvm::PlainAcvmSolver;
    use mpc_core::gadgets::field_from_hex_string;
    use num_bigint::BigUint;

    use crate::{
        prelude::GenericUltraCircuitBuilder,
        transcript_ct::Bn254G1,
        types::{big_field::BigField, big_group::BigGroup, field_ct::FieldCT},
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
    fn test_add_sub() {
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

    #[test]
    fn test_compute_naf() {
        let mut rng = rand::thread_rng();
        let builder = &mut GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(1);
        let driver = &mut PlainAcvmSolver::<Fr>::new();

        for length in 2..254 {
            let mut scalar_biguint: BigUint = Fr::rand(&mut rng).into();
            scalar_biguint = scalar_biguint >> (256 - length);

            // NAF with short scalars doesn't handle 0
            if scalar_biguint == BigUint::from(0u64) {
                scalar_biguint = BigUint::one();
            }

            let scalar_field = FieldCT::from(Fr::from(scalar_biguint.clone()));

            let naf = BigGroup::<Fr, PlainAcvmSolver<Fr>>::compute_naf(
                &scalar_field,
                length,
                builder,
                driver,
            )
            .unwrap();

            // scalar = -naf[L] + \sum_{i=0}^{L-1}(1-2*naf[i]) 2^{L-1-i}
            let mut reconstructed_scalar = Fr::zero();
            for i in 0..length {
                reconstructed_scalar += (Fr::one() - Fr::from(2u64) * naf[i].get_value(driver))
                    * Fr::from(BigUint::one() << (length - 1 - i) as u32);
            }

            reconstructed_scalar -= Fr::from(naf[length].get_value(driver));
            assert_eq!(
                reconstructed_scalar,
                Fr::from(scalar_biguint),
                "Failed for length {}",
                length
            );
        }
    }

    #[test]
    fn test_batch_mul_consistency() {
        let builder = &mut GenericUltraCircuitBuilder::<Bn254G1, PlainAcvmSolver<Fr>>::new(100);
        let driver = &mut PlainAcvmSolver::<Fr>::new();

        let num_points = 1;
        let point_x: Fq = field_from_hex_string(
            "0x14f0c23a3ed30648669282fc85f27e9774fd8f2f6159ad296ddaffdfb47dbfbe",
        )
        .unwrap();
        let point_y: Fq = field_from_hex_string(
            "0x16e9ac387918e0a1a326b5b103f51dec1cbeb1e28c0c6630fa4c54f9c64aa6fa",
        )
        .unwrap();
        let scalar: Fr = field_from_hex_string(
            "0x0a778a2e61449eee90a6459895a8250e8564315d8e76790e5f479651dbe9be45",
        )
        .unwrap();

        let result_x: Fq = field_from_hex_string(
            "0x072d8907368eac980ef02f2078a8bd44d9d38102d379bdb7f54c169c31f434e6",
        )
        .unwrap();
        let result_y: Fq = field_from_hex_string(
            "0x2e9835a1d0a4d5481cd0591970d9086369ea3a83f3a27c01996b3af9dcef2630",
        )
        .unwrap();

        let point = G1Affine::new(point_x, point_y);

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let expected_result = G1Affine::new(result_x, result_y);

        for _ in 0..num_points {
            points.push(affine_to_biggroup(&point, builder, driver, false));
            scalars.push(FieldCT::from_witness(scalar, builder));
        }

        let result = BigGroup::batch_mul(
            &points,
            &scalars,
            0,
            false,
            &FieldCT::from(Fr::one()),
            builder,
            driver,
        )
        .unwrap();

        let result_affine = biggroup_to_affine(&result, driver, builder);

        assert_eq!(result_affine, expected_result);
    }
}
