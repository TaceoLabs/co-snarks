use crate::eccvm::co_ecc_op_queue::precompute_flags;
use crate::mega_builder::MegaCircuitBuilder;
use crate::types::field_ct::BoolCT;
use crate::types::field_ct::FieldCT;
use crate::types::field_ct::WitnessCT;
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use itertools::izip;
use std::fmt::Debug;
const LIMB_BITS: usize = 136; // Each GoblinField element is represented as 2 field elements of 136 bits each

pub struct GoblinElement<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub x: GoblinField<P::ScalarField>,
    pub y: GoblinField<P::ScalarField>,
    pub is_infinity: BoolCT<P, T>,
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub fn new(x: GoblinField<P::ScalarField>, y: GoblinField<P::ScalarField>) -> Self {
        Self {
            x,
            y,
            is_infinity: BoolCT::default(),
        }
    }
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone for GoblinElement<P, T> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            is_infinity: self.is_infinity.clone(),
        }
    }
}

impl<P: CurveGroup<BaseField: PrimeField>, T: NoirWitnessExtensionProtocol<P::ScalarField>> Debug
    for GoblinElement<P, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoblinElement")
            .field("x", &self.x)
            .field("y", &self.y)
            .field("is_infinity", &self.is_infinity)
            .finish()
    }
}

impl<P: CurveGroup<BaseField: PrimeField>, T: NoirWitnessExtensionProtocol<P::ScalarField>> Default
    for GoblinElement<P, T>
{
    fn default() -> Self {
        Self {
            x: GoblinField::new([
                FieldCT::from_witness_index(u32::MAX),
                FieldCT::from_witness_index(u32::MAX),
            ]),
            y: GoblinField::new([
                FieldCT::from_witness_index(u32::MAX),
                FieldCT::from_witness_index(u32::MAX),
            ]),
            is_infinity: BoolCT::from(true),
        }
    }
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub fn set_point_at_infinity(&mut self, is_infinity: BoolCT<P, T>) {
        self.is_infinity = is_infinity;
    }
}

#[derive(Clone)]
pub struct GoblinField<F: PrimeField> {
    pub limbs: [FieldCT<F>; 2],
}

impl<F: PrimeField> Debug for GoblinField<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoblinField")
            .field("limbs", &self.limbs)
            .finish()
    }
}

impl<F: PrimeField> GoblinField<F> {
    pub fn new(limbs: [FieldCT<F>; 2]) -> Self {
        Self { limbs }
    }
}
impl GoblinField<TranscriptFieldType> {
    pub fn get_value<
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
    >(
        &self,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> (T::AcvmType, T::AcvmType) {
        let x = self.limbs[0].get_value(builder, driver);
        let y = self.limbs[1].get_value(builder, driver);
        (x, y)
    }
}

impl<
    P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
> GoblinElement<P, T>
{
    pub fn get_value(
        &self,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> HonkProofResult<T::NativeAcvmPoint<P>> {
        let (x0, x1) = self.x.get_value(builder, driver);
        let (y0, y1) = self.y.get_value(builder, driver);
        let is_infinity = self.is_infinity.get_value(driver);
        Ok(driver.acvm_types_to_native_point::<LIMB_BITS, _>(x0, x1, y0, y1, is_infinity)?)
    }

    pub fn get_value_many(
        points: &[Self],
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<T::NativeAcvmPoint<P>>> {
        let limbs = points
            .iter()
            .map(|point| {
                let (x0, x1) = point.x.get_value(builder, driver);
                let (y0, y1) = point.y.get_value(builder, driver);
                let is_infinity = point.is_infinity.get_value(driver);
                (x0, x1, y0, y1, is_infinity)
            })
            .collect::<Vec<_>>();

        Ok(driver.acvm_types_to_native_point_many::<LIMB_BITS, _>(&limbs)?)
    }

    pub fn from_witness(
        point: T::NativeAcvmPoint<P>,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> HonkProofResult<Self> {
        let (x0, x1, y0, y1, is_infinity) =
            driver.native_point_to_acvm_types::<LIMB_BITS, _>(point)?;
        let x_lo = FieldCT::from_witness(x0, builder);
        let x_hi = FieldCT::from_witness(x1, builder);
        let y_lo = FieldCT::from_witness(y0, builder);
        let y_hi = FieldCT::from_witness(y1, builder);
        Ok(Self {
            x: GoblinField {
                limbs: [x_lo, x_hi],
            },
            y: GoblinField {
                limbs: [y_lo, y_hi],
            },
            is_infinity: BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(is_infinity, builder),
                builder,
            ),
        })
    }

    pub fn from_witness_many(
        points: Vec<T::NativeAcvmPoint<P>>,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<Self>> {
        let res = driver
            .native_point_to_acvm_types_many::<LIMB_BITS, _>(&points)?
            .into_iter()
            .map(|(x_lo, x_hi, y_lo, y_hi, is_infinity)| {
                (
                    FieldCT::from_witness(x_lo, builder),
                    FieldCT::from_witness(x_hi, builder),
                    FieldCT::from_witness(y_lo, builder),
                    FieldCT::from_witness(y_hi, builder),
                    BoolCT::from_witness_ct(
                        WitnessCT::from_acvm_type(is_infinity, builder),
                        builder,
                    ),
                )
            })
            .map(|(x_lo, x_hi, y_lo, y_hi, is_infinity)| Self {
                x: GoblinField {
                    limbs: [x_lo, x_hi],
                },
                y: GoblinField {
                    limbs: [y_lo, y_hi],
                },
                is_infinity,
            })
            .collect::<Vec<Self>>();

        Ok(res)
    }

    pub fn point_at_infinity(builder: &mut MegaCircuitBuilder<P, T>) -> Self {
        let zero = FieldCT::from_witness_index(builder.zero_idx);

        Self {
            x: GoblinField {
                limbs: [zero.clone(), zero.clone()],
            },
            y: GoblinField {
                limbs: [zero.clone(), zero.clone()],
            },
            is_infinity: true.into(),
        }
    }

    pub fn one(builder: &mut MegaCircuitBuilder<P, T>) -> Self {
        let two = FieldCT::from_witness(P::ScalarField::from(2u64).into(), builder);
        let one = FieldCT::from_witness(P::ScalarField::ONE.into(), builder);
        let zero = FieldCT::from_witness_index(builder.zero_idx);
        Self {
            x: GoblinField {
                limbs: [one, zero.clone()],
            },
            y: GoblinField { limbs: [two, zero] },
            is_infinity: false.into(),
        }
    }

    pub fn neg(
        &self,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<GoblinElement<P, T>> {
        let element_value = self.get_value(builder, driver)?;

        let result_value = driver.negate_native_point(element_value)?;

        let element_limbs = [
            self.x.limbs[0].get_value(builder, driver),
            self.x.limbs[1].get_value(builder, driver),
            self.y.limbs[0].get_value(builder, driver),
            self.y.limbs[1].get_value(builder, driver),
            self.is_infinity.get_value(driver),
        ];

        // TACEO TODO: batch these two queue_ecc_add_accum calls
        let op_tuple = builder.queue_ecc_add_accum(element_value, Some(element_limbs), driver)?;

        {
            let x_lo = FieldCT::from_witness_index(op_tuple.x_lo);
            let x_hi = FieldCT::from_witness_index(op_tuple.x_hi);
            let y_lo = FieldCT::from_witness_index(op_tuple.y_lo);
            let y_hi = FieldCT::from_witness_index(op_tuple.y_hi);

            x_lo.assert_equal(&self.x.limbs[0], builder, driver);
            x_hi.assert_equal(&self.x.limbs[1], builder, driver);
            y_lo.assert_equal(&self.y.limbs[0], builder, driver);
            y_hi.assert_equal(&self.y.limbs[1], builder, driver);
        }

        let op_tuple_2 = builder.queue_ecc_add_accum(result_value, None, driver)?;

        let result = {
            let x_lo = FieldCT::from_witness_index(op_tuple_2.x_lo);
            let x_hi = FieldCT::from_witness_index(op_tuple_2.x_hi);
            let y_lo = FieldCT::from_witness_index(op_tuple_2.y_lo);
            let y_hi = FieldCT::from_witness_index(op_tuple_2.y_hi);

            let mut result = GoblinElement::new(
                GoblinField::new([x_lo.clone(), x_hi.clone()]),
                GoblinField::new([y_lo.clone(), y_hi.clone()]),
            );

            // if the output is at infinity, this is represented by x/y coordinates being zero
            // because they are all 136-bit, we can do a cheap zerocheck by first summing the limbs
            let op2_is_infinity = x_lo
                .add_two(&x_hi, &y_lo, builder, driver)
                .add(&y_hi, builder, driver)
                .is_zero(builder, driver)?;
            result.set_point_at_infinity(op2_is_infinity);

            result
        };

        let ecc_op_tuple_3 = builder.queue_ecc_eq(driver)?;
        let point_at_infinity = GoblinElement::point_at_infinity(builder);
        {
            let x_lo = FieldCT::from_witness_index(ecc_op_tuple_3.x_lo);
            let x_hi = FieldCT::from_witness_index(ecc_op_tuple_3.x_hi);
            let y_lo = FieldCT::from_witness_index(ecc_op_tuple_3.y_lo);
            let y_hi = FieldCT::from_witness_index(ecc_op_tuple_3.y_hi);

            x_lo.assert_equal(&point_at_infinity.x.limbs[0], builder, driver);
            x_hi.assert_equal(&point_at_infinity.x.limbs[1], builder, driver);
            y_lo.assert_equal(&point_at_infinity.y.limbs[0], builder, driver);
            y_hi.assert_equal(&point_at_infinity.y.limbs[1], builder, driver);
        }

        Ok(result)
    }

    /**
     * @brief Goblin style batch multiplication
     *
     * @details In goblin-style arithmetization, the operands (points/scalars) for each mul-accumulate operation are
     * decomposed into smaller components and written to an operation queue via the builder. The components are also added
     * as witness variables. This function adds constraints demonstrating the fidelity of the point/scalar decompositions
     * given the indices of the components in the variables array. The actual mul-accumulate operations are performed
     * natively (without constraints) under the hood, and the final result is obtained by queueing an equality operation via
     * the builder. The components of the result are returned as indices into the variables array from which the resulting
     * accumulator point is re-constructed.
     * @note Because this is the only method for performing Goblin-style group operations (Issue #707), it is sometimes used
     * in situations where one of the scalars is 1 (e.g. to perform P = P_0 + z*P_1). In this case, we perform a simple add
     * accumulate instead of a mul-then_accumulate.
     *
     * @tparam C CircuitBuilder
     * @tparam Fq Base field
     * @tparam Fr Scalar field
     * @tparam G Native group
     * @param points
     * @param scalars
     * @param max_num_bits
     * @return element<C, Fq, Fr, G>
     */
    pub fn batch_mul(
        points: &[Self],
        scalars: &[FieldCT<P::ScalarField>],
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<GoblinElement<P, T>> {
        // TACEO TODO: Assert?
        // Assert the accumulator is zero at the start
        // assert!(builder.ecc_op_queue.get_accumulator().is_zero_point());

        let mut co_eccvm_ops = Vec::with_capacity(points.len());

        // Decompose all points into limbs and add them as witness variables
        let point_limbs = points
            .iter()
            .map(|point| {
                [
                    point.x.limbs[0].get_value(builder, driver),
                    point.x.limbs[1].get_value(builder, driver),
                    point.y.limbs[0].get_value(builder, driver),
                    point.y.limbs[1].get_value(builder, driver),
                    point.is_infinity.get_value(driver),
                ]
            })
            .collect::<Vec<_>>();

        let point_values = GoblinElement::get_value_many(points, builder, driver)?;

        for i in 0..points.len() {
            let point = &points[i];
            let scalar = &scalars[i];
            let precomputed_point_limbs = Some(point_limbs[i]);
            let point_value = point_values[i];

            // TACEO TODO: Origin Tags?

            // Populate the goblin-style ecc op gates for the given mul inputs
            // If scalar is 1, there is no need to perform a mul
            let scalar_is_constant_equal_one = scalar.is_constant()
                && scalar.get_value(builder, driver) == P::ScalarField::ONE.into();

            // TACEO TODO: all the points are converted to field shares, so we should batch this
            let (op_tuple, co_eccvm_op) = if scalar_is_constant_equal_one {
                // if scalar is 1, there is no need to perform a mul
                builder.queue_ecc_add_accum_no_store(
                    point_value,
                    precomputed_point_limbs,
                    driver,
                )?
            } else {
                // otherwise, perform a mul-then-accumulate
                builder.queue_ecc_mul_accum_no_store(
                    point_value,
                    precomputed_point_limbs,
                    scalar.get_value(builder, driver),
                    driver,
                )?
            };

            co_eccvm_ops.push(co_eccvm_op);

            // Add constraints demonstrating that the EC point coordinates were decomposed faithfully. In particular, show
            // that the lo-hi components that have been encoded in the op wires can be reconstructed via the limbs of the
            // original point coordinates.
            let x_lo = FieldCT::from_witness_index(op_tuple.x_lo);
            let x_hi = FieldCT::from_witness_index(op_tuple.x_hi);
            let y_lo = FieldCT::from_witness_index(op_tuple.y_lo);
            let y_hi = FieldCT::from_witness_index(op_tuple.y_hi);

            // Note: These constraints do not assume or enforce that the coordinates of the original point have been
            // asserted to be in the field, only that they are less than the smallest power of 2 greater than the field
            // modulus (a la the bigfield(lo, hi) constructor with can_overflow == false).
            // TACEO TODO: assert!(point.x.get_maximum_value() <= P::BaseField::default_maximum_remainder());
            // TACEO TODO: assert!(point.y.get_maximum_value() <= P::BaseField::default_maximum_remainder());
            x_lo.assert_equal(&point.x.limbs[0], builder, driver);
            x_hi.assert_equal(&point.x.limbs[1], builder, driver);
            y_lo.assert_equal(&point.y.limbs[0], builder, driver);
            y_hi.assert_equal(&point.y.limbs[1], builder, driver);

            // Add constraints demonstrating proper decomposition of scalar into endomorphism scalars
            if !scalar_is_constant_equal_one {
                let z_1 = FieldCT::from_witness_index(op_tuple.z_1);
                let z_2 = FieldCT::from_witness_index(op_tuple.z_2);
                let beta = FieldCT::from_witness(
                    P::ScalarField::get_root_of_unity(3)
                        .expect("P::ScalarField should have a cube root of unity")
                        .into(),
                    builder,
                );
                scalar.assert_equal(
                    &z_1.sub(&z_2.multiply(&beta, builder, driver)?, builder, driver),
                    builder,
                    driver,
                );
            }
        }

        // Precompute is_zero flags and append the eccvm operations to the builder's eccvm op queue
        precompute_flags(&mut co_eccvm_ops, driver)?;
        builder.ecc_op_queue.append_eccvm_ops(co_eccvm_ops);

        // Populate equality gates based on the internal accumulator point
        let op_tuple = builder.queue_ecc_eq(driver)?;

        // Reconstruct the result of the batch mul using indices into the variables array
        let x_lo = FieldCT::from_witness_index(op_tuple.x_lo);
        let x_hi = FieldCT::from_witness_index(op_tuple.x_hi);
        let y_lo = FieldCT::from_witness_index(op_tuple.y_lo);
        let y_hi = FieldCT::from_witness_index(op_tuple.y_hi);

        let mut result = GoblinElement::new(
            GoblinField::new([x_lo.clone(), x_hi.clone()]),
            GoblinField::new([y_lo.clone(), y_hi.clone()]),
        );

        // NOTE: this used to be set as a circuit constant from `op_tuple.return_is_infinity`
        // I do not see how this was secure as it meant a circuit constant could change depending on witness values
        // e.g. x*[P] + y*[Q] where `x = y` and `[P] = -[Q]`
        // AZTEC TODO(@zac-williamson) what is op_queue.return_is_infinity actually used for? I don't see its value
        let op2_is_infinity = x_lo
            .add_two(&x_hi, &y_lo, builder, driver)
            .add(&y_hi, builder, driver)
            .is_zero(builder, driver)?;
        result.set_point_at_infinity(op2_is_infinity);

        // TACEO TODO: Origin Tags?

        Ok(result)
    }

    pub fn batch_mul_many(
        points: &[Vec<Self>],
        scalars: &[Vec<FieldCT<P::ScalarField>>],
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Vec<GoblinElement<P, T>>> {
        assert!(points.len() == scalars.len());

        // Decompose all points into limbs and add them as witness variables
        let point_limbs = points
            .iter()
            .map(|points| {
                points
                    .iter()
                    .map(|point| {
                        [
                            point.x.limbs[0].get_value(builder, driver),
                            point.x.limbs[1].get_value(builder, driver),
                            point.y.limbs[0].get_value(builder, driver),
                            point.y.limbs[1].get_value(builder, driver),
                            point.is_infinity.get_value(driver),
                        ]
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let flat_points: Vec<_> = points.iter().flatten().cloned().collect();
        let flat_point_values = GoblinElement::get_value_many(&flat_points, builder, driver)?;
        let mut point_values = Vec::with_capacity(points.len());
        let mut start = 0;
        for p in points {
            let box_len = p.len();
            point_values.push(flat_point_values[start..start + box_len].to_vec());
            start += box_len;
        }

        let mut results = Vec::with_capacity(points.len());
        for (points, scalars, point_limbs, point_values) in
            izip!(points, scalars, point_limbs, point_values)
        {
            let mut co_eccvm_ops = Vec::with_capacity(points.len());
            for i in 0..points.len() {
                let point = &points[i];
                let scalar = &scalars[i];
                let precomputed_point_limbs = Some(point_limbs[i]);
                let point_value = point_values[i];

                // TACEO TODO: Origin Tags?

                // Populate the goblin-style ecc op gates for the given mul inputs
                // If scalar is 1, there is no need to perform a mul
                let scalar_is_constant_equal_one = scalar.is_constant()
                    && scalar.get_value(builder, driver) == P::ScalarField::ONE.into();

                // TACEO TODO: all the points are converted to field shares, so we should batch this
                let (op_tuple, co_eccvm_op) = if scalar_is_constant_equal_one {
                    // if scalar is 1, there is no need to perform a mul
                    builder.queue_ecc_add_accum_no_store(
                        point_value,
                        precomputed_point_limbs,
                        driver,
                    )?
                } else {
                    // otherwise, perform a mul-then-accumulate
                    builder.queue_ecc_mul_accum_no_store(
                        point_value,
                        precomputed_point_limbs,
                        scalar.get_value(builder, driver),
                        driver,
                    )?
                };

                co_eccvm_ops.push(co_eccvm_op);

                // Add constraints demonstrating that the EC point coordinates were decomposed faithfully. In particular, show
                // that the lo-hi components that have been encoded in the op wires can be reconstructed via the limbs of the
                // original point coordinates.
                let x_lo = FieldCT::from_witness_index(op_tuple.x_lo);
                let x_hi = FieldCT::from_witness_index(op_tuple.x_hi);
                let y_lo = FieldCT::from_witness_index(op_tuple.y_lo);
                let y_hi = FieldCT::from_witness_index(op_tuple.y_hi);

                // Note: These constraints do not assume or enforce that the coordinates of the original point have been
                // asserted to be in the field, only that they are less than the smallest power of 2 greater than the field
                // modulus (a la the bigfield(lo, hi) constructor with can_overflow == false).
                // TACEO TODO: assert!(point.x.get_maximum_value() <= P::BaseField::default_maximum_remainder());
                // TACEO TODO: assert!(point.y.get_maximum_value() <= P::BaseField::default_maximum_remainder());
                x_lo.assert_equal(&point.x.limbs[0], builder, driver);
                x_hi.assert_equal(&point.x.limbs[1], builder, driver);
                y_lo.assert_equal(&point.y.limbs[0], builder, driver);
                y_hi.assert_equal(&point.y.limbs[1], builder, driver);

                // Add constraints demonstrating proper decomposition of scalar into endomorphism scalars
                if !scalar_is_constant_equal_one {
                    let z_1 = FieldCT::from_witness_index(op_tuple.z_1);
                    let z_2 = FieldCT::from_witness_index(op_tuple.z_2);
                    let beta = FieldCT::from_witness(
                        P::ScalarField::get_root_of_unity(3)
                            .expect("P::ScalarField should have a cube root of unity")
                            .into(),
                        builder,
                    );
                    scalar.assert_equal(
                        &z_1.sub(&z_2.multiply(&beta, builder, driver)?, builder, driver),
                        builder,
                        driver,
                    );
                }
            }

            // TACEO TODO: Check if these flag precomputations can be batched
            // Precompute is_zero flags and append the eccvm operations to the builder's eccvm op queue
            precompute_flags(&mut co_eccvm_ops, driver)?;
            builder.ecc_op_queue.append_eccvm_ops(co_eccvm_ops);

            // Populate equality gates based on the internal accumulator point
            let op_tuple = builder.queue_ecc_eq(driver)?;

            // Reconstruct the result of the batch mul using indices into the variables array
            let x_lo = FieldCT::from_witness_index(op_tuple.x_lo);
            let x_hi = FieldCT::from_witness_index(op_tuple.x_hi);
            let y_lo = FieldCT::from_witness_index(op_tuple.y_lo);
            let y_hi = FieldCT::from_witness_index(op_tuple.y_hi);

            let mut result = GoblinElement::new(
                GoblinField::new([x_lo.clone(), x_hi.clone()]),
                GoblinField::new([y_lo.clone(), y_hi.clone()]),
            );

            // NOTE: this used to be set as a circuit constant from `op_tuple.return_is_infinity`
            // I do not see how this was secure as it meant a circuit constant could change depending on witness values
            // e.g. x*[P] + y*[Q] where `x = y` and `[P] = -[Q]`
            // AZTEC TODO(@zac-williamson) what is op_queue.return_is_infinity actually used for? I don't see its value
            let op2_is_infinity = x_lo
                .add_two(&x_hi, &y_lo, builder, driver)
                .add(&y_hi, builder, driver)
                .is_zero(builder, driver)?;
            result.set_point_at_infinity(op2_is_infinity);

            results.push(result);
        }

        Ok(results)
    }
}
