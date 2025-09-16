use crate::eccvm::co_ecc_op_queue::precompute_mul_acc_flags;
use crate::mega_builder::MegaCircuitBuilder;
use crate::types::field_ct::BoolCT;
use crate::types::field_ct::FieldCT;
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use common::honk_curve::HonkCurve;
use common::honk_proof::TranscriptFieldType;
use common::mpc::NoirUltraHonkProver;
use itertools::Itertools;
use mpc_net::Network;
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

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub fn set_point_at_infinity(&mut self, is_infinity: BoolCT<P, T>) {
        self.is_infinity = is_infinity;
    }
}

#[derive(Clone)]
pub struct GoblinField<F: PrimeField> {
    pub limbs: [FieldCT<F>; 2],
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
        D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>,
    >(
        &self,
        builder: &mut MegaCircuitBuilder<P, T, D>,
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
    pub fn get_value<D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>>(
        &self,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
    ) -> T::AcvmNativePoint<P> {
        let (x0, x1) = self.x.get_value(builder, driver);
        let (y0, y1) = self.y.get_value(builder, driver);
        let is_infinity = self.is_infinity.get_value(driver);
        driver
            .field_shares_to_native_pointshare::<LIMB_BITS, _>(x0, x1, y0, y1, is_infinity)
            .expect("Failed to convert field shares to native point share")
    }

    pub fn point_at_infinity<D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>>(
        builder: &mut MegaCircuitBuilder<P, T, D>,
    ) -> Self {
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

    pub fn one<D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>>(
        builder: &mut MegaCircuitBuilder<P, T, D>,
    ) -> Self {
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

    pub fn neg<
        N: Network,
        D: NoirUltraHonkProver<
                P,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<P>,
            >,
    >(
        &self,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
        net: &N,
        state: &mut D::State,
    ) -> eyre::Result<GoblinElement<P, T>> {
        let element_value = self.get_value(builder, driver);

        let result_value = driver.negate_native_point(element_value.clone())?;

        // TODO TACEO: Assumes that the point is always secret shared, this issue will be solved once CoEccOpQueue is generic only on
        // NoirWitnessExtensionProtocol
        let op_tuple = builder.queue_ecc_add_accum(
            T::get_shared_native_point(element_value).unwrap(),
            net,
            state,
        );

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

        // TODO TACEO: Assumes that the point is always secret shared, this issue will be solved once CoEccOpQueue is generic only on
        // NoirWitnessExtensionProtocol
        let result_share = T::get_shared_native_point(result_value).unwrap();
        let op_tuple_2 = builder.queue_ecc_add_accum(result_share, net, state);

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

        let ecc_op_tuple_3 = builder.queue_ecc_eq(net, state);
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
    pub fn batch_mul<
        N: Network,
        D: NoirUltraHonkProver<
                P,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<P>,
            >,
    >(
        points: &[Self],
        scalars: &[FieldCT<P::ScalarField>],
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
        net: &N,
        state: &mut D::State,
    ) -> eyre::Result<GoblinElement<P, T>> {
        // TODO TACEO: Assert?
        // Assert the accumulator is zero at the start
        // assert!(builder.ecc_op_queue.get_accumulator().is_zero_point());

        let mut co_eccvm_ops = Vec::with_capacity(points.len());

        for i in 0..points.len() {
            let point = &points[i];
            let scalar = &scalars[i];

            // TODO TACEO: Origin Tags?

            // Populate the goblin-style ecc op gates for the given mul inputs
            // If scalar is 1, there is no need to perform a mul
            let scalar_is_constant_equal_one = scalar.is_constant()
                && scalar.get_value(builder, driver) == P::ScalarField::ONE.into();

            let point_value = point.get_value(builder, driver);

            // TODO TACEO: Assumes that the point is always secret shared, this issue will be solved once CoEccOpQueue is generic only on
            // NoirWitnessExtensionProtocol
            let point_share = T::get_shared_native_point(point_value).unwrap();
            let field_share = T::get_shared(&scalar.get_value(builder, driver)).unwrap();

            let (op_tuple, co_eccvm_op) = if scalar_is_constant_equal_one {
                // if scalar is 1, there is no need to perform a mul
                builder.queue_ecc_add_accum_no_store::<N>(point_share, net, state)
            } else {
                // otherwise, perform a mul-then-accumulate
                builder.queue_ecc_mul_accum_no_store(point_share, field_share, net, state)
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
            // TODO TACEO: assert!(point.x.get_maximum_value() <= P::BaseField::default_maximum_remainder());
            // TODO TACEO: assert!(point.y.get_maximum_value() <= P::BaseField::default_maximum_remainder());
            x_lo.assert_equal(&point.x.limbs[0], builder, driver);
            x_hi.assert_equal(&point.x.limbs[1], builder, driver);
            y_lo.assert_equal(&point.y.limbs[0], builder, driver);
            y_hi.assert_equal(&point.y.limbs[1], builder, driver);

            // Add constraints demonstrating proper decomposition of scalar into endomorphism scalars
            if !scalar_is_constant_equal_one {
                let z_1 = FieldCT::from_witness_index(op_tuple.z_1);
                let z_2 = FieldCT::from_witness_index(op_tuple.z_2);
                let beta = FieldCT::from_witness(
                    P::ScalarField::get_root_of_unity(3).unwrap().into(),
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
        precompute_mul_acc_flags(&mut co_eccvm_ops.iter_mut().collect_vec(), net, state);
        builder.ecc_op_queue.append_eccvm_ops(co_eccvm_ops);

        // Populate equality gates based on the internal accumulator point
        let op_tuple = builder.queue_ecc_eq(net, state);

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

        // TODO TACEO: Origin Tags?

        Ok(result)
    }
}
