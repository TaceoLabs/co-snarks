use ark_ff::FftField;
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::eccvm::co_ecc_op_queue::precompute_mul_acc_flags;
use co_builder::{
    mega_builder::MegaCircuitBuilder,
    prelude::NUM_WIRES,
    transcript::{TranscriptCT, TranscriptHasherCT},
    types::{
        field_ct::FieldCT,
        goblin_types::{GoblinElement, GoblinField},
    },
};
use common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
};
use itertools::Itertools;
use mpc_net::Network;

pub struct OpeningClaim<
    P: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
> {
    pub opening_pair: (FieldCT<P::ScalarField>, FieldCT<P::ScalarField>),
    pub commitment: GoblinElement<P, T>,
}
pub struct MergeRecursiveVerifier;

impl MergeRecursiveVerifier {
    /**
     * @brief Computes inputs to a pairing check that, if verified, establishes proper construction of the aggregate Goblin
     * ECC op queue polynomials T_j, j = 1,2,3,4.
     * @details Let T_j be the jth column of the aggregate ecc op table after prepending the subtable columns t_j containing
     * the contribution from a single circuit. T_{j,prev} corresponds to the columns of the aggregate table at the
     * previous stage. For each column we have the relationship T_j = t_j + right_shift(T_{j,prev}, k), where k is the
     * length of the subtable columns t_j. This protocol demonstrates, assuming the length of t is at most k, that the
     * aggregate ecc op table has been constructed correctly via the simple Schwartz-Zippel check:
     *
     *      T_j(\kappa) = t_j(\kappa) + \kappa^k * (T_{j,prev}(\kappa)).
     *
     * @tparam CircuitBuilder
     * @param proof
     * @return std::array<typename Flavor::GroupElement, 2> Inputs to final pairing
     */
    pub fn verify_proof<
        N: Network,
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<
                P,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<P>,
            >,
        H: TranscriptHasherCT<P>,
    >(
        &self,
        proof: Vec<FieldCT<P::ScalarField>>,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
        net: &N,
        state: &mut D::State,
    ) -> HonkProofResult<(GoblinElement<P, T>, GoblinElement<P, T>)> {
        // Transform proof into a stdlib object
        let mut transcript = TranscriptCT::<P, H>::new_verifier(proof);

        let subtable_size = transcript.receive_fr_from_prover("subtable_size".to_owned())?;

        // Receive table column polynomial commitments [t_j], [T_{j,prev}], and [T_j], j = 1,2,3,4
        let mut t_commitments = Vec::with_capacity(NUM_WIRES);
        let mut T_prev_commitments = Vec::with_capacity(NUM_WIRES);
        let mut T_commitments = Vec::with_capacity(NUM_WIRES);

        for idx in 0..NUM_WIRES {
            let suffix = idx.to_string();
            t_commitments.push(transcript.receive_point_from_prover(
                format!("t_CURRENT_{}", suffix),
                builder,
                driver,
            )?);
            T_prev_commitments.push(transcript.receive_point_from_prover(
                format!("T_PREV_{}", suffix),
                builder,
                driver,
            )?);
            T_commitments.push(transcript.receive_point_from_prover(
                format!("T_CURRENT_{}", suffix),
                builder,
                driver,
            )?);
        }

        let kappa = transcript.get_challenge("kappa".to_owned(), builder, driver)?;

        // Receive evaluations t_j(kappa), T_{j,prev}(kappa), T_j(kappa), j = 1,2,3,4
        let mut t_evals = Vec::with_capacity(NUM_WIRES);
        let mut T_prev_evals = Vec::with_capacity(NUM_WIRES);
        let mut T_evals = Vec::with_capacity(NUM_WIRES);
        let mut opening_claims = Vec::new();

        for idx in 0..NUM_WIRES {
            let eval = transcript.receive_fr_from_prover(format!("t_eval_{}", idx + 1))?;
            t_evals.push(eval.clone());
            opening_claims.push(OpeningClaim {
                opening_pair: (kappa.clone(), eval),
                commitment: t_commitments[idx].clone(),
            });
        }
        for idx in 0..NUM_WIRES {
            let eval = transcript.receive_fr_from_prover(format!("T_prev_eval_{}", idx + 1))?;
            T_prev_evals.push(eval.clone());
            opening_claims.push(OpeningClaim {
                opening_pair: (kappa.clone(), eval),
                commitment: T_prev_commitments[idx].clone(),
            });
        }
        for idx in 0..NUM_WIRES {
            let eval = transcript.receive_fr_from_prover(format!("T_eval_{}", idx + 1))?;
            T_evals.push(eval.clone());
            opening_claims.push(OpeningClaim {
                opening_pair: (kappa.clone(), eval),
                commitment: T_commitments[idx].clone(),
            });
        }

        // Check the identity T_j(kappa) = t_j(kappa) + kappa^m * T_{j,prev}(kappa)
        let kappa_pow = kappa.pow(&subtable_size, builder, driver);
        for idx in 0..NUM_WIRES {
            let T_prev_shifted_eval_reconstructed = T_prev_evals[idx]
                .multiply(&kappa_pow, builder, driver)
                .unwrap();
            let rhs = t_evals[idx].add(&T_prev_shifted_eval_reconstructed, builder, driver);
            T_evals[idx].assert_equal(&rhs, builder, driver);
        }

        let alpha = transcript.get_challenge("alpha".to_string(), builder, driver)?;

        // Construct inputs to batched commitment and batched evaluation from constituents using batching challenge alpha
        let mut scalars = Vec::new();
        let mut commitments = Vec::new();
        scalars.push(P::ScalarField::ONE.into());
        commitments.push(opening_claims[0].commitment.clone());
        let mut batched_eval = opening_claims[0].opening_pair.1.clone();
        let mut alpha_pow = alpha.clone();
        for claim in opening_claims.iter().skip(1) {
            scalars.push(alpha_pow.clone());
            commitments.push(claim.commitment.clone());
            let tmp = alpha_pow
                .multiply(&claim.opening_pair.1, builder, driver)
                .unwrap();
            batched_eval = batched_eval.add(&tmp, builder, driver);
            alpha_pow = alpha_pow.multiply(&alpha, builder, driver).unwrap();
        }

        let batched_commitment =
            Self::batch_mul(&commitments, &scalars, builder, driver, net, state);
        let opening_claim = OpeningClaim {
            commitment: batched_commitment,
            opening_pair: (kappa, batched_eval),
        };

        MergeRecursiveVerifier::reduce_verify(
            opening_claim,
            &mut transcript,
            builder,
            driver,
            net,
            state,
        )
    }

    fn batch_mul<
        N: Network,
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<
                P,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<P>,
            >,
    >(
        points: &Vec<GoblinElement<P, T>>,
        scalars: &Vec<FieldCT<P::ScalarField>>,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
        net: &N,
        state: &mut D::State,
    ) -> GoblinElement<P, T> {
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

            // TODO TACEO: Assumes that the point is always secret shared, to be solved once CoEccOpQueue is generic only on
            // NoirWitnessExtensionProtocol
            let point_share = T::get_shared_native_point(point_value).unwrap();
            let field_share = T::get_shared(&scalar.get_value(builder, driver)).unwrap();

            let (op_tuple, co_eccvm_op) = if scalar_is_constant_equal_one {
                // if scalar is 1, there is no need to perform a mul
                builder.queue_ecc_add_accum_no_store::<N>(point_share.into(), net, state)
            } else {
                // otherwise, perform a mul-then-accumulate
                builder.queue_ecc_mul_accum_no_store(point_share.into(), field_share, net, state)
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
                    &z_1.sub(
                        &z_2.multiply(&beta, builder, driver).unwrap(),
                        builder,
                        driver,
                    ),
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
            .is_zero(builder, driver)
            .expect("is_zero should not fail");
        result.set_point_at_infinity(op2_is_infinity);

        // TODO TACEO: Origin Tags?

        result
    }

    /**
     * @brief Computes the input points for the pairing check needed to verify a KZG opening claim of a single
     * polynomial commitment. This reduction is non-interactive and always succeeds.
     * @details This is used in the recursive setting where we want to "aggregate" proofs, not verify them.
     *
     * @param claim OpeningClaim ({r, v}, C)
     * @return  {P₀, P₁} where
     *      - P₀ = C − v⋅[1]₁ + r⋅[W(x)]₁
     *      - P₁ = - [W(x)]₁
     */
    fn reduce_verify<
        N: Network,
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<
                P,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<P>,
            >,
        H: TranscriptHasherCT<P>,
    >(
        opening_claim: OpeningClaim<P, T>,
        transcript: &mut TranscriptCT<P, H>,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
        net: &N,
        state: &mut D::State,
    ) -> HonkProofResult<(GoblinElement<P, T>, GoblinElement<P, T>)> {
        let quotient_commitment =
            transcript.receive_point_from_prover("KZG:W".to_owned(), builder, driver)?;

        // Note: The pairing check can be expressed naturally as
        // e(C - v * [1]_1, [1]_2) = e([W]_1, [X - r]_2) where C =[p(X)]_1. This can be rearranged (e.g. see the plonk
        // paper) as e(C + r*[W]_1 - v*[1]_1, [1]_2) * e(-[W]_1, [X]_2) = 1, or e(P_0, [1]_2) * e(P_1, [X]_2) = 1
        let one = FieldCT::from_witness(P::ScalarField::ONE.into(), builder);
        let commitments = vec![
            opening_claim.commitment.clone(),
            quotient_commitment.clone(),
            GoblinElement::one(builder),
        ];
        let scalars = vec![
            one.clone(),
            opening_claim.opening_pair.0,
            opening_claim.opening_pair.1.neg(),
        ];

        let p_0 = Self::batch_mul(&commitments, &scalars, builder, driver, net, state);

        // Construct P₁ = -[W(x)]
        // TODO CESAR: How to negate a goblin element
        let p_1 = Self::negate_goblin_element(&quotient_commitment, builder, driver, net, state);

        Ok((p_0, p_1))
    }

    pub fn negate_goblin_element<
        N: Network,
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<
                P,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<P>,
            >,
    >(
        element: &GoblinElement<P, T>,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
        net: &N,
        state: &mut D::State,
    ) -> GoblinElement<P, T> {
        let element_value = element.get_value(builder, driver);

        let result_value = driver
            .negate_native_point(element_value.clone())
            .expect("Failed to negate goblin element");

        let op_tuple = builder.queue_ecc_add_accum(
            T::get_shared_native_point(element_value).unwrap().into(),
            net,
            state,
        );

        {
            let x_lo = FieldCT::from_witness_index(op_tuple.x_lo);
            let x_hi = FieldCT::from_witness_index(op_tuple.x_hi);
            let y_lo = FieldCT::from_witness_index(op_tuple.y_lo);
            let y_hi = FieldCT::from_witness_index(op_tuple.y_hi);

            x_lo.assert_equal(&element.x.limbs[0], builder, driver);
            x_hi.assert_equal(&element.x.limbs[1], builder, driver);
            y_lo.assert_equal(&element.y.limbs[0], builder, driver);
            y_hi.assert_equal(&element.y.limbs[1], builder, driver);
        }

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
                .is_zero(builder, driver)
                .expect("is_zero should not fail");
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

        result
    }
}
