use ark_ff::AdditiveGroup;
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{
    flavours::mega_flavour::MegaFlavour,
    mega_builder::MegaCircuitBuilder,
    polynomials::polynomial_flavours::{PrecomputedEntitiesFlavour, WitnessEntitiesFlavour},
    prover_flavour::ProverFlavour,
    transcript::{TranscriptCT, TranscriptFieldType, TranscriptHasherCT},
    types::{field_ct::FieldCT, goblin_types::GoblinElement},
};
use co_noir_common::barycentric::Barycentric;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use co_ultrahonk::prelude::MPCProverFlavour;
use itertools::{Itertools, izip};

use crate::{
    prover::co_protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, CONST_PG_LOG_N, NUM_KEYS},
    recursive_verifier::{
        oink_recursive_verifier::OinkRecursiveVerifier,
        recursive_decider_verification_key::RecursiveDeciderVerificationKey,
    },
};

pub(crate) const COMBINER_LENGTH: usize = BATCHED_EXTENDED_LENGTH - NUM_KEYS;
pub(crate) const NUM_FOLDED_ENTITIES: usize =
    MegaFlavour::WITNESS_ENTITIES_SIZE + MegaFlavour::PRECOMPUTED_ENTITIES_SIZE;
pub(crate) const NUM_RELATION_PARAMS: usize = 7;
pub struct ProtogalaxyRecursiveVerifier;

impl ProtogalaxyRecursiveVerifier {
    fn run_oink_verifier_on_one_incomplete_key<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        H: TranscriptHasherCT<C>,
    >(
        verification_key: &mut RecursiveDeciderVerificationKey<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        OinkRecursiveVerifier::verify(verification_key, transcript, builder, driver)
    }

    fn run_oink_verifier_on_each_incomplete_key<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        H: TranscriptHasherCT<C>,
    >(
        accumulator: &mut RecursiveDeciderVerificationKey<C, T>,
        key_to_fold: &mut RecursiveDeciderVerificationKey<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        if !accumulator.is_accumulator {
            Self::run_oink_verifier_on_one_incomplete_key(
                accumulator,
                transcript,
                builder,
                driver,
            )?;
            accumulator.target_sum = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
            accumulator.gate_challenges =
                vec![FieldCT::from_witness(C::ScalarField::ZERO.into(), builder); CONST_PG_LOG_N];
        }

        Self::run_oink_verifier_on_one_incomplete_key(key_to_fold, transcript, builder, driver)
    }

    pub fn verify_folding_proofs<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        H: TranscriptHasherCT<C>,
    >(
        accumulator: &mut RecursiveDeciderVerificationKey<C, T>,
        key_to_fold: &mut RecursiveDeciderVerificationKey<C, T>,
        proof: Vec<FieldCT<C::ScalarField>>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

        let mut transcript = TranscriptCT::<C, H>::new_verifier(proof);
        Self::run_oink_verifier_on_each_incomplete_key(
            accumulator,
            key_to_fold,
            &mut transcript,
            builder,
            driver,
        )?;

        let delta = transcript.get_challenge("delta".to_owned(), builder, driver)?;

        let deltas = std::iter::successors(Some(delta), |x| {
            Some(
                x.multiply(x, builder, driver)
                    .expect("Failed to square delta"),
            )
        })
        .take(CONST_PG_LOG_N)
        .collect::<Vec<_>>();

        let perturbator_coeffs = (1..CONST_PG_LOG_N + 1)
            .map(|idx| {
                transcript
                    .receive_fr_from_prover(format!("perturbator_{idx}"))
                    .expect("Failed to get perturbator challenge")
            })
            .collect::<Vec<_>>();

        let perturbator_coeffs =
            [vec![accumulator.target_sum.clone()], perturbator_coeffs].concat();

        let perturbator_challenge =
            transcript.get_challenge("perturbator_challenge".to_owned(), builder, driver)?;

        let perturbator_evaluation = Self::evaluate_perturbator(
            &perturbator_challenge,
            &perturbator_coeffs,
            builder,
            driver,
        )?;

        let combiner_quotient_evals = (0..COMBINER_LENGTH)
            .map(|idx| {
                transcript
                    .receive_fr_from_prover(format!("combiner_quotient_{idx}"))
                    .expect("Failed to receive combiner quotient")
            })
            .collect::<Vec<_>>();

        let combiner_challenge =
            transcript.get_challenge("combiner_quotient_challenge".to_owned(), builder, driver)?;

        let combiner_quotient_at_challenge =
            Self::evaluate_with_domain_start::<COMBINER_LENGTH, _, _>(
                &combiner_quotient_evals
                    .try_into()
                    .expect("Failed to convert combiner quotient evals"),
                combiner_challenge.clone(),
                NUM_KEYS,
                builder,
                driver,
            )?;

        let vanishing_polynomial_at_challenge = combiner_challenge
            .sub(&one, builder, driver)
            .multiply(&combiner_challenge, builder, driver)?;

        let lagranges = [
            one.sub(&combiner_challenge, builder, driver),
            combiner_challenge.clone(),
        ];

        /*
        Fold the commitments
        Note: we use additional challenges to reduce the amount of elliptic curve work performed by the ECCVM

        For an accumulator commitment [P'] and an instance commitment [P] , we compute folded commitment [P''] where
        [P''] = L0(gamma).[P'] + L1(gamma).[P]
        For the size-2 case this becomes:
        P'' = (1 - gamma).[P'] + gamma.[P] = gamma.[P - P'] + [P']

        This requires a large number of size-1 scalar muls (about 53)
        The ECCVM can perform a size-k MSM in 32 + roundup((k/4)) rows, if each scalar multiplier is <128 bits
        i.e. number of ECCVM rows = 53 * 64 = painful

        To optimize, we generate challenges `c_i` for each commitment and evaluate the relation:

        [A] = \sum c_i.[P_i]
        [B] = \sum c_i.[P'_i]
        [C] = \sum c_i.[P''_i]
        and validate
        (1 - gamma).[A] + gamma.[B] == [C]


        This reduces the relation to 3 large MSMs where each commitment requires 3 size-128bit scalar multiplications
        For a flavor with 53 instance/witness commitments, this is 53 * 24 rows

        Note: there are more efficient ways to evaluate this relationship if one solely wants to reduce number of scalar
        muls, however we must also consider the number of ECCVM operations being executed, as each operation incurs a
        cost in the translator circuit Each ECCVM opcode produces 5 rows in the translator circuit, which is approx.
        equivalent to 9 ECCVM rows. Something to pay attention to
        */

        let mut accumulator_commitments = Vec::new();
        let mut instance_commitments = Vec::new();

        for (a, b) in izip!(
            accumulator.precomputed_commitments.iter(),
            key_to_fold.precomputed_commitments.iter()
        ) {
            accumulator_commitments.push(a.clone());
            instance_commitments.push(b.clone());
        }

        for (a, b) in izip!(
            accumulator.witness_commitments.iter(),
            key_to_fold.witness_commitments.iter()
        ) {
            accumulator_commitments.push(a.clone());
            instance_commitments.push(b.clone());
        }

        let lhs_scalar = one
            .sub(&combiner_challenge, builder, driver)
            .get_value(builder, driver);
        let rhs_scalar = combiner_challenge.get_value(builder, driver);

        let mut accumulator_values = GoblinElement::get_value_many(
            &[
                accumulator_commitments.as_slice(),
                instance_commitments.as_slice(),
            ]
            .concat(),
            builder,
            driver,
        )?;
        let instance_values = accumulator_values.split_off(accumulator_values.len() / 2);

        let mut output_values = Vec::with_capacity(accumulator_values.len());

        for (lhs, rhs) in izip!(accumulator_values, instance_values) {
            let lhs_scaled = driver.scale_native_point(lhs, lhs_scalar)?;
            let rhs_scaled = driver.scale_native_point(rhs, rhs_scalar)?;

            let output = driver.add_native_points(lhs_scaled, rhs_scaled);

            output_values.push(output);
        }

        let output_commitments = GoblinElement::from_witness_many(output_values, builder, driver)?;

        for (i, output_commitment) in output_commitments.iter().enumerate() {
            // Add the output commitment to the transcript to ensure that they can't be spoofed
            transcript.add_point_to_hash_buffer(
                format!("new_accumulator_commitment_{i}"),
                output_commitment,
            );
        }

        let labels = (0..NUM_FOLDED_ENTITIES)
            .map(|i| format!("accumulator_combination_challenges_{i}"))
            .collect_vec();
        let scalars = transcript.get_challenges(&labels, builder, driver)?;

        let [accumulator_sum, instance_sum, output_sum] = GoblinElement::batch_mul_many(
            &[
                accumulator_commitments,
                instance_commitments,
                output_commitments.clone(),
            ],
            &std::iter::repeat_n(scalars, 3).collect::<Vec<_>>(),
            builder,
            driver,
        )?
        .try_into()
        .expect("Failed to convert batch mul many output into array");

        let folded_sum = GoblinElement::batch_mul(
            &[accumulator_sum, instance_sum],
            &lagranges,
            builder,
            driver,
        )?;

        output_sum.x.limbs[0].assert_equal(&folded_sum.x.limbs[0], builder, driver);
        output_sum.x.limbs[1].assert_equal(&folded_sum.x.limbs[1], builder, driver);
        output_sum.y.limbs[0].assert_equal(&folded_sum.y.limbs[0], builder, driver);
        output_sum.y.limbs[1].assert_equal(&folded_sum.y.limbs[1], builder, driver);

        // Compute next folding parameters
        accumulator.is_accumulator = true;

        // Update circuit size
        let accumulator_circuit_size_value = accumulator
            .verification_key
            .circuit_size
            .get_value(builder, driver);
        let key_to_fold_circuit_size_value = key_to_fold
            .verification_key
            .circuit_size
            .get_value(builder, driver);
        let accumulator_log_circuit_size_value = accumulator
            .verification_key
            .log_circuit_size
            .get_value(builder, driver);
        let key_to_fold_log_circuit_size_value = key_to_fold
            .verification_key
            .log_circuit_size
            .get_value(builder, driver);

        let accumulator_is_smaller = driver.lt(
            accumulator_circuit_size_value,
            key_to_fold_circuit_size_value,
        )?;

        let [circuit_size, log_circuit_size] = driver
            .cmux_many(
                accumulator_is_smaller,
                &[
                    key_to_fold_circuit_size_value,
                    key_to_fold_log_circuit_size_value,
                ],
                &[
                    accumulator_circuit_size_value,
                    accumulator_log_circuit_size_value,
                ],
            )?
            .try_into()
            .expect("Failed to convert cmux output into array");

        accumulator.verification_key.circuit_size = FieldCT::from_witness(circuit_size, builder);
        accumulator.verification_key.log_circuit_size =
            FieldCT::from_witness(log_circuit_size, builder);

        let lhs = [
            accumulator.alphas.clone(),
            accumulator
                .relation_parameters
                .get_params()
                .into_iter()
                .cloned()
                .collect_vec(),
            key_to_fold.alphas.clone(),
            key_to_fold
                .relation_parameters
                .get_params()
                .into_iter()
                .cloned()
                .collect_vec(),
            deltas,
            vec![perturbator_evaluation, vanishing_polynomial_at_challenge],
        ]
        .concat();
        let rhs = [
            std::iter::repeat_n(
                lagranges[0].clone(),
                MegaFlavour::NUM_ALPHAS + NUM_RELATION_PARAMS,
            )
            .collect::<Vec<_>>(),
            std::iter::repeat_n(
                lagranges[1].clone(),
                MegaFlavour::NUM_ALPHAS + NUM_RELATION_PARAMS,
            )
            .collect::<Vec<_>>(),
            std::iter::repeat_n(perturbator_challenge.clone(), CONST_PG_LOG_N).collect::<Vec<_>>(),
            vec![lagranges[0].clone(), combiner_quotient_at_challenge],
        ]
        .concat();

        let tmp = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;
        let (tmp_1, tmp) = tmp.split_at(MegaFlavour::NUM_ALPHAS + NUM_RELATION_PARAMS);
        let (tmp_2, tmp) = tmp.split_at(MegaFlavour::NUM_ALPHAS + NUM_RELATION_PARAMS);
        let (deltas_by_perturbator, tmp) = tmp.split_at(CONST_PG_LOG_N);
        let perturbator_by_lagrange_0 = &tmp[0];
        let vanishing_by_combiner_quotient = &tmp[1];

        let (acc_alphas, acc_relation_params) = tmp_1.split_at(MegaFlavour::NUM_ALPHAS);
        let (key_alphas, key_relation_params) = tmp_2.split_at(MegaFlavour::NUM_ALPHAS);

        // Update target sum
        accumulator.target_sum =
            perturbator_by_lagrange_0.add(vanishing_by_combiner_quotient, builder, driver);

        // Update gate challenges
        accumulator
            .gate_challenges
            .iter_mut()
            .zip(deltas_by_perturbator)
            .for_each(|(c, delta)| {
                *c = c.add(delta, builder, driver);
            });

        // Update alphas
        accumulator.alphas = izip!(acc_alphas.iter(), key_alphas.iter())
            .map(|(a, b)| a.add(b, builder, driver))
            .collect();

        // Update relation parameters
        izip!(
            accumulator.relation_parameters.get_params_as_mut(),
            acc_relation_params.iter(),
            key_relation_params.iter()
        )
        .for_each(|(acc_param, acc_rel_param, key_rel_param)| {
            *acc_param = acc_rel_param.add(key_rel_param, builder, driver);
        });

        // Update precomputed commitments
        izip!(
            accumulator.precomputed_commitments.iter_mut(),
            output_commitments.iter()
        )
        .for_each(|(acc_commitment, new_commitment)| {
            *acc_commitment = new_commitment.clone();
        });

        // Update witness commitments
        izip!(
            accumulator.witness_commitments.iter_mut(),
            output_commitments
                .iter()
                .skip(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE)
        )
        .for_each(|(acc_commitment, new_commitment)| {
            *acc_commitment = new_commitment.clone();
        });

        Ok(())
    }

    fn evaluate_perturbator<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
    >(
        point: &FieldCT<C::ScalarField>,
        coeffs: &[FieldCT<C::ScalarField>],
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let point_accs = std::iter::successors(
            Some(FieldCT::from_witness(C::ScalarField::ONE.into(), builder)),
            |x| {
                Some(
                    x.multiply(point, builder, driver)
                        .expect("Failed to multiply"),
                )
            },
        )
        .take(CONST_PG_LOG_N + 1)
        .collect::<Vec<_>>();
        let result = FieldCT::multiply_many(&point_accs, coeffs, builder, driver)?
            .into_iter()
            .fold(
                FieldCT::from_witness(C::ScalarField::ZERO.into(), builder),
                |acc: FieldCT<_>, x| acc.add(&x, builder, driver),
            );
        Ok(result)
    }

    pub fn evaluate_with_domain_start<
        const SIZE: usize,
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
    >(
        evals: &[FieldCT<C::ScalarField>; SIZE],
        u: FieldCT<C::ScalarField>,
        domain_start: usize,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let mut full_numerator_value = one.clone();
        for i in domain_start..SIZE + domain_start {
            let coeff = FieldCT::from_witness(C::ScalarField::from(i as u64).into(), builder);
            let tmp = u.sub(&coeff, builder, driver);
            full_numerator_value = full_numerator_value.multiply(&tmp, builder, driver)?;
        }

        let big_domain = (domain_start..domain_start + SIZE)
            .map(|i| C::ScalarField::from(i as u64))
            .collect::<Vec<_>>();
        let lagrange_denominators = Barycentric::construct_lagrange_denominators(SIZE, &big_domain);

        let mut denominator_inverses = vec![FieldCT::default(); SIZE];
        let lhs = (0..SIZE)
            .map(|i| u.sub(&big_domain[i].into(), builder, driver))
            .collect::<Vec<_>>();
        let rhs = lagrange_denominators
            .iter()
            .map(|&x| FieldCT::from_witness(x.into(), builder))
            .collect::<Vec<_>>();
        let denominators = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        // TACEO TODO: batch invert
        for i in 0..SIZE {
            denominator_inverses[i] = one.divide(&denominators[i], builder, driver)?;
        }

        // Compute each term v_j / (d_j*(x-x_j)) of the sum
        let terms = FieldCT::multiply_many(&denominator_inverses, evals, builder, driver)?;
        let result = terms.into_iter().fold(
            FieldCT::from_witness(C::ScalarField::ZERO.into(), builder),
            |acc: FieldCT<_>, x| acc.add(&x, builder, driver),
        );
        // Scale the sum by the value of B(x)
        Ok(result.multiply(&full_numerator_value, builder, driver)?)
    }
}
