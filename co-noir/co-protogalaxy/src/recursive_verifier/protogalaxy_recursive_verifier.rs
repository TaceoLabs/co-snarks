use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::Zero;
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

        let mut output_commitments = Vec::new();
        let lhs_scalar = one
            .sub(&combiner_challenge, builder, driver)
            .get_value(builder, driver);
        let rhs_scalar = combiner_challenge.get_value(builder, driver);

        for (i, (accumulator_commitment, instance_commitment)) in
            izip!(accumulator_commitments.iter(), instance_commitments.iter()).enumerate()
        {
            let lhs = accumulator_commitment.get_value(builder, driver);
            let rhs = instance_commitment.get_value(builder, driver);

            let lhs_scaled = driver.scale_native_point(lhs, lhs_scalar)?;
            let rhs_scaled = driver.scale_native_point(rhs, rhs_scalar)?;

            let output = driver.add_native_points(lhs_scaled, rhs_scaled);
            let output_commitment = GoblinElement::from_witness(output, builder, driver)?;

            output_commitments.push(output_commitment.clone());

            // Add the output commitment to the transcript to ensure that they can't be spoofed
            transcript.add_point_to_hash_buffer(
                format!("new_accumulator_commitment_{i}"),
                &output_commitment,
            );
        }

        let labels = (0..NUM_FOLDED_ENTITIES)
            .map(|i| format!("accumulator_combination_challenges_{i}"))
            .collect_vec();
        let scalars = transcript.get_challenges(&labels, builder, driver)?;

        let accumulator_sum =
            GoblinElement::batch_mul(&accumulator_commitments, &scalars, builder, driver)?;

        let instance_sum =
            GoblinElement::batch_mul(&instance_commitments, &scalars, builder, driver)?;

        let output_sum = GoblinElement::batch_mul(&output_commitments, &scalars, builder, driver)?;

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
        accumulator.target_sum = lagranges[0]
            .multiply(&perturbator_evaluation, builder, driver)?
            .add(
                &vanishing_polynomial_at_challenge.multiply(
                    &combiner_quotient_at_challenge,
                    builder,
                    driver,
                )?,
                builder,
                driver,
            );

        // Update gate challenges
        accumulator
            .gate_challenges
            .iter_mut()
            .zip(deltas)
            .for_each(|(c, delta)| {
                let tmp = perturbator_challenge
                    .multiply(&delta, builder, driver)
                    .expect("Failed to multiply perturbator challenge and delta");
                *c = c.add(&tmp, builder, driver);
            });

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

        // Update alphas
        izip!(accumulator.alphas.iter_mut(), key_to_fold.alphas.iter()).for_each(
            |(acc_alpha, alpha_2)| {
                let a = acc_alpha
                    .clone()
                    .multiply(&lagranges[0], builder, driver)
                    .expect("Failed to multiply acc_alpha and lagrange[0]");
                let b = alpha_2
                    .clone()
                    .multiply(&lagranges[1], builder, driver)
                    .expect("Failed to multiply alpha_2 and lagrange[1]");
                *acc_alpha = a.add(&b, builder, driver);
            },
        );

        // Update relation parameters
        izip!(
            accumulator.relation_parameters.get_params_as_mut(),
            key_to_fold.relation_parameters.get_params().into_iter()
        )
        .for_each(|(acc_param, param_2)| {
            let a = acc_param
                .multiply(&lagranges[0], builder, driver)
                .expect("Failed to multiply acc_param and lagrange[0]");
            let b = param_2
                .multiply(&lagranges[1], builder, driver)
                .expect("Failed to multiply param_2 and lagrange[1]");
            *acc_param = a.add(&b, builder, driver);
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
        let mut point_acc = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let mut result = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
        for coeff in coeffs.iter().take(CONST_PG_LOG_N + 1) {
            result = coeff.madd(&point_acc, &result, builder, driver)?;
            point_acc = point_acc.multiply(point, builder, driver)?;
        }

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
        for i in 0..SIZE {
            let mut inv = FieldCT::from_witness(lagrange_denominators[i].into(), builder);
            let tmp = u.sub(&big_domain[i].into(), builder, driver);
            inv = inv.multiply(&tmp, builder, driver)?;
            inv = one.divide(&inv, builder, driver)?;
            denominator_inverses[i] = inv;
        }

        let mut result = FieldCT::from_witness(C::ScalarField::zero().into(), builder);
        // Compute each term v_j / (d_j*(x-x_j)) of the sum
        for (i, inverse) in denominator_inverses.iter().enumerate() {
            let mut term = evals[i].clone();
            term = term.multiply(inverse, builder, driver)?;
            result = result.add(&term, builder, driver);
        }

        // Scale the sum by the value of B(x)
        Ok(result.multiply(&full_numerator_value, builder, driver)?)
    }
}
