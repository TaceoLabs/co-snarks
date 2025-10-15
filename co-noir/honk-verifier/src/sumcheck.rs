use crate::verifier_relations::AllRelationsEvals;
use crate::verifier_relations::compute_full_relation_purported_value;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::types::gate_separator::GateSeparatorPolynomial;
use co_builder::{
    flavours::mega_flavour::MegaFlavour,
    mega_builder::MegaCircuitBuilder,
    prover_flavour::ProverFlavour,
    transcript::{TranscriptCT, TranscriptHasherCT},
    types::field_ct::FieldCT,
};
use co_noir_common::barycentric::Barycentric;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::types::AllEntities;
use ultrahonk::CONST_PROOF_SIZE_LOG_N;

pub struct SumcheckOutput<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> {
    pub challenges: Vec<FieldCT<C::ScalarField>>,
    pub claimed_evaluations:
        AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
}

pub struct SumcheckVerifier;

impl SumcheckVerifier {
    #[expect(clippy::too_many_arguments)]
    pub fn verify<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        transcript: &mut TranscriptCT<C, H>,
        target_sum: &mut FieldCT<C::ScalarField>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        alphas: &Vec<FieldCT<C::ScalarField>>,
        gate_challenges: &mut Vec<FieldCT<C::ScalarField>>,
        padding_indicator_array: &Vec<FieldCT<C::ScalarField>>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<SumcheckOutput<C>> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

        Self::pad_gate_challenges::<C, T>(gate_challenges, builder);

        let mut gate_separators =
            GateSeparatorPolynomial::new_without_products(gate_challenges.clone(), builder);

        // MegaRecursiveFlavor does not have ZK
        let mut multivariate_challenge = Vec::with_capacity(padding_indicator_array.len());
        for (round_idx, padding_indicator) in padding_indicator_array.iter().enumerate() {
            let round_univariate = transcript.receive_n_from_prover(
                format!("Sumcheck:univariate_{round_idx}"),
                MegaFlavour::BATCHED_RELATION_PARTIAL_LENGTH,
            )?;

            let round_challenge =
                transcript.get_challenge(format!("Sumcheck:u_{round_idx}"), builder, driver)?;

            multivariate_challenge.push(round_challenge.clone());

            SumcheckVerifier::check_sum(
                &round_univariate,
                target_sum,
                padding_indicator,
                builder,
                driver,
            )?;

            // Update the target sum for the next round
            let lhs = one
                .sub(padding_indicator, builder, driver)
                .multiply(target_sum, builder, driver)?;
            let rhs = evaluate_with_domain_start::<
                { MegaFlavour::BATCHED_RELATION_PARTIAL_LENGTH },
                _,
                _,
            >(
                &round_univariate.try_into().unwrap(),
                &round_challenge,
                0,
                builder,
                driver,
            )?
            .multiply(padding_indicator, builder, driver)?;
            *target_sum = lhs.add(&rhs, builder, driver);

            // Partially evaluate the gate separator polynomial
            gate_separators.partially_evaluate_with_padding(
                &round_challenge,
                padding_indicator,
                builder,
                driver,
            )?;
        }

        let transcript_evaluations = transcript.receive_n_from_prover(
            "Sumcheck:evaluations".to_owned(),
            MegaFlavour::NUM_ALL_ENTITIES,
        )?;

        // For ZK Flavors: the evaluation of the Row Disabling Polynomial at the sumcheck challenge
        // Evaluate the Honk relation at the point (u_0, ..., u_{d-1}) using claimed evaluations of prover polynomials.
        // In ZK Flavors, the evaluation is corrected by full_libra_purported_value
        let (precomputed, witness) =
            transcript_evaluations.split_at(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
        let claimed_evaluations =
            AllEntities::from_elements(witness.to_vec(), precomputed.to_vec());

        let full_honk_purported_value = compute_full_relation_purported_value(
            &claimed_evaluations,
            &mut AllRelationsEvals::default(),
            relation_parameters,
            gate_separators,
            alphas,
            builder,
            driver,
        )?;

        // Final Verification Step
        full_honk_purported_value.assert_equal(target_sum, builder, driver);

        Ok(SumcheckOutput {
            challenges: multivariate_challenge,
            claimed_evaluations,
        })
    }

    /**
     * @brief Check that the round target sum is correct
     * @details The verifier receives the claimed evaluations of the round univariate \f$ \tilde{S}^i \f$ at \f$X_i =
     * 0,\ldots, D \f$ and checks \f$\sigma_i = \tilde{S}^{i-1}(u_{i-1}) \stackrel{?}{=} \tilde{S}^i(0) + \tilde{S}^i(1)
     * \f$
     * @param univariate Round univariate \f$\tilde{S}^{i}\f$ represented by its evaluations over \f$0,\ldots,D\f$.
     *
     */
    fn check_sum<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        univariate: &[FieldCT<C::ScalarField>],
        target_sum: &FieldCT<C::ScalarField>,
        indicator: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let lhs = [
            one.sub(indicator, builder, driver),
            univariate[0].add(&univariate[1], builder, driver),
        ];
        let rhs = [target_sum.clone(), indicator.clone()];

        let [lhs, rhs] = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?
            .try_into()
            .expect("We provided 2 elements");

        let total_sum = lhs.add(&rhs, builder, driver);

        target_sum.assert_equal(&total_sum, builder, driver);
        Ok(())
    }

    fn pad_gate_challenges<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        gate_challenges: &mut Vec<FieldCT<C::ScalarField>>,
        builder: &mut MegaCircuitBuilder<C, T>,
    ) {
        if gate_challenges.len() < CONST_PROOF_SIZE_LOG_N {
            let zero = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
            for _ in gate_challenges.len()..CONST_PROOF_SIZE_LOG_N {
                gate_challenges.push(zero.clone());
            }
        }
    }
}

pub fn evaluate_with_domain_start<
    const SIZE: usize,
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
>(
    evals: &[FieldCT<C::ScalarField>; SIZE],
    u: &FieldCT<C::ScalarField>,
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
        .map(|i| FieldCT::from_witness(lagrange_denominators[i].into(), builder))
        .collect::<Vec<_>>();
    let rhs = (0..SIZE)
        .map(|i| u.sub(&big_domain[i].into(), builder, driver))
        .collect::<Vec<_>>();

    let denominators = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;
    for i in 0..SIZE {
        denominator_inverses[i] = one.divide(&denominators[i], builder, driver)?;
    }

    // Compute each term v_j / (d_j*(x-x_j)) of the sum
    let result = FieldCT::multiply_many(evals, &denominator_inverses, builder, driver)?
        .iter()
        .fold(
            FieldCT::from_witness(C::ScalarField::zero().into(), builder),
            |acc, x| acc.add(x, builder, driver),
        );

    // Scale the sum by the value of B(x)
    Ok(result.multiply(&full_numerator_value, builder, driver)?)
}
