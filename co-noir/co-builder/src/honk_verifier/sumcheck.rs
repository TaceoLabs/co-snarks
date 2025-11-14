use crate::honk_verifier::verifier_relations::AllRelationsEvals;
use crate::honk_verifier::verifier_relations::NUM_SUBRELATIONS;
use crate::honk_verifier::verifier_relations::compute_full_relation_purported_value;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::transcript_ct::TranscriptCT;
use crate::transcript_ct::TranscriptHasherCT;
use crate::types::field_ct::FieldCT;
use crate::types::gate_separator::GateSeparatorPolynomial;
use ark_ff::Field;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::barycentric::Barycentric;
use co_noir_common::constants::BATCHED_RELATION_PARTIAL_LENGTH;
use co_noir_common::constants::NUM_ALL_ENTITIES;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::polynomials::entities::PRECOMPUTED_ENTITIES_SIZE;
use co_noir_common::types::RelationParameters;
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

pub struct SumcheckOutput<C: HonkCurve<TranscriptFieldType>> {
    pub(crate) challenges: Vec<FieldCT<C::ScalarField>>,
    pub(crate) claimed_evaluations: AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
    pub(crate) claimed_libra_evaluation: Option<FieldCT<C::ScalarField>>,
}

pub struct SumcheckVerifier;

impl SumcheckVerifier {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn verify<
        const SIZE: usize,
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        transcript: &mut TranscriptCT<C, H>,
        target_sum: &mut FieldCT<C::ScalarField>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        alphas: &[FieldCT<C::ScalarField>; NUM_SUBRELATIONS - 1],
        gate_challenges: &[FieldCT<C::ScalarField>],
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> HonkProofResult<SumcheckOutput<C>> {
        let one = FieldCT::from(C::ScalarField::ONE);

        let mut gate_separators =
            GateSeparatorPolynomial::new_without_products(gate_challenges.to_vec());

        let libra_challenge = if has_zk == ZeroKnowledge::Yes {
            // If running zero-knowledge sumcheck the target total sum is corrected by the claimed sum of libra masking
            // multivariate over the hypercube
            let libra_total_sum = transcript.receive_fr_from_prover("Libra:Sum".to_owned())?;
            let libra_challenge =
                transcript.get_challenge("Libra:Challenge".to_string(), builder, driver)?;
            *target_sum = libra_total_sum.multiply(&libra_challenge, builder, driver)?;
            Some(libra_challenge)
        } else {
            None
        };

        // MegaRecursiveFlavor does not have ZK
        let mut multivariate_challenge = Vec::with_capacity(padding_indicator_array.len());
        for (round_idx, padding_indicator) in padding_indicator_array.iter().enumerate() {
            let round_univariate = transcript
                .receive_n_from_prover(format!("Sumcheck:univariate_{round_idx}"), SIZE)?;

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
            let rhs = FieldCT::evaluate_with_domain_start::<{ SIZE }, _, _>(
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
        // Extract claimed evaluations of Libra univariates and compute their sum multiplied by the Libra challenge
        // Final round
        let transcript_evaluations = transcript
            .receive_n_from_prover("Sumcheck:evaluations".to_owned(), NUM_ALL_ENTITIES)?;

        let (precomputed, witness) = transcript_evaluations.split_at(PRECOMPUTED_ENTITIES_SIZE);
        let claimed_evaluations =
            AllEntities::from_elements(witness.to_vec(), precomputed.to_vec());

        // Evaluate the Honk relation at the point (u_0, ..., u_{d-1}) using claimed evaluations of prover polynomials.
        // In ZK Flavors, the evaluation is corrected by full_libra_purported_value
        let mut full_honk_purported_value = compute_full_relation_purported_value(
            &claimed_evaluations,
            &mut AllRelationsEvals::default(),
            relation_parameters,
            gate_separators,
            alphas,
            builder,
            driver,
        )?;

        // For ZK Flavors: compute the evaluation of the Row Disabling Polynomial at the sumcheck challenge and of the
        // libra univariate used to hide the contribution from the actual Honk relation
        let libra_evaluation = if has_zk == ZeroKnowledge::Yes {
            let libra_evaluation =
                transcript.receive_fr_from_prover("Libra:claimed_evaluation".to_owned())?;
            let tmp = libra_evaluation.multiply(
                &libra_challenge.expect("We have ZK"),
                builder,
                driver,
            )?;
            full_honk_purported_value = full_honk_purported_value.add(&tmp, builder, driver);
            Some(libra_evaluation)
        } else {
            None
        };

        // Final Verification Step
        full_honk_purported_value.assert_equal(target_sum, builder, driver);

        Ok(SumcheckOutput {
            challenges: multivariate_challenge,
            claimed_evaluations,
            claimed_libra_evaluation: libra_evaluation,
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
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        univariate: &[FieldCT<C::ScalarField>],
        target_sum: &FieldCT<C::ScalarField>,
        indicator: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let one = FieldCT::from(C::ScalarField::ONE);
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
}
