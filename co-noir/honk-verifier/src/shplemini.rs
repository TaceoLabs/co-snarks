use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::types::goblin_types::GoblinElement;
use co_builder::{
    flavours::mega_flavour::MegaFlavour,
    mega_builder::MegaCircuitBuilder,
    prover_flavour::ProverFlavour,
    transcript::{TranscriptCT, TranscriptHasherCT},
    types::field_ct::FieldCT,
};

use crate::claim_batcher::ClaimBatcher;
use ark_ff::AdditiveGroup;
use common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
pub struct BatchOpeningClaim<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) commitments: Vec<GoblinElement<C, T>>,
    pub(crate) scalars: Vec<FieldCT<C::ScalarField>>,
    pub(crate) evaluation_point: FieldCT<C::ScalarField>,
}

pub struct ShpleminiVerifier;

impl ShpleminiVerifier {
    pub fn compute_batch_opening_claim<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        claim_batcher: &mut ClaimBatcher<C, T>,
        multivariate_challenge: &[FieldCT<C::ScalarField>],
        g1_identity: &GoblinElement<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<BatchOpeningClaim<C, T>> {
        let virtual_log_n = multivariate_challenge.len();
        let mut batched_evaluation = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);

        // Get the challenge ρ to batch commitments to multilinear polynomials and their shifts
        let gemini_batching_challenge =
            transcript.get_challenge("rho".to_owned(), builder, driver)?;

        // Process Gemini transcript data:
        // - Get Gemini commitments (com(A₁), com(A₂), … , com(Aₙ₋₁))
        let fold_commitments = (0..virtual_log_n - 1)
            .map(|i| {
                transcript.receive_point_from_prover(
                    format!("Gemini:FOLD_{}", i + 1),
                    builder,
                    driver,
                )
            })
            .collect::<HonkProofResult<Vec<GoblinElement<C, T>>>>()?;

        // - Get Gemini evaluation challenge for Aᵢ, i = 0, … , d−1
        let gemini_evaluation_challenge =
            transcript.get_challenge("Gemini:r".to_string(), builder, driver)?;

        // - Get evaluations (A₀(−r), A₁(−r²), ... , Aₙ₋₁(−r²⁽ⁿ⁻¹⁾))1
        let gemini_fold_neg_evaluations = (1..=virtual_log_n)
            .map(|i| transcript.receive_fr_from_prover(format!("Gemini:a_{}", i + 1)))
            .collect::<HonkProofResult<Vec<FieldCT<C::ScalarField>>>>()?;

        // TACEO TODO: Interleaved claim batchers

        // - Compute vector (r, r², ... , r^{2^{d-1}}), where d = log_n
        let gemini_eval_challenge_powers =
            std::iter::successors(Some(gemini_evaluation_challenge.clone()), |last| {
                Some(
                    last.multiply(&last, builder, driver)
                        .expect("failed to compute squares of gemini evaluation challenge"),
                )
            })
            .take(virtual_log_n)
            .collect::<Vec<_>>();

        // TACEO TODO: HasZK case

        // Process Shplonk transcript data:
        // - Get Shplonk batching challenge
        let shplonk_batching_challenge =
            transcript.get_challenge("Shplonk:nu".to_string(), builder, driver)?;

        // Compute the powers of ν that are required for batching Gemini, SmallSubgroupIPA, and committed sumcheck
        // univariate opening claims.
        let shplonk_batching_challenge_powers = std::iter::successors(
            Some(FieldCT::from_witness(C::ScalarField::ONE.into(), builder)),
            |last| {
                Some(
                    last.multiply(&shplonk_batching_challenge, builder, driver)
                        .expect("failed to compute powers of shplonk batching challenge"),
                )
            },
        )
        .take(virtual_log_n)
        .collect::<Vec<_>>();

        // - Get the quotient commitment for the Shplonk batching of Gemini opening claims
        let Q_commitment =
            transcript.receive_point_from_prover("Shplonk:Q".to_string(), builder, driver)?;

        // Start populating the vector (Q, f₀, ... , fₖ₋₁, g₀, ... , gₘ₋₁, com(A₁), ... , com(A_{d-1}), [1]₁) where fᵢ
        // are the k commitments to unshifted polynomials and gⱼ are the m commitments to shifted polynomials
        let mut commitments = vec![Q_commitment];

        // Get Shplonk opening point z
        let shplonk_evaluation_challenge =
            transcript.get_challenge("Shplonk:z".to_string(), builder, driver)?;

        // Start computing the scalar to be multiplied by [1]₁
        let mut constant_term_accumulator =
            FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);

        // Initialize the vector of scalars placing the scalar 1 correposnding to Q_commitment
        let mut scalars = vec![constant_term_accumulator.clone()];

        // Compute 1/(z − r), 1/(z + r), 1/(z - r²),  1/(z + r²), … , 1/(z - r^{2^{d-1}}), 1/(z + r^{2^{d-1}})
        // These represent the denominators of the summand terms in Shplonk partially evaluated polynomial Q_z
        let inverse_vanishing_evals = ShpleminiVerifier::compute_inverted_gemini_denominators(
            &shplonk_evaluation_challenge,
            &gemini_eval_challenge_powers,
            builder,
            driver,
        )?;

        // Compute the additional factors to be multiplied with unshifted and shifted commitments when lazily
        // reconstructing the commitment of Q_z
        claim_batcher.compute_scalars_for_each_batch(
            &inverse_vanishing_evals,
            &shplonk_batching_challenge,
            &gemini_evaluation_challenge,
            builder,
            driver,
        )?;

        // TODO TACEO: HasZK case

        // TODO TACEO: ClaimBatcher interleaved case

        // Update the commitments and scalars vectors as well as the batched evaluation given the present batches
        claim_batcher.update_batch_mul_inputs_and_batched_evaluation(
            &mut commitments,
            &mut scalars,
            &mut batched_evaluation,
            &gemini_batching_challenge,
            &mut FieldCT::from_witness(C::ScalarField::ONE.into(), builder),
            builder,
            driver,
        )?;

        // Reconstruct Aᵢ(r²ⁱ) for i=0, ..., d - 1 from the batched evaluation of the multilinear polynomials and
        // Aᵢ(−r²ⁱ) for i = 0, ..., d - 1. In the case of interleaving, we compute A₀(r) as A₀₊(r) + P₊(r^s).
        let gemini_fold_pos_evaluations = Self::compute_fold_pos_evaluations(
            padding_indicator_array,
            &batched_evaluation,
            multivariate_challenge,
            &gemini_eval_challenge_powers,
            &gemini_fold_neg_evaluations,
            builder,
            driver,
        )?;

        // Place the commitments to Gemini fold polynomials Aᵢ in the vector of batch_mul commitments, compute the
        // contributions from Aᵢ(−r²ⁱ) for i=1, … , d − 1 to the constant term accumulator, add corresponding scalars
        // for the batch mul
        Self::batch_gemini_claims_received_from_prover(
            padding_indicator_array,
            &fold_commitments,
            &gemini_fold_neg_evaluations,
            &gemini_fold_pos_evaluations,
            &inverse_vanishing_evals,
            &shplonk_batching_challenge_powers,
            &mut commitments,
            &mut scalars,
            &mut constant_term_accumulator,
            builder,
            driver,
        )?;

        // Retrieve  the contribution without P₊(r^s)
        let a_0_pos = gemini_fold_pos_evaluations[0].clone();

        // Add contributions from A₀₊(r) and  A₀₋(-r) to constant_term_accumulator:
        //  Add  A₀₊(r)/(z−r) to the constant term accumulator
        constant_term_accumulator = a_0_pos
            .multiply(&inverse_vanishing_evals[0], builder, driver)?
            .add(&constant_term_accumulator, builder, driver);

        // Add  A₀₋(-r)/(z+r) to the constant term accumulator
        constant_term_accumulator = gemini_fold_neg_evaluations[0]
            .multiply(&shplonk_batching_challenge, builder, driver)?
            .multiply(&inverse_vanishing_evals[1], builder, driver)?
            .add(&constant_term_accumulator, builder, driver);

        Self::remove_repeated_commitments(&mut commitments, &mut scalars, builder, driver);

        // For ZK flavors, the sumcheck output contains the evaluations of Libra univariates that submitted to the
        // ShpleminiVerifier, otherwise this argument is set to be empty
        // TODO TACEO: HasZK case

        // Currently, only used in ECCVM
        // TACEO TODO: committed_sumcheck
        // if (committed_sumcheck) {
        //     batch_sumcheck_round_claims(commitments,
        //                                 scalars,
        //                                 constant_term_accumulator,
        //                                 multivariate_challenge,
        //                                 shplonk_batching_challenge_powers,
        //                                 shplonk_evaluation_challenge,
        //                                 sumcheck_round_commitments,
        //                                 sumcheck_round_evaluations);
        // }

        // Finalize the batch opening claim
        commitments.push(g1_identity.clone());
        scalars.push(constant_term_accumulator);

        return HonkProofResult::Ok(BatchOpeningClaim {
            commitments,
            scalars,
            evaluation_point: shplonk_evaluation_challenge,
        });
    }

    fn compute_inverted_gemini_denominators<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        shplonk_evaluation_challenge: &FieldCT<C::ScalarField>,
        gemini_eval_challenge_powers: &[FieldCT<C::ScalarField>],
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        let virtual_log_n = gemini_eval_challenge_powers.len();
        let num_gemini_claims = 2 * virtual_log_n;
        let mut denominators = Vec::with_capacity(num_gemini_claims);

        for gemini_eval_challenge_power in gemini_eval_challenge_powers.iter() {
            // Place 1/(z - r^{2^j})
            denominators.push(shplonk_evaluation_challenge.sub(
                gemini_eval_challenge_power,
                builder,
                driver,
            ));

            // Place 1/(z + r^{2^j})
            denominators.push(shplonk_evaluation_challenge.add(
                gemini_eval_challenge_power,
                builder,
                driver,
            ));
        }

        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

        // TACEO TODO: Batch invert
        for denom in denominators.iter_mut() {
            *denom = one.divide(denom, builder, driver)?;
        }

        Ok(denominators)
    }

    /**
     * @brief Compute \f$ A_0(r), A_1(r^2), \ldots, A_{d-1}(r^{2^{d-1}})\f$
     *
     * Recall that \f$ A_0(r) = \sum \rho^i \cdot f_i + \frac{1}{r} \cdot \sum \rho^{i+k} g_i \f$, where \f$
     * k \f$ is the number of "unshifted" commitments.
     *
     * @details Initialize `a_pos` = \f$ A_{d}(r) \f$ with the batched evaluation \f$ \sum \rho^i f_i(\vec{u}) + \sum
     * \rho^{i+k} g_i(\vec{u}) \f$. The verifier recovers \f$ A_{l-1}(r^{2^{l-1}}) \f$ from the "negative" value \f$
     * A_{l-1}\left(-r^{2^{l-1}}\right) \f$ received from the prover and the value \f$ A_{l}\left(r^{2^{l}}\right) \f$
     * computed at the previous step. Namely, the verifier computes
     * \f{align}{ A_{l-1}\left(r^{2^{l-1}}\right) =
     * \frac{2 \cdot r^{2^{l-1}} \cdot A_{l}\left(r^{2^l}\right) - A_{l-1}\left( -r^{2^{l-1}} \right)\cdot
     * \left(r^{2^{l-1}} (1-u_{l-1}) - u_{l-1}\right)} {r^{2^{l-1}} (1- u_{l-1}) + u_{l-1}}. \f}
     *
     * In the case of interleaving, the first "negative" evaluation has to be corrected by the contribution from \f$
     * P_{-}(-r^s)\f$, where \f$ s \f$ is the size of the group to be interleaved.
     *
     * This method uses `padding_indicator_array`, whose i-th entry is FF{1} if i < log_n and 0 otherwise.
     * We use these entries to either assign `eval_pos_prev` the value `eval_pos` computed in the current iteration of
     * the loop, or to propagate the batched evaluation of the multilinear polynomials to the next iteration. This
     * ensures the correctnes of the computation of the required positive evaluations.
     *
     * To ensure that dummy evaluations cannot be used to tamper with the final batch_mul result, we multiply dummy
     * positive evaluations by the entries of `padding_indicator_array`.
     *
     * @param padding_indicator_array An array with first log_n entries equal to 1, and the remaining entries are 0.
     * @param batched_evaluation The evaluation of the batched polynomial at \f$ (u_0, \ldots, u_{d-1})\f$.
     * @param evaluation_point Evaluation point \f$ (u_0, \ldots, u_{d-1}) \f$ padded to CONST_PROOF_SIZE_LOG_N.
     * @param challenge_powers Powers of \f$ r \f$, \f$ r^2 \), ..., \( r^{2^{d-1}} \f$.
     * @param fold_neg_evals  Evaluations \f$ A_{i-1}(-r^{2^{i-1}}) \f$.
     * @return \f A_{i}}(r^{2^{i}})\f$ \f$ i = 0, \ldots, \text{virtual_log_n} - 1 \f$.
     */
    fn compute_fold_pos_evaluations<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        batched_evaluation: &FieldCT<C::ScalarField>,
        evaluation_point: &[FieldCT<C::ScalarField>],
        challenge_powers: &[FieldCT<C::ScalarField>],
        fold_neg_evals: &[FieldCT<C::ScalarField>],
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        let virtual_log_n = evaluation_point.len();
        let mut evals = fold_neg_evals.to_vec();
        let mut eval_pos_prev = batched_evaluation.clone();
        let zero = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

        let mut fold_pos_evaluations = Vec::with_capacity(virtual_log_n);

        // Add the contribution of P-((-r)ˢ) to get A_0(-r), which is 0 if there are no interleaved polynomials
        evals[0] = zero.clone();

        // Solve the sequence of linear equations
        for l in (1..=virtual_log_n).rev() {
            // Get r²⁽ˡ⁻¹⁾
            let challenge_power = challenge_powers[l - 1].clone();

            // Get uₗ₋₁
            let u = evaluation_point[l - 1].clone();
            let eval_neg = evals[l - 1].clone();

            let one_minus_u = one.sub(&u, builder, driver);

            // Get A₍ₗ₋₁₎(−r²⁽ˡ⁻¹⁾)
            // Compute the numerator
            let lhs = challenge_power
                .multiply(&eval_pos_prev, builder, driver)?
                .multiply(
                    &FieldCT::from_witness((C::ScalarField::from(2u64)).into(), builder),
                    builder,
                    driver,
                )?;
            let rhs = &challenge_power
                .multiply(&one_minus_u, builder, driver)?
                .sub(&u, builder, driver)
                .multiply(&eval_neg, builder, driver)?;
            let mut eval_pos = lhs.sub(&rhs, builder, driver);

            // Divide by the denominator
            eval_pos = one
                .divide(
                    &challenge_power
                        .multiply(&one_minus_u, builder, driver)?
                        .add(&u, builder, driver),
                    builder,
                    driver,
                )?
                .multiply(&eval_pos, builder, driver)?;

            // If current index is bigger than log_n, we propagate `batched_evaluation` to the next
            // round.  Otherwise, current `eval_pos` A₍ₗ₋₁₎(−r²⁽ˡ⁻¹⁾) becomes `eval_pos_prev` in the round l-2.
            let lhs = padding_indicator_array[l - 1].multiply(&eval_pos, builder, driver)?;
            let rhs = one
                .sub(&padding_indicator_array[l - 1], builder, driver)
                .multiply(&eval_pos_prev, builder, driver)?;
            eval_pos_prev = lhs.add(&rhs, builder, driver);

            // If current index is bigger than log_n, we emplace 0, which is later multiplied against
            // Commitment::one().
            fold_pos_evaluations.push(padding_indicator_array[l - 1].multiply(
                &eval_pos_prev,
                builder,
                driver,
            )?);
        }

        fold_pos_evaluations.reverse();
        Ok(fold_pos_evaluations)
    }

    /**
     * @brief Place fold polynomial commitments to `commitments` and compute the corresponding scalar multipliers.
     *
     * @details Once the commitments to Gemini "fold" polynomials \f$ A_i \f$ and their negative evaluations, i.e. \f$
     * A_i(-r^{2^i}) \f$, for \f$ i = 1, \ldots, d - 1 \f$, are obtained, and the verifier has reconstructed the
     * positive fold evaluation \f$ A_i(r^{2^i}) \f$ for \f$ i=1, \ldots, d- 1 \f$, it performs the following
     * operations:
     *
     * 1. Moves the vector
     * \f[
     * \left( \text{com}(A_1), \text{com}(A_2), \ldots, \text{com}(A_{d-1}) \right)
     * \f]
     * to the 'commitments' vector.
     *
     * 2. Computes the scalars
     * \f{align}{
     * \frac{\nu^2}{z - r^2} + \frac{\nu^3}{z + r^2},
     * \frac{\nu^4}{z - r^4} + \frac{\nu^5}{z + r^4},
     * \ldots,
     * \frac{\nu^{2 \cdot d} } {z - r^{2^{d-1}}} + \frac{\nu^{2 \cdot d + 1}}{z + r^{2^{d-1}}} \f}
     * and multiplies them against the entries of `padding_indicator_array`. The commitments \f$ [A_1]_1, \ldots,
     * [A_{d-1}]_1 \f$ are multiplied by these scalars in the final `batch_mul` perfomed by KZG or IPA. Since
     * `padding_indicator_array[i]` = 1 for i < log_n, and 0 otherwise, it ensures that the contributions from "dummy"
     * rounds do not affect the final `batch mul`.
     *
     * 3. Accumulates the summands of the constant term:
     * \f{align}{
     * \frac{\nu^{2 i} \cdot A_i\left(r^{2^i} \right)}{z - r^{2^i}} + \frac{\nu^{2 \cdot i+1} \cdot
     * A_i\left(-r^{2^i}\right)}{z+ r^{2^i}} \f} for \f$ i = 1, \ldots, d-1 \f$ and adds them to the
     * 'constant_term_accumulator'.
     *
     * @param padding_indicator_array An array with first log_n entries equal to 1, and the remaining entries are 0.
     * @param fold_commitments A vector containing the commitments to the Gemini fold polynomials \f$ A_i \f$.
     * @param gemini_neg_evaluations The evaluations of Gemini fold polynomials \f$ A_i \f$ at \f$ -r^{2^i} \f$ for \f$
     * i = 0, \ldots, d - 1 \f$.
     * @param gemini_pos_evaluations The evaluations of Gemini fold polynomials \f$ A_i \f$ at \f$ r^{2^i} \f$ for \f$
     * i = 0, \ldots, d - 1 \f$
     * @param inverse_vanishing_evals \f$ 1/(z − r), 1/(z + r), 1/(z - r^2),  1/(z + r^2), \ldots, 1/(z - r^{2^{d-1}}),
     * 1/(z + r^{2^{-1}}) \f$
     * @param shplonk_batching_challenge_powers A vector of powers of \f$ \nu \f$ used to batch all univariate claims.
     * @param commitments Output vector where the commitments to the Gemini fold polynomials will be stored.
     * @param scalars Output vector where the computed scalars will be stored.
     * @param constant_term_accumulator The accumulator for the summands of the Shplonk constant term.
     */
    fn batch_gemini_claims_received_from_prover<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        fold_commitments: &Vec<GoblinElement<C, T>>,
        gemini_neg_evaluations: &[FieldCT<C::ScalarField>],
        gemini_pos_evaluations: &[FieldCT<C::ScalarField>],
        inverse_vanishing_evals: &[FieldCT<C::ScalarField>],
        shplonk_batching_challenge_powers: &[FieldCT<C::ScalarField>],
        commitments: &mut Vec<GoblinElement<C, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        constant_term_accumulator: &mut FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let virtual_log_n = gemini_neg_evaluations.len();

        // Start from 1, because the commitment to A_0 is reconstructed from the commitments to the multilinear
        // polynomials. The corresponding evaluations are also handled separately.
        for j in 1..virtual_log_n {
            // The index of 1/ (z - r^{2^{j}}) in the vector of inverted Gemini denominators
            let pos_index = 2 * j;
            // The index of 1/ (z + r^{2^{j}}) in the vector of inverted Gemini denominators
            let neg_index = 2 * j + 1;

            // Compute the "positive" scaling factor  (ν^{2j}) / (z - r^{2^{j}})
            let scaling_factor_pos = shplonk_batching_challenge_powers[pos_index].multiply(
                &inverse_vanishing_evals[pos_index],
                builder,
                driver,
            )?;
            // Compute the "negative" scaling factor  (ν^{2j+1}) / (z + r^{2^{j}})
            let scaling_factor_neg = shplonk_batching_challenge_powers[neg_index].multiply(
                &inverse_vanishing_evals[neg_index],
                builder,
                driver,
            )?;

            // Accumulate the const term contribution given by
            // v^{2j} * A_j(r^{2^j}) /(z - r^{2^j}) + v^{2j+1} * A_j(-r^{2^j}) /(z+ r^{2^j})
            let tmp = FieldCT::multiply_many(
                &[scaling_factor_neg.clone(), scaling_factor_pos.clone()],
                &[
                    gemini_neg_evaluations[j].clone(),
                    gemini_pos_evaluations[j].clone(),
                ],
                builder,
                driver,
            )?;
            *constant_term_accumulator = constant_term_accumulator
                .add(&tmp[0], builder, driver)
                .add(&tmp[1], builder, driver);

            // Place the scaling factor to the 'scalars' vector
            let tmp = padding_indicator_array[j].neg().multiply(
                &scaling_factor_pos.add(&scaling_factor_neg, builder, driver),
                builder,
                driver,
            )?;
            scalars.push(tmp);

            // Move com(Aᵢ) to the 'commitments' vector
            commitments.push(fold_commitments[j - 1].clone());
        }

        HonkProofResult::Ok(())
    }

    /**
     * @brief Combines scalars of repeating commitments to reduce the number of scalar multiplications performed by the
     * verifier.
     *
     * @details The Shplemini verifier gets the access to multiple groups of commitments, some of which are duplicated
     * because they correspond to polynomials whose shifts also evaluated or used in concatenation groups in
     * Translator. This method combines the scalars associated with these repeating commitments, reducing the total
     * number of scalar multiplications required during the verification.
     *
     * More specifically, the Shplemini verifier receives two or three groups of commitments: get_unshifted() and
     * get_to_be_shifted() in the case of Ultra, Mega, and ECCVM Flavors; and get_unshifted_without_interleaved(),
     * get_to_be_shifted(), and get_groups_to_be_interleaved() in the case of the TranslatorFlavor. The commitments are
     * then placed in this specific order in a BatchOpeningClaim object containing a vector of commitments and a vector
     * of scalars. The ranges with repeated commitments belong to the Flavors. This method iterates over these ranges
     * and sums the scalar multipliers corresponding to the same group element. After combining the scalars, we erase
     * corresponding entries in both vectors.
     *
     */
    // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1151) Avoid erasing vector elements.
    fn remove_repeated_commitments<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        commitments: &mut Vec<GoblinElement<C, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) {
        // We started populating commitments and scalars by adding Shplonk:Q commitmment and the corresponding scalar
        // factor 1. In the case of ZK, we also added Gemini:masking_poly_comm before populating the vector with
        // commitments to prover polynomials
        // TACEO TODO: Handle ZK case
        let offset = 1;

        // Extract the indices from the container, which is normally created in a given Flavor
        let first_range_to_be_shifted_start = MegaFlavour::PRECOMPUTED_ENTITIES_SIZE + offset;
        let first_range_shifted_start =
            MegaFlavour::PRECOMPUTED_ENTITIES_SIZE + MegaFlavour::WITNESS_ENTITIES_SIZE + offset;
        let first_range_size = MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE;

        let second_range_to_be_shifted_start = offset;
        let second_range_shifted_start = offset;
        let second_range_size = 0;

        // Iterate over the first range of to-be-shifted scalars and their shifted counterparts
        for i in 0..first_range_size {
            let idx_to_be_shifted = i + first_range_to_be_shifted_start;
            let idx_shifted = i + first_range_shifted_start;
            scalars[idx_to_be_shifted] =
                scalars[idx_to_be_shifted].add(&scalars[idx_shifted], builder, driver);
        }

        // Iterate over the second range of to-be-shifted precomputed scalars and their shifted counterparts (if
        // provided)
        for i in 0..second_range_size {
            let idx_to_be_shifted = i + second_range_to_be_shifted_start;
            let idx_shifted = i + second_range_shifted_start;
            scalars[idx_to_be_shifted] =
                scalars[idx_to_be_shifted].add(&scalars[idx_shifted], builder, driver);
        }

        // Only `else` case since `second_range_shifted_start` is less than `first_range_shifted_start`
        // Erase the shifted scalars and commitments from the first range
        for _ in 0..first_range_size {
            scalars.remove(first_range_shifted_start);
            commitments.remove(first_range_shifted_start);
        }
        // Erase the shifted scalars and commitments from the second range (if provided)
        for _ in 0..second_range_size {
            scalars.remove(second_range_shifted_start);
            commitments.remove(second_range_shifted_start);
        }
    }
}
