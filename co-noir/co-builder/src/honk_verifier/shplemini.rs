use std::{array, vec};

use crate::{
    honk_verifier::claim_batcher::ClaimBatcher,
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptHasherCT},
    types::{big_group::BigGroup, field_ct::FieldCT},
};
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    constants::{NUM_INTERLEAVING_CLAIMS, NUM_LIBRA_COMMITMENTS},
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    polynomials::entities::WITNESS_ENTITIES_SIZE,
};
use co_noir_common::{
    constants::{NUM_SMALL_IPA_EVALUATIONS, SHIFTED_WITNESS_ENTITIES_SIZE},
    polynomials::entities::PRECOMPUTED_ENTITIES_SIZE,
    types::ZeroKnowledge,
};
pub struct BatchOpeningClaim<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) commitments: Vec<BigGroup<C::ScalarField, T>>,
    pub(crate) scalars: Vec<FieldCT<C::ScalarField>>,
    pub(crate) evaluation_point: FieldCT<C::ScalarField>,
}

pub struct ShpleminiVerifier;

impl ShpleminiVerifier {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_batch_opening_claim<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        claim_batcher: &mut ClaimBatcher<C, T>,
        multivariate_challenge: &[FieldCT<C::ScalarField>],
        g1_identity: &BigGroup<C::ScalarField, T>,
        transcript: &mut TranscriptCT<C, H>,
        consistency_checked: &mut bool,
        libra_commitments: Option<&[BigGroup<C::ScalarField, T>; NUM_LIBRA_COMMITMENTS]>,
        libra_univariate_evaluation: Option<&FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<BatchOpeningClaim<C, T>> {
        let has_zk = ZeroKnowledge::from(libra_commitments.is_some());
        let virtual_log_n = multivariate_challenge.len();
        let mut batched_evaluation = FieldCT::from(C::ScalarField::ZERO);

        let mut hiding_polynomial_commitment = BigGroup::default();
        if has_zk == ZeroKnowledge::Yes {
            hiding_polynomial_commitment = transcript.receive_point_from_prover(
                "Gemini:masking_poly_comm".to_string(),
                builder,
                driver,
            )?;
            batched_evaluation =
                transcript.receive_fr_from_prover("Gemini:masking_poly_eval".to_owned())?;
        }

        // Get the challenge ρ to batch commitments to multilinear polynomials and their shifts
        let gemini_batching_challenge =
            transcript.get_challenge("rho".to_owned(), builder, driver)?;

        // Process Gemini transcript data:
        // - Get Gemini commitments (com(A₁), com(A₂), … , com(Aₙ₋₁))
        // TACEO TODO: batch `is_zero` calls on `receive_point_from_prover``
        let fold_commitments = (0..virtual_log_n - 1)
            .map(|i| {
                transcript.receive_point_from_prover(
                    format!("Gemini:FOLD_{}", i + 1),
                    builder,
                    driver,
                )
            })
            .collect::<HonkProofResult<Vec<_>>>()?;

        // - Get Gemini evaluation challenge for Aᵢ, i = 0, … , d−1
        let gemini_evaluation_challenge =
            transcript.get_challenge("Gemini:r".to_string(), builder, driver)?;

        // - Get evaluations (A₀(−r), A₁(−r²), ... , Aₙ₋₁(−r²⁽ⁿ⁻¹⁾))1
        let gemini_fold_neg_evaluations = (1..=virtual_log_n)
            .map(|i| transcript.receive_fr_from_prover(format!("Gemini:a_{}", i + 1)))
            .collect::<HonkProofResult<Vec<_>>>()?;

        // - Compute vector (r, r², ... , r^{2^{d-1}}), where d = log_n
        let mut gemini_eval_challenge_powers = vec![gemini_evaluation_challenge.clone()];
        for i in 1..virtual_log_n {
            gemini_eval_challenge_powers.push(
                gemini_eval_challenge_powers[i - 1]
                    .multiply(&gemini_eval_challenge_powers[i - 1], builder, driver)
                    .expect("failed to compute squares of gemini evaluation challenge"),
            );
        }

        let mut libra_evaluations: [FieldCT<C::ScalarField>; NUM_SMALL_IPA_EVALUATIONS] =
            array::from_fn(|_| FieldCT::default());
        if has_zk == ZeroKnowledge::Yes {
            libra_evaluations[0] =
                transcript.receive_fr_from_prover("Libra:concatenation_eval".to_string())?;
            libra_evaluations[1] =
                transcript.receive_fr_from_prover("Libra:shifted_grand_sum_eval".to_string())?;
            libra_evaluations[2] =
                transcript.receive_fr_from_prover("Libra:grand_sum_eval".to_string())?;
            libra_evaluations[3] =
                transcript.receive_fr_from_prover("Libra:quotient_eval".to_string())?;
        }

        // Process Shplonk transcript data:
        // - Get Shplonk batching challenge
        let shplonk_batching_challenge =
            transcript.get_challenge("Shplonk:nu".to_string(), builder, driver)?;

        // Compute the powers of ν that are required for batching Gemini, SmallSubgroupIPA, and committed sumcheck
        // univariate opening claims.
        let shplonk_batching_challenge_powers = Self::compute_shplonk_batching_challenge_powers(
            &shplonk_batching_challenge,
            virtual_log_n,
            has_zk == ZeroKnowledge::Yes,
            // TODO CESAR / TODO FLORIN
            false,
            builder,
            driver,
        )?;

        // - Get the quotient commitment for the Shplonk batching of Gemini opening claims
        let q_commitment =
            transcript.receive_point_from_prover("Shplonk:Q".to_string(), builder, driver)?;

        // Start populating the vector (Q, f₀, ... , fₖ₋₁, g₀, ... , gₘ₋₁, com(A₁), ... , com(A_{d-1}), [1]₁) where fᵢ
        // are the k commitments to unshifted polynomials and gⱼ are the m commitments to shifted polynomials
        let mut commitments = vec![q_commitment];

        // Get Shplonk opening point z
        let shplonk_evaluation_challenge =
            transcript.get_challenge("Shplonk:z".to_string(), builder, driver)?;

        // Start computing the scalar to be multiplied by [1]₁
        let mut constant_term_accumulator = FieldCT::from(C::ScalarField::ZERO);

        let mut scalars = vec![FieldCT::from(C::ScalarField::ONE)];

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

        if has_zk == ZeroKnowledge::Yes {
            commitments.push(hiding_polynomial_commitment);
            scalars.push(claim_batcher.get_unshifted_batch_scalar().neg()); // corresponds to ρ⁰
        }

        // Place the commitments to prover polynomials in the commitments vector. Compute the evaluation of the
        // batched multilinear polynomial. Populate the vector of scalars for the final batch mul

        let mut gemini_batching_challenge_power = FieldCT::from(C::ScalarField::ONE);
        if has_zk == ZeroKnowledge::Yes {
            // ρ⁰ is used to batch the hiding polynomial which has already been added to the commitments vector
            gemini_batching_challenge_power = gemini_batching_challenge_power.multiply(
                &gemini_batching_challenge,
                builder,
                driver,
            )?;
        }

        // Update the commitments and scalars vectors as well as the batched evaluation given the present batches
        claim_batcher.update_batch_mul_inputs_and_batched_evaluation(
            &mut commitments,
            &mut scalars,
            &mut batched_evaluation,
            &gemini_batching_challenge,
            &mut gemini_batching_challenge_power,
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
        constant_term_accumulator.add_assign(
            &a_0_pos.multiply(&inverse_vanishing_evals[0], builder, driver)?,
            builder,
            driver,
        );

        // Add  A₀₋(-r)/(z+r) to the constant term accumulator
        constant_term_accumulator.add_assign(
            &gemini_fold_neg_evaluations[0]
                .multiply(&shplonk_batching_challenge, builder, driver)?
                .multiply(&inverse_vanishing_evals[1], builder, driver)?,
            builder,
            driver,
        );

        Self::remove_repeated_commitments(&mut commitments, &mut scalars, builder, driver);

        // For ZK flavors, the sumcheck output contains the evaluations of Libra univariates that submitted to the
        // ShpleminiVerifier, otherwise this argument is set to be empty
        if has_zk == ZeroKnowledge::Yes {
            Self::add_zk_data(
                virtual_log_n,
                &mut commitments,
                &mut scalars,
                &mut constant_term_accumulator,
                libra_commitments.expect("We have ZK"),
                &libra_evaluations,
                &gemini_evaluation_challenge,
                &shplonk_batching_challenge_powers,
                &shplonk_evaluation_challenge,
                builder,
                driver,
            )?;

            *consistency_checked = Self::check_libra_evaluations_consistency(
                &libra_evaluations,
                &gemini_evaluation_challenge,
                multivariate_challenge,
                libra_univariate_evaluation.expect("We have ZK"),
                builder,
                driver,
            )?;
        }

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

        HonkProofResult::Ok(BatchOpeningClaim {
            commitments,
            scalars,
            evaluation_point: shplonk_evaluation_challenge,
        })
    }

    fn compute_inverted_gemini_denominators<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        shplonk_evaluation_challenge: &FieldCT<C::ScalarField>,
        gemini_eval_challenge_powers: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
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

        let one = FieldCT::from(C::ScalarField::ONE);

        // TACEO TODO: Batch invert / no zero check
        for denom in denominators.iter_mut() {
            *denom = one.divide_no_zero_check(denom, builder, driver)?;
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
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        batched_evaluation: &FieldCT<C::ScalarField>,
        evaluation_point: &[FieldCT<C::ScalarField>],
        challenge_powers: &[FieldCT<C::ScalarField>],
        fold_neg_evals: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        let virtual_log_n = evaluation_point.len();
        let evals = fold_neg_evals.to_vec();
        let mut eval_pos_prev = batched_evaluation.clone();
        let one = FieldCT::from(C::ScalarField::ONE);
        // TODO CESAR: But why?
        let mut zero = FieldCT::from(C::ScalarField::ZERO);
        zero.convert_constant_to_fixed_witness(builder, driver);

        let mut fold_pos_evaluations = Vec::with_capacity(virtual_log_n);

        // Add the contribution of P-((-r)ˢ) to get A_0(-r), which is 0 if there are no interleaved polynomials
        // evals[0] += p_neg

        // TODO CESAR / TODO FLORIN: Batch these

        // Solve the sequence of linear equations
        let one_sub_u = evaluation_point
            .iter()
            .map(|u| one.sub(u, builder, driver))
            .collect::<Vec<_>>();
        let mut challs_by_one_sub_u =
            FieldCT::multiply_many_raw(challenge_powers, &one_sub_u, builder, driver)?;

        for l in (1..=virtual_log_n).rev() {
            // Get r²⁽ˡ⁻¹⁾
            let challenge_power = challenge_powers[l - 1].clone();

            // Get uₗ₋₁
            let u = evaluation_point[l - 1].clone();
            let eval_neg = evals[l - 1].clone();

            // Get A₍ₗ₋₁₎(−r²⁽ˡ⁻¹⁾)
            // Compute the numerator
            let lhs = challenge_power
                .multiply(&eval_pos_prev, builder, driver)?
                .multiply(&FieldCT::from(C::ScalarField::from(2u64)), builder, driver)?;
            let tmp = FieldCT::commit_mul(&mut challs_by_one_sub_u[l - 1], builder)?
                .sub(&u, builder, driver);
            let rhs = eval_neg.multiply(&tmp, builder, driver)?;
            let mut eval_pos = lhs.sub(&rhs, builder, driver);

            // Divide by the denominator
            let tmp = one.divide_no_zero_check(
                &FieldCT::commit_mul(&mut challs_by_one_sub_u[l - 1], builder)?
                    .add(&u, builder, driver),
                builder,
                driver,
            )?;
            eval_pos = eval_pos.multiply(&tmp, builder, driver)?;

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
     *    \f[
     *    \left( \text{com}(A_1), \text{com}(A_2), \ldots, \text{com}(A_{d-1}) \right)
     *    \f]
     *    to the 'commitments' vector.
     *
     * 2. Computes the scalars
     *    \f{align}{
     *    \frac{\nu^2}{z - r^2} + \frac{\nu^3}{z + r^2},
     *    \frac{\nu^4}{z - r^4} + \frac{\nu^5}{z + r^4},
     *    \ldots,
     *    \frac{\nu^{2 \cdot d} } {z - r^{2^{d-1}}} + \frac{\nu^{2 \cdot d + 1}}{z + r^{2^{d-1}}}
     *    \f}
     *    and multiplies them against the entries of `padding_indicator_array`. The commitments \f$ [A_1]_1, \ldots,
     *    [A_{d-1}]_1 \f$ are multiplied by these scalars in the final `batch_mul` perfomed by KZG or IPA. Since
     *    `padding_indicator_array[i]` = 1 for i < log_n, and 0 otherwise, it ensures that the contributions from "dummy"
     *    rounds do not affect the final `batch mul`.
     *
     * 3. Accumulates the summands of the constant term:
     *    \f{align}{
     *    \frac{\nu^{2 i} \cdot A_i\left(r^{2^i} \right)}{z - r^{2^i}} + \frac{\nu^{2 \cdot i+1} \cdot
     *    A_i\left(-r^{2^i}\right)}{z+ r^{2^i}} \f
     *    } for \f$ i = 1, \ldots, d-1 \f$ and adds them to the
     *    'constant_term_accumulator'.
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
    #[expect(clippy::too_many_arguments)]
    fn batch_gemini_claims_received_from_prover<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        fold_commitments: &[BigGroup<C::ScalarField, T>],
        gemini_neg_evaluations: &[FieldCT<C::ScalarField>],
        gemini_pos_evaluations: &[FieldCT<C::ScalarField>],
        inverse_vanishing_evals: &[FieldCT<C::ScalarField>],
        shplonk_batching_challenge_powers: &[FieldCT<C::ScalarField>],
        commitments: &mut Vec<BigGroup<C::ScalarField, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        constant_term_accumulator: &mut FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let virtual_log_n = gemini_neg_evaluations.len();

        // Start from 1, because the commitment to A_0 is reconstructed from the commitments to the multilinear
        // polynomials. The corresponding evaluations are also handled separately.
        // The index of 1/ (z - r^{2^{j}}) in the vector of inverted Gemini denominators
        let lhs = (1..virtual_log_n)
            .flat_map(|i| {
                vec![
                    shplonk_batching_challenge_powers[2 * i].clone(),
                    shplonk_batching_challenge_powers[2 * i + 1].clone(),
                ]
            })
            .collect::<Vec<_>>();
        let rhs = (1..virtual_log_n)
            .flat_map(|i| {
                vec![
                    inverse_vanishing_evals[2 * i].clone(),
                    inverse_vanishing_evals[2 * i + 1].clone(),
                ]
            })
            .collect::<Vec<_>>();

        let mut scaling_factors_raw = FieldCT::multiply_many_raw(&lhs, &rhs, builder, driver)?;

        for j in 1..virtual_log_n {
            // The index of 1/ (z - r^{2^{j}}) in the vector of inverted Gemini denominators
            let pos_index = 2 * (j - 1);
            // The index of 1/ (z + r^{2^{j}}) in the vector of inverted Gemini denominators
            let neg_index = 2 * (j - 1) + 1;

            // Compute the "positive" scaling factor  (ν^{2j}) / (z - r^{2^{j}})
            let scaling_factor_pos =
                FieldCT::commit_mul(&mut scaling_factors_raw[pos_index], builder)?;

            // Compute the "negative" scaling factor  (ν^{2j+1}) / (z + r^{2^{j}})
            let scaling_factor_neg =
                FieldCT::commit_mul(&mut scaling_factors_raw[neg_index], builder)?;

            // Accumulate the const term contribution given by
            // v^{2j} * A_j(r^{2^j}) /(z - r^{2^j}) + v^{2j+1} * A_j(-r^{2^j}) /(z+ r^{2^j})
            let lhs = scaling_factor_neg.multiply(&gemini_neg_evaluations[j], builder, driver)?;
            let rhs = scaling_factor_pos.multiply(&gemini_pos_evaluations[j], builder, driver)?;
            constant_term_accumulator.add_assign(&lhs.add(&rhs, builder, driver), builder, driver);

            // Place the scaling factor to the 'scalars' vector
            scalars.push(padding_indicator_array[j].neg().multiply(
                &scaling_factor_neg.add(&scaling_factor_pos, builder, driver),
                builder,
                driver,
            )?);

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
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        commitments: &mut Vec<BigGroup<C::ScalarField, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) {
        // We started populating commitments and scalars by adding Shplonk:Q commitmment and the corresponding scalar
        // factor 1. In the case of ZK, we also added Gemini:masking_poly_comm before populating the vector with
        // commitments to prover polynomials
        // TACEO TODO: Handle ZK case
        let offset = 1;

        // Extract the indices from the container, which is normally created in a given Flavor
        let first_range_to_be_shifted_start = PRECOMPUTED_ENTITIES_SIZE + offset;
        let first_range_shifted_start = PRECOMPUTED_ENTITIES_SIZE + WITNESS_ENTITIES_SIZE + offset;
        let first_range_size = SHIFTED_WITNESS_ENTITIES_SIZE;

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

    #[expect(clippy::too_many_arguments)]
    fn add_zk_data<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        virtual_log_n: usize,
        commitments: &mut Vec<BigGroup<C::ScalarField, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        constant_term_accumulator: &mut FieldCT<C::ScalarField>,
        libra_commitments: &[BigGroup<C::ScalarField, T>; NUM_LIBRA_COMMITMENTS],
        libra_evaluations: &[FieldCT<C::ScalarField>; NUM_SMALL_IPA_EVALUATIONS],
        gemini_evaluation_challenge: &FieldCT<C::ScalarField>,
        shplonk_batching_challenge_powers: &[FieldCT<C::ScalarField>],
        shplonk_evaluation_challenge: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // Add Libra commitments to the vector of commitments
        commitments.extend_from_slice(libra_commitments);

        // Compute corresponding scalars and the correction to the constant term
        let mut denominators: [FieldCT<C::ScalarField>; NUM_SMALL_IPA_EVALUATIONS] =
            array::from_fn(|_| FieldCT::default());
        let mut batching_scalars: [FieldCT<C::ScalarField>; NUM_SMALL_IPA_EVALUATIONS] =
            array::from_fn(|_| FieldCT::default());

        // Compute Shplonk denominators and invert them
        let one = FieldCT::from(C::ScalarField::ONE);
        denominators[0] = one.divide(
            &shplonk_evaluation_challenge.sub(gemini_evaluation_challenge, builder, driver),
            builder,
            driver,
        )?;

        let subgroup_generator = FieldCT::from(C::get_subgroup_generator());
        let temp = subgroup_generator.multiply(gemini_evaluation_challenge, builder, driver)?;
        denominators[1] = one.divide(
            &shplonk_evaluation_challenge.sub(&temp, builder, driver),
            builder,
            driver,
        )?;

        denominators[2] = denominators[0].clone();
        denominators[3] = denominators[0].clone();

        // Compute the scalars to be multiplied against the commitments
        for idx in 0..NUM_SMALL_IPA_EVALUATIONS {
            let scaling_factor = denominators[idx].multiply(
                &shplonk_batching_challenge_powers
                    [2 * virtual_log_n + NUM_INTERLEAVING_CLAIMS as usize + idx],
                builder,
                driver,
            )?;
            batching_scalars[idx] = scaling_factor.neg();
            *constant_term_accumulator = constant_term_accumulator.add(
                &scaling_factor.multiply(&libra_evaluations[idx], builder, driver)?,
                builder,
                driver,
            );
        }

        // To save a scalar mul, add the sum of the batching scalars corresponding to the big sum evaluations
        scalars.push(batching_scalars[0].clone());
        scalars.push(batching_scalars[1].add(&batching_scalars[2], builder, driver));
        scalars.push(batching_scalars[3].clone());

        Ok(())
    }

    /**
     * A method required by ZKSumcheck. The challenge polynomial is concatenated from the powers of the sumcheck
     * challenges.
     */
    fn check_libra_evaluations_consistency<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        libra_evaluations: &[FieldCT<C::ScalarField>; NUM_SMALL_IPA_EVALUATIONS],
        gemini_evaluation_challenge: &FieldCT<C::ScalarField>,
        multilinear_challenge: &[FieldCT<C::ScalarField>],
        inner_product_eval_claim: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<bool> {
        // Compute the evaluation of the vanishing polynomial Z_H(X) at X = gemini_evaluation_challenge
        let one = FieldCT::from(C::ScalarField::ONE);
        let subgroup_size = FieldCT::from(C::ScalarField::from(C::SUBGROUP_SIZE as u64));
        let vanishing_poly_eval = gemini_evaluation_challenge
            .pow(&subgroup_size, builder, driver)?
            .sub(&one, builder, driver);

        Self::check_consistency(
            libra_evaluations,
            gemini_evaluation_challenge,
            &Self::compute_challenge_polynomial_coeffs(multilinear_challenge, builder, driver)?,
            inner_product_eval_claim,
            &vanishing_poly_eval,
            builder,
            driver,
        )
    }

    /**
     * Given the sumcheck multivariate challenge (u₀,...,u_{D-1}), where D = CONST_PROOF_SIZE_LOG_N,
     * the verifier constructs and evaluates the polynomial whose coefficients are given by
     * (1, u₀, u₀², u₁,...,1, u_{D-1}, u_{D-1}²). We spend D multiplications to construct the coefficients.
     */
    fn compute_challenge_polynomial_coeffs<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        multivariate_challenge: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<Vec<FieldCT<C::ScalarField>>> {
        let mut challenge_polynomial_lagrange = Vec::with_capacity(C::SUBGROUP_SIZE);

        let libra_univariates_length = C::LIBRA_UNIVARIATES_LENGTH;

        let challenge_poly_length = libra_univariates_length * multivariate_challenge.len() + 1;

        let mut one = FieldCT::from(C::ScalarField::ONE);
        let mut zero = FieldCT::from(C::ScalarField::ZERO);

        one.convert_constant_to_fixed_witness(builder, driver);
        zero.convert_constant_to_fixed_witness(builder, driver);

        challenge_polynomial_lagrange.push(one.clone());

        // Populate the vector with the powers of the challenges
        for (round_idx, challenge) in multivariate_challenge.iter().enumerate() {
            let current_idx = 1 + libra_univariates_length * round_idx;
            challenge_polynomial_lagrange.push(one.clone());

            // Recursively compute the powers of the challenge up to the length of libra univariates
            for idx in (current_idx + 1)..(current_idx + libra_univariates_length) {
                challenge_polynomial_lagrange.push(
                    challenge_polynomial_lagrange[idx - 1].multiply(challenge, builder, driver)?,
                );
            }
        }

        // Ensure that the coefficients are padded with zeros
        challenge_polynomial_lagrange[challenge_poly_length..].fill(zero.clone());

        Ok(challenge_polynomial_lagrange)
    }

    /**
     * @brief Generic consistency check agnostic to challenge polynomial \f$ F\f$.
     *
     * @param small_ipa_evaluations \f$ G(r) \f$ , \f$ A(g* r) \f$, \f$ A(r) \f$ , \f$ Q(r)\f$.
     * @param small_ipa_eval_challenge
     * @param challenge_polynomial The polynomial \f$ F \f$ that the verifier computes and evaluates on its own.
     * @param inner_product_eval_claim \f$ <F,G> \f$ where the polynomials are treated as vectors of coefficients (in
     * Lagrange basis).
     * @param vanishing_poly_eval \f$ Z_H(r) \f$
     * @return true
     * @return false
     */
    fn check_consistency<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        small_ipa_evaluations: &[FieldCT<C::ScalarField>; NUM_SMALL_IPA_EVALUATIONS],
        small_ipa_eval_challenge: &FieldCT<C::ScalarField>,
        challenge_polynomial: &[FieldCT<C::ScalarField>],
        inner_product_eval_claim: &FieldCT<C::ScalarField>,
        vanishing_poly_eval: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<bool> {
        // Check if Z_H(r) = 0.
        // handle_edge_cases(vanishing_poly_eval); //TACEO NOTE: We skip this check

        // Compute evaluations at r of F, Lagrange first, and Lagrange last for the fixed small subgroup
        let [challenge_poly, lagrange_first, lagrange_last] =
            Self::compute_batched_barycentric_evaluations(
                challenge_polynomial,
                small_ipa_eval_challenge,
                vanishing_poly_eval,
                builder,
                driver,
            )?;

        let concatenated_at_r = &small_ipa_evaluations[0];
        let grand_sum_shifted_eval = &small_ipa_evaluations[1];
        let grand_sum_eval = &small_ipa_evaluations[2];
        let quotient_eval = &small_ipa_evaluations[3];

        // Compute the evaluation of L_1(X) * A(X) + (X - 1/g) (A(gX) - A(X) - F(X) G(X)) + L_{|H|}(X)(A(X) - s) -
        // Z_H(X) * Q(X)
        let mut diff = lagrange_first.multiply(grand_sum_eval, builder, driver)?;

        let subgroup_gen_inv = FieldCT::from(C::get_subgroup_generator_inverse());
        let temp = small_ipa_eval_challenge
            .sub(&subgroup_gen_inv, builder, driver)
            .multiply(
                &grand_sum_shifted_eval
                    .sub(grand_sum_eval, builder, driver)
                    .sub(
                        &concatenated_at_r.multiply(&challenge_poly, builder, driver)?,
                        builder,
                        driver,
                    ),
                builder,
                driver,
            )?;
        diff = diff.add(&temp, builder, driver);

        let temp = lagrange_last.multiply(
            &grand_sum_eval.sub(inner_product_eval_claim, builder, driver),
            builder,
            driver,
        )?;
        diff = diff.add(&temp, builder, driver);

        let temp = vanishing_poly_eval.multiply(quotient_eval, builder, driver)?;
        diff = diff.sub(&temp, builder, driver);

        let zero = FieldCT::from(C::ScalarField::ZERO);
        diff.assert_equal(&zero, builder, driver);

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/1186).
        // Insecure pattern.
        // TACEO TODO: We could also ignore the result?
        Ok(T::get_public(&diff.get_value(builder, driver))
            .expect("Is this ever shared?")
            .is_zero())
    }

    fn compute_batched_barycentric_evaluations<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        coeffs: &[FieldCT<C::ScalarField>],
        r: &FieldCT<C::ScalarField>,
        vanishing_poly_eval: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<[FieldCT<C::ScalarField>; 3]> {
        let mut one = FieldCT::from(C::ScalarField::ONE);
        let mut zero = FieldCT::from(C::ScalarField::ZERO);

        one.convert_constant_to_fixed_witness(builder, driver);
        zero.convert_constant_to_fixed_witness(builder, driver);

        let subgroup_generator_inverse = FieldCT::from(C::get_subgroup_generator_inverse());

        let mut denominators = vec![FieldCT::from(C::ScalarField::ZERO); C::SUBGROUP_SIZE];

        let subgroup_size_inverse = FieldCT::from(C::ScalarField::from(C::SUBGROUP_SIZE as u64))
            .inverse(builder, driver)?;

        let numerator = vanishing_poly_eval.multiply(&subgroup_size_inverse, builder, driver)?;
        // (r^n - 1) / n

        let mut running_power = one.clone();
        //
        // Compute the denominators of the Lagrange polynomials evaluated at r
        for denominator in denominators.iter_mut() {
            *denominator = running_power.multiply(r, builder, driver)?; // r * g^{-i} - 1
            *denominator = denominator.sub(&one, builder, driver);
            running_power = running_power.multiply(&subgroup_generator_inverse, builder, driver)?;
        }

        // Invert/Batch invert denominators
        for denominator in denominators.iter_mut() {
            *denominator = denominator.inverse(builder, driver)?;
        }

        let mut result = [
            zero,
            FieldCT::from(C::ScalarField::ZERO),
            FieldCT::from(C::ScalarField::ZERO),
        ];

        // Accumulate the evaluation of the polynomials given by `coeffs` vector
        for (coeff, denominator) in coeffs.iter().zip(denominators.iter()) {
            result[0] = result[0].add(
                &coeff.multiply(denominator, builder, driver)?,
                builder,
                driver,
            ); // + coeffs_i * 1/(r * g^{-i}  - 1)
        }

        result[0] = result[0].multiply(&numerator, builder, driver)?; // The evaluation of the polynomials given by its evaluations over H
        result[1] = denominators[0].multiply(&numerator, builder, driver)?; // Lagrange first evaluated at r
        result[2] = denominators[C::SUBGROUP_SIZE - 1].multiply(&numerator, builder, driver)?; // Lagrange last evaluated at r

        Ok(result)
    }

    /// Precomputes a vector of the powers of `shplonk_batching_challenge` needed to batch all univariate claims.
    fn compute_shplonk_batching_challenge_powers<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        shplonk_batching_challenge: &FieldCT<C::ScalarField>,
        virtual_log_n: usize,
        has_zk: bool,
        committed_sumcheck: bool,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        // Minimum size of denominators
        let mut num_powers = 2 * virtual_log_n + NUM_INTERLEAVING_CLAIMS as usize;
        const NUM_COMMITTED_SUMCHECK_CLAIMS_PER_ROUND: usize = 3;

        if has_zk {
            num_powers += NUM_SMALL_IPA_EVALUATIONS;
        }
        if committed_sumcheck {
            num_powers += NUM_COMMITTED_SUMCHECK_CLAIMS_PER_ROUND * virtual_log_n;
        }

        let mut result = Vec::with_capacity(num_powers);
        result.push(FieldCT::from(C::ScalarField::ONE));
        for idx in 1..num_powers {
            let prev = &result[idx - 1];
            result.push(prev.multiply(shplonk_batching_challenge, builder, driver)?);
        }
        Ok(result)
    }
}
