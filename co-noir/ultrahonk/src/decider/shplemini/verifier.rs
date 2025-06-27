use super::{
    ShpleminiVerifierOpeningClaim,
    types::{PolyF, PolyG, PolyGShift},
};
use crate::{
    CONST_PROOF_SIZE_LOG_N, NUM_INTERLEAVING_CLAIMS, NUM_LIBRA_COMMITMENTS,
    NUM_SMALL_IPA_EVALUATIONS,
    decider::{
        types::{ClaimedEvaluations, VerifierCommitments},
        verifier::DeciderVerifier,
    },
    prelude::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
    verifier::HonkVerifyResult,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use co_builder::prelude::HonkCurve;
use co_builder::prelude::ZeroKnowledge;

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    DeciderVerifier<P, H>
{
    pub fn get_g_shift_evaluations(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyGShift<P::ScalarField> {
        PolyGShift {
            wires: &evaluations.shifted_witness,
        }
    }

    pub fn get_g_shift_comms(evaluations: &VerifierCommitments<P::G1Affine>) -> PolyG<P::G1Affine> {
        PolyG {
            wires: evaluations.witness.to_be_shifted().try_into().unwrap(),
        }
    }

    pub fn get_f_evaluations(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyF<P::ScalarField> {
        PolyF {
            precomputed: &evaluations.precomputed,
            witness: &evaluations.witness,
        }
    }
    pub fn get_f_comms(evaluations: &ClaimedEvaluations<P::G1Affine>) -> PolyF<P::G1Affine> {
        PolyF {
            precomputed: &evaluations.precomputed,
            witness: &evaluations.witness,
        }
    }

    pub fn get_fold_commitments(
        virtual_log_n: u32,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<Vec<P::G1Affine>> {
        let fold_commitments: Vec<_> = (0..virtual_log_n - 1)
            .map(|i| transcript.receive_point_from_prover::<P>(format!("Gemini:FOLD_{}", i + 1)))
            .collect::<Result<_, _>>()?;
        Ok(fold_commitments)
    }

    pub fn get_gemini_evaluations(
        virtual_log_n: u32,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<Vec<P::ScalarField>> {
        let gemini_evaluations: Vec<_> = (1..=virtual_log_n)
            .map(|i| transcript.receive_fr_from_prover::<P>(format!("Gemini:a_{}", i + 1)))
            .collect::<Result<_, _>>()?;
        Ok(gemini_evaluations)
    }

    pub fn powers_of_evaluation_challenge(
        gemini_evaluation_challenge: P::ScalarField,
        num_squares: usize,
    ) -> Vec<P::ScalarField> {
        let mut squares = Vec::with_capacity(num_squares);
        squares.push(gemini_evaluation_challenge);
        for j in 1..num_squares {
            squares.push(squares[j - 1].square());
        }
        squares
    }

    fn compute_inverted_gemini_denominators(
        shplonk_eval_challenge: &P::ScalarField,
        gemini_eval_challenge_powers: &[P::ScalarField],
    ) -> Vec<P::ScalarField> {
        tracing::trace!("Compute inverted gemini denominators");
        let virtual_log_n = gemini_eval_challenge_powers.len();
        let num_gemini_claims = 2 * virtual_log_n;
        let mut denominators = Vec::with_capacity(num_gemini_claims);
        for gemini_eval_challenge_power in gemini_eval_challenge_powers {
            // Place 1/(z - r ^ {2^j})
            denominators.push(*shplonk_eval_challenge - *gemini_eval_challenge_power);
            // Place 1/(z + r ^ {2^j})
            denominators.push(*shplonk_eval_challenge + *gemini_eval_challenge_power);
        }

        co_builder::prelude::Utils::batch_invert(&mut denominators);

        denominators
    }

    pub fn compute_batch_opening_claim(
        &self,
        multivariate_challenge: Vec<P::ScalarField>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        libra_commitments: Option<Vec<P::G1Affine>>,
        libra_univariate_evaluation: Option<P::ScalarField>,
        consistency_checked: &mut bool,
        padding_indicator_array: &[P::ScalarField; CONST_PROOF_SIZE_LOG_N],
        // const std::vector<RefVector<Commitment>>& concatenation_group_commitments = {},
        // RefSpan<P::ScalarField> concatenated_evaluations = {}
    ) -> HonkVerifyResult<ShpleminiVerifierOpeningClaim<P>> {
        tracing::trace!("Compute batch opening claim");

        let virtual_log_n = multivariate_challenge.len();

        let has_zk = ZeroKnowledge::from(libra_commitments.is_some());

        let mut hiding_polynomial_commitment = P::G1Affine::default();
        let mut batched_evaluation = P::ScalarField::zero();
        if has_zk == ZeroKnowledge::Yes {
            hiding_polynomial_commitment = transcript
                .receive_point_from_prover::<P>("Gemini:masking_poly_comm".to_string())?;
            batched_evaluation =
                transcript.receive_fr_from_prover::<P>("Gemini:masking_poly_eval".to_string())?;
        }

        // Get the challenge ρ to batch commitments to multilinear polynomials and their shifts
        let gemini_batching_challenge = transcript.get_challenge::<P>("rho".to_string());

        // Process Gemini transcript data:
        // - Get Gemini commitments (com(A₁), com(A₂), … , com(Aₙ₋₁))
        let fold_commitments = Self::get_fold_commitments(virtual_log_n as u32, transcript)?;

        // - Get Gemini evaluation challenge for Aᵢ, i = 0, … , d−1
        let gemini_evaluation_challenge = transcript.get_challenge::<P>("Gemini:r".to_string());

        // - Get evaluations (A₀(−r), A₁(−r²), ... , Aₙ₋₁(−r²⁽ⁿ⁻¹⁾))
        let gemini_fold_neg_evaluations =
            Self::get_gemini_evaluations(virtual_log_n as u32, transcript)?;

        // Get evaluations of partially evaluated batched interleaved polynomials P₊(rˢ) and P₋((-r)ˢ)
        let p_pos = P::ScalarField::zero();
        let p_neg = P::ScalarField::zero();
        // if (claim_batcher.interleaved) {
        //     p_pos = transcript->template receive_from_prover<Fr>("Gemini:P_pos");
        //     p_neg = transcript->template receive_from_prover<Fr>("Gemini:P_neg");
        // }

        // - Compute vector (r, r², ... , r^{2^{d-1}}), where d = log_n
        let gemini_eval_challenge_powers =
            Self::powers_of_evaluation_challenge(gemini_evaluation_challenge, virtual_log_n);

        let mut libra_evaluations = [P::ScalarField::zero(); NUM_SMALL_IPA_EVALUATIONS];
        if has_zk == ZeroKnowledge::Yes {
            libra_evaluations[0] =
                transcript.receive_fr_from_prover::<P>("Libra:concatenation_eval".to_string())?;
            libra_evaluations[1] = transcript
                .receive_fr_from_prover::<P>("Libra:shifted_grand_sum_eval".to_string())?;
            libra_evaluations[2] =
                transcript.receive_fr_from_prover::<P>("Libra:grand_sum_eval".to_string())?;
            libra_evaluations[3] =
                transcript.receive_fr_from_prover::<P>("Libra:quotient_eval".to_string())?;
        }

        // Process Shplonk transcript data:
        // - Get Shplonk batching challenge
        let shplonk_batching_challenge = transcript.get_challenge::<P>("Shplonk:nu".to_string());

        // Compute the powers of ν that are required for batching Gemini, SmallSubgroupIPA, and committed sumcheck
        // univariate opening claims.
        let shplonk_batching_challenge_powers = Self::compute_shplonk_batching_challenge_powers(
            shplonk_batching_challenge,
            virtual_log_n,
            has_zk,
        );

        // - Get the quotient commitment for the Shplonk batching of Gemini opening claims
        let q_commitment = transcript.receive_point_from_prover::<P>("Shplonk:Q".to_string())?;

        // Start populating the vector (Q, f₀, ... , fₖ₋₁, g₀, ... , gₘ₋₁, com(A₁), ... , com(Aₙ₋₁), [1]₁) where fᵢ are
        // the k commitments to unshifted polynomials and gⱼ are the m commitments to shifted polynomials

        // Get Shplonk opening point z
        let shplonk_evaluation_challenge = transcript.get_challenge::<P>("Shplonk:z".to_string());

        // Start computing the scalar to be multiplied by [1]₁
        let mut constant_term_accumulator = P::ScalarField::zero();

        let mut opening_claim: ShpleminiVerifierOpeningClaim<P> = ShpleminiVerifierOpeningClaim {
            challenge: shplonk_evaluation_challenge,
            scalars: Vec::new(),
            commitments: vec![q_commitment],
        };
        opening_claim.scalars.push(P::ScalarField::one());

        // Compute 1/(z − r), 1/(z + r), 1/(z - r²),  1/(z + r²), … , 1/(z - r^{2^{d-1}}), 1/(z + r^{2^{d-1}})
        // These represent the denominators of the summand terms in Shplonk partially evaluated polynomial Q_z
        let inverse_vanishing_evals: Vec<P::ScalarField> =
            Self::compute_inverted_gemini_denominators(
                &opening_claim.challenge,
                &gemini_eval_challenge_powers,
            );

        // TACEO NOTE: so far we have no interleaved polynomials so some parts here are skipped

        // Compute the additional factors to be multiplied with unshifted and shifted commitments when lazily
        // reconstructing the commitment of Q_z
        // i-th unshifted commitment is multiplied by −ρⁱ and the unshifted_scalar ( 1/(z−r) + ν/(z+r) )
        let unshifted_scalar =
            inverse_vanishing_evals[0] + shplonk_batching_challenge * inverse_vanishing_evals[1];

        // j-th shifted commitment is multiplied by −ρᵏ⁺ʲ⁻¹ and the shifted_scalar r⁻¹ ⋅ (1/(z−r) − ν/(z+r))
        let shifted_scalar = gemini_evaluation_challenge.inverse().unwrap()
            * (inverse_vanishing_evals[0]
                - shplonk_batching_challenge * inverse_vanishing_evals[1]);

        if has_zk == ZeroKnowledge::Yes {
            opening_claim.commitments.push(hiding_polynomial_commitment);
            opening_claim.scalars.push(-unshifted_scalar);
        }

        // Place the commitments to prover polynomials in the commitments vector. Compute the evaluation of the
        // batched multilinear polynomial. Populate the vector of scalars for the final batch mul

        let mut gemini_batching_challenge_power = P::ScalarField::one();
        if has_zk == ZeroKnowledge::Yes {
            // ρ⁰ is used to batch the hiding polynomial which has already been added to the commitments vector
            gemini_batching_challenge_power *= gemini_batching_challenge;
        }

        // Append the commitments and scalars from each batch of claims to the Shplemini, vectors which subsequently
        // will be inputs to the batch mul;
        // update the batched evaluation and the running batching challenge (power of rho) in place.
        // Update the commitments and scalars vectors as well as the batched evaluation given the present batches
        self.update_batch_mul_inputs_and_batched_evaluation(
            &gemini_batching_challenge,
            &unshifted_scalar,
            &shifted_scalar,
            &mut opening_claim,
            &mut batched_evaluation,
            &gemini_batching_challenge_power,
        );

        // Reconstruct Aᵢ(r²ⁱ) for i=0, ..., n-1 from the batched evaluation of the multilinear polynomials and Aᵢ(−r²ⁱ)
        // for i = 0, ..., n-1.
        // In the case of interleaving, we compute A₀(r) as A₀₊(r) + P₊(r^s).
        let gemini_fold_pos_evaluations = Self::compute_fold_pos_evaluations(
            padding_indicator_array,
            &batched_evaluation,
            &multivariate_challenge,
            &gemini_eval_challenge_powers,
            &gemini_fold_neg_evaluations,
            p_neg,
        );

        // Place the commitments to Gemini fold polynomials Aᵢ in the vector of batch_mul commitments, compute the
        // contributions from Aᵢ(−r²ⁱ) for i=1, … , n−1 to the constant term accumulator, add corresponding scalars for
        // the batch mul
        Self::batch_gemini_claims_received_from_prover(
            padding_indicator_array,
            &fold_commitments,
            &gemini_fold_neg_evaluations,
            &gemini_fold_pos_evaluations,
            &inverse_vanishing_evals,
            &shplonk_batching_challenge_powers,
            &mut opening_claim,
            &mut constant_term_accumulator,
        );

        let full_a_0_pos = gemini_fold_pos_evaluations[0];

        // Retrieve  the contribution without P₊(r^s)
        let a_0_pos = full_a_0_pos - p_pos;
        // Add contributions from A₀₊(r) and  A₀₋(-r) to constant_term_accumulator:
        //  Add  A₀₊(r)/(z−r) to the constant term accumulator
        constant_term_accumulator += a_0_pos * inverse_vanishing_evals[0];
        // Add  A₀₋(-r)/(z+r) to the constant term accumulator
        constant_term_accumulator += gemini_fold_neg_evaluations[0]
            * shplonk_batching_challenge
            * inverse_vanishing_evals[1];

        //TACEO TODO:
        // // - Add A₀(r)/(z−r) to the constant term accumulator
        // constant_term_accumulator += a_0_pos * inverse_vanishing_evals[0];
        // // Add A₀(−r)/(z+r) to the constant term accumulator
        // constant_term_accumulator += gemini_fold_neg_evaluations[0]
        //     * shplonk_batching_challenge
        //     * inverse_vanishing_evals[1];

        // TACEO TODO: BB removes repeated commitments here to reduce the number of scalar muls
        // remove_repeated_commitments(commitments, scalars, repeated_commitments, has_zk);

        // For ZK flavors, the sumcheck output contains the evaluations of Libra univariates that submitted to the
        // ShpleminiVerifier, otherwise this argument is set to be empty
        if has_zk == ZeroKnowledge::Yes {
            Self::add_zk_data(
                virtual_log_n,
                &mut opening_claim.commitments,
                &mut opening_claim.scalars,
                &mut constant_term_accumulator,
                &libra_commitments
                    .expect("We have ZK")
                    .as_slice()
                    .try_into()
                    .unwrap(),
                &libra_evaluations.as_slice().try_into().unwrap(),
                &gemini_evaluation_challenge,
                &shplonk_batching_challenge_powers,
                &shplonk_evaluation_challenge,
            )?;

            *consistency_checked = Self::check_evaluations_consistency(
                &libra_evaluations,
                gemini_evaluation_challenge,
                &multivariate_challenge,
                libra_univariate_evaluation.expect("checked it is ZK"),
            )?;
        }

        // Finalize the batch opening claim
        opening_claim.commitments.push(P::G1Affine::generator());
        opening_claim.scalars.push(constant_term_accumulator);
        Ok(opening_claim)
    }

    /**
     * @brief Append the commitments and scalars from each batch of claims to the Shplemini, vectors which subsequently
     * will be inputs to the batch mul;
     * update the batched evaluation and the running batching challenge (power of rho) in place.
     *
     * @param commitments commitment inputs to the single Shplemini batch mul
     * @param scalars scalar inputs to the single Shplemini batch mul
     * @param batched_evaluation running batched evaluation of the committed multilinear polynomials
     * @param rho multivariate batching challenge \rho
     * @param rho_power current power of \rho used in the batching scalar
     * @param shplonk_batching_pos and @param shplonk_batching_neg consecutive powers of the Shplonk batching
     * challenge ν for the interleaved contributions
     */
    fn update_batch_mul_inputs_and_batched_evaluation(
        &self,
        multivariate_batching_challenge: &P::ScalarField,
        unshifted_scalar: &P::ScalarField,
        shifted_scalar: &P::ScalarField,
        opening_claim: &mut ShpleminiVerifierOpeningClaim<P>,
        batched_evaluation: &mut P::ScalarField,
        gemini_batching_challenge_power: &P::ScalarField,
    ) {
        tracing::trace!("Batch multivariate opening claims");

        let mut current_batching_challenge = *gemini_batching_challenge_power;
        let unshifted_evaluations = Self::get_f_evaluations(&self.memory.claimed_evaluations);
        let shifted_evaluations = Self::get_g_shift_evaluations(&self.memory.claimed_evaluations);
        let unshifted_commitments = Self::get_f_comms(&self.memory.verifier_commitments);
        let to_be_shifted_commitments = Self::get_g_shift_comms(&self.memory.verifier_commitments);
        for (unshifted_commitment, unshifted_evaluation) in unshifted_commitments
            .iter()
            .zip(unshifted_evaluations.iter())
        {
            // Move unshifted commitments to the 'commitments' vector
            opening_claim.commitments.push(*unshifted_commitment);
            // Compute −ρⁱ ⋅ (1/(z−r) + ν/(z+r)) and place into 'scalars'
            opening_claim
                .scalars
                .push(-(*unshifted_scalar) * current_batching_challenge);
            // Accumulate the evaluation of ∑ ρⁱ ⋅ fᵢ at the sumcheck challenge
            *batched_evaluation += *unshifted_evaluation * current_batching_challenge;
            // Update the batching challenge
            current_batching_challenge *= *multivariate_batching_challenge;
        }
        for (shifted_commitment, shifted_evaluation) in to_be_shifted_commitments
            .iter()
            .zip(shifted_evaluations.iter())
        {
            // Move shifted commitments to the 'commitments' vector
            opening_claim.commitments.push(*shifted_commitment);
            // Compute −ρ⁽ᵏ⁺ʲ⁾ ⋅ r⁻¹ ⋅ (1/(z−r) − ν/(z+r)) and place into 'scalars'
            opening_claim
                .scalars
                .push(-(*shifted_scalar) * current_batching_challenge);
            // Accumulate the evaluation of ∑ ρ⁽ᵏ⁺ʲ⁾ ⋅ f_shift at the sumcheck challenge
            *batched_evaluation += *shifted_evaluation * current_batching_challenge;
            // Update the batching challenge ρ
            current_batching_challenge *= *multivariate_batching_challenge;
        }
    }
    /**
     * @brief Populates the 'commitments' and 'scalars' vectors with the commitments to Gemini fold polynomials \f$
     * A_i \f$.
     *
     * @details Once the commitments to Gemini "fold" polynomials \f$ A_i \f$ and their evaluations at \f$ -r^{2^i}
     * \f$, where \f$ i = 1, \ldots, n-1 \f$, are received by the verifier, it performs the following operations:
     *
     * 1. Moves the vector
     *    \f[
     *    \left( \text{com}(A_1), \text{com}(A_2), \ldots, \text{com}(A_{n-1}) \right)
     *    \f]
     *    to the 'commitments' vector.
     *
     * 2. Computes the scalars:
     *    \f[
     *    \frac{\nu^{2}}{z + r^2}, \frac{\nu^3}{z + r^4}, \ldots, \frac{\nu^{n-1}}{z + r^{2^{n-1}}}
     *    \f]
     *    and places them into the 'scalars' vector.
     *
     * 3. Accumulates the summands of the constant term:
     *    \f[
     *    \sum_{i=2}^{n-1} \frac{\nu^{i} \cdot A_i(-r^{2^i})}{z + r^{2^i}}
     *    \f]
     *    and adds them to the 'constant_term_accumulator'.
     *
     * @param log_circuit_size The logarithm of the circuit size, determining the depth of the Gemini protocol.
     * @param fold_commitments A vector containing the commitments to the Gemini fold polynomials \f$ A_i \f$.
     * @param gemini_evaluations A vector containing the evaluations of the Gemini fold polynomials \f$ A_i \f$ at
     * points \f$ -r^{2^i} \f$.
     * @param inverse_vanishing_evals A vector containing the inverse evaluations of the vanishing polynomial.
     * @param shplonk_batching_challenge The batching challenge \f$ \nu \f$ used in the SHPLONK protocol.
     * @param commitments Output vector where the commitments to the Gemini fold polynomials will be stored.
     * @param scalars Output vector where the computed scalars will be stored.
     * @param constant_term_accumulator The accumulator for the summands of the constant term.
     */
    #[expect(clippy::too_many_arguments)]
    fn batch_gemini_claims_received_from_prover(
        padding_indicator_array: &[P::ScalarField; CONST_PROOF_SIZE_LOG_N],
        fold_commitments: &[P::G1Affine],
        gemini_neg_evaluations: &[P::ScalarField],
        gemini_pos_evaluations: &[P::ScalarField],
        inverse_vanishing_evals: &[P::ScalarField],
        shplonk_batching_challenge_powers: &[P::ScalarField],
        opening_claim: &mut ShpleminiVerifierOpeningClaim<P>,
        constant_term_accumulator: &mut P::ScalarField,
    ) {
        tracing::trace!("Receive batch gemini claims");
        let virtual_log_n = gemini_neg_evaluations.len();
        // Start from 1, because the commitment to A_0 is reconstructed from the commitments to the multilinear
        // polynomials. The corresponding evaluations are also handled separately.
        for j in 1..virtual_log_n {
            // The index of 1/ (z - r^{2^{j}}) in the vector of inverted Gemini denominators
            let pos_index = 2 * j;
            // The index of 1/ (z + r^{2^{j}}) in the vector of inverted Gemini denominators
            let neg_index = 2 * j + 1;

            // Compute the "positive" scaling factor  (ν^{2j}) / (z - r^{2^{j}})
            let scaling_factor_pos =
                shplonk_batching_challenge_powers[pos_index] * inverse_vanishing_evals[pos_index];
            // Compute the "negative" scaling factor  (ν^{2j+1}) / (z + r^{2^{j}})
            let scaling_factor_neg =
                shplonk_batching_challenge_powers[neg_index] * inverse_vanishing_evals[neg_index];

            // Accumulate the const term contribution given by
            // v^{2j} * A_j(r^{2^j}) /(z - r^{2^j}) + v^{2j+1} * A_j(-r^{2^j}) /(z+ r^{2^j})
            *constant_term_accumulator += scaling_factor_neg * gemini_neg_evaluations[j]
                + scaling_factor_pos * gemini_pos_evaluations[j];

            // Place the scaling factor to the 'scalars' vector
            opening_claim
                .scalars
                .push(-padding_indicator_array[j] * (scaling_factor_neg + scaling_factor_pos));
            // Move com(Aᵢ) to the 'commitments' vector
            opening_claim.commitments.push(fold_commitments[j - 1]);
        }
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
     * @param batched_evaluation The evaluation of the batched polynomial at \f$ (u_0, \ldots, u_{d-1})\f$.
     * @param evaluation_point Evaluation point \f$ (u_0, \ldots, u_{d-1}) \f$ padded to CONST_PROOF_SIZE_LOG_N.
     * @param challenge_powers Powers of \f$ r \f$, \f$ r^2 \), ..., \( r^{2^{d-1}} \f$.
     * @param fold_neg_evals  Evaluations \f$ A_{i-1}(-r^{2^{i-1}}) \f$.
     * @return Evaluation \f$ A_0(r) \f$.
     */
    pub fn compute_fold_pos_evaluations(
        padding_indicator_array: &[P::ScalarField; CONST_PROOF_SIZE_LOG_N],
        batched_evaluation: &P::ScalarField,
        evaluation_point: &[P::ScalarField], // CONST_PROOF_SIZE
        challenge_powers: &[P::ScalarField], // r_squares CONST_PROOF_SIZE_LOG_N
        fold_neg_evals: &[P::ScalarField],
        p_neg: P::ScalarField,
    ) -> Vec<P::ScalarField> {
        let virtual_log_n = evaluation_point.len();

        let mut evals = fold_neg_evals.to_vec();

        let mut eval_pos_prev = *batched_evaluation;

        let mut fold_pos_evaluations = Vec::with_capacity(virtual_log_n);
        // Either a computed eval of A_i at r^{2^i}, or 0
        let mut value_to_emplace;

        // Add the contribution of P-((-r)ˢ) to get A_0(-r), which is 0 if there are no interleaved polynomials
        evals[0] += p_neg;

        // Solve the sequence of linear equations
        for l in (1..=virtual_log_n).rev() {
            // Get r²⁽ˡ⁻¹⁾
            let challenge_power = challenge_powers[l - 1];
            // Get uₗ₋₁
            let u = evaluation_point[l - 1];
            let eval_neg = evals[l - 1];
            // Get A₍ₗ₋₁₎(−r²⁽ˡ⁻¹⁾)
            // Compute the numerator
            let mut eval_pos = (challenge_power * eval_pos_prev * P::ScalarField::from(2u64))
                - eval_neg * (challenge_power * (P::ScalarField::one() - u) - u);
            // Divide by the denominator
            eval_pos *= (challenge_power * (P::ScalarField::one() - u) + u)
                .inverse()
                .expect("Non-zero denominator");

            // If current index is bigger than log_n, we propagate `batched_evaluation` to the next
            // round. Otherwise, current `eval_pos` A₍ₗ₋₁₎(−r²⁽ˡ⁻¹⁾) becomes `eval_pos_prev` in the round l-2.
            eval_pos_prev = padding_indicator_array[l - 1] * eval_pos
                + (P::ScalarField::one() - padding_indicator_array[l - 1]) * eval_pos_prev;
            // If current index is bigger than log_n, we emplace 0, which is later multiplied against
            // Commitment::one().
            value_to_emplace = padding_indicator_array[l - 1] * eval_pos_prev;
            fold_pos_evaluations.push(value_to_emplace);
        }

        fold_pos_evaluations.reverse();

        fold_pos_evaluations
    }

    /**
     * @brief Add the opening data corresponding to Libra masking univariates to the batched opening claim
     *
     * @details After verifying ZK Sumcheck, the verifier has to validate the claims about the evaluations of Libra
     * univariates used to mask Sumcheck round univariates. To minimize the overhead of such openings, we continue
     * the Shplonk batching started in Gemini, i.e. we add new claims multiplied by a suitable power of the Shplonk
     * batching challenge and re-use the evaluation challenge sampled to prove the evaluations of Gemini
     * polynomials.
     *
     * @param commitments
     * @param scalars
     * @param libra_commitments
     * @param libra_univariate_evaluations
     * @param multivariate_challenge
     * @param shplonk_batching_challenge
     * @param shplonk_evaluation_challenge
     */
    #[expect(clippy::too_many_arguments)]
    fn add_zk_data(
        virtual_log_n: usize,
        commitments: &mut Vec<P::G1Affine>,
        scalars: &mut Vec<P::ScalarField>,
        constant_term_accumulator: &mut P::ScalarField,
        libra_commitments: &[P::G1Affine; NUM_LIBRA_COMMITMENTS],
        libra_evaluations: &[P::ScalarField; NUM_SMALL_IPA_EVALUATIONS],
        gemini_evaluation_challenge: &P::ScalarField,
        shplonk_batching_challenge_powers: &[P::ScalarField],
        shplonk_evaluation_challenge: &P::ScalarField,
    ) -> HonkVerifyResult<()> {
        commitments.reserve(NUM_LIBRA_COMMITMENTS);
        // Add Libra commitments to the vector of commitments
        for &commitment in libra_commitments.iter() {
            commitments.push(commitment);
        }

        // Compute corresponding scalars and the correction to the constant term
        let mut denominators = [P::ScalarField::zero(); NUM_SMALL_IPA_EVALUATIONS];
        let mut batching_scalars = [P::ScalarField::zero(); NUM_SMALL_IPA_EVALUATIONS];
        let subgroup_generator = P::get_subgroup_generator();

        // Compute Shplonk denominators and invert them
        denominators[0] = (*shplonk_evaluation_challenge - *gemini_evaluation_challenge)
            .inverse()
            .expect("non-zero");
        denominators[1] = (*shplonk_evaluation_challenge
            - subgroup_generator * *gemini_evaluation_challenge)
            .inverse()
            .expect("non-zero");
        denominators[2] = denominators[0];
        denominators[3] = denominators[0];

        // Compute the scalars to be multiplied against the commitments [libra_concatenated], [grand_sum], [grand_sum], and
        // [libra_quotient]
        for idx in 0..NUM_SMALL_IPA_EVALUATIONS {
            let scaling_factor = denominators[idx]
                * shplonk_batching_challenge_powers
                    [2 * virtual_log_n + NUM_INTERLEAVING_CLAIMS as usize + idx];
            batching_scalars[idx] = -scaling_factor;
            *constant_term_accumulator += scaling_factor * libra_evaluations[idx];
        }

        // To save a scalar mul, add the sum of the batching scalars corresponding to the big sum evaluations
        scalars.reserve(NUM_SMALL_IPA_EVALUATIONS - 1);
        scalars.push(batching_scalars[0]);
        scalars.push(batching_scalars[1] + batching_scalars[2]);
        scalars.push(batching_scalars[3]);
        Ok(())
    }

    fn check_evaluations_consistency(
        libra_evaluations: &[P::ScalarField],
        gemini_evaluation_challenge: P::ScalarField,
        multilinear_challenge: &[P::ScalarField],
        inner_product_eval_claim: P::ScalarField,
    ) -> HonkVerifyResult<bool> {
        let subgroup_generator_inverse = P::get_subgroup_generator_inverse();

        // Compute the evaluation of the vanishing polynomia Z_H(X) at X = gemini_evaluation_challenge
        let vanishing_poly_eval =
            gemini_evaluation_challenge.pow([P::SUBGROUP_SIZE as u64]) - P::ScalarField::one();

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1194). Handle edge cases in PCS
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1186). Insecure pattern.
        let gemini_challenge_in_small_subgroup = vanishing_poly_eval == P::ScalarField::zero();

        // The probability of this event is negligible but it has to be processed correctly
        if gemini_challenge_in_small_subgroup {
            return Err(eyre::eyre!("Gemini challenge is in the small subgroup"));
        }

        // Construct the challenge polynomial from the sumcheck challenge, the verifier has to evaluate it on its own
        let challenge_polynomial_lagrange =
            Self::compute_challenge_polynomial(multilinear_challenge);

        // Compute the evaluations of the challenge polynomial, Lagrange first, and Lagrange last for the fixed small
        // subgroup
        let [challenge_poly, lagrange_first, lagrange_last] =
            Self::compute_batched_barycentric_evaluations(
                &challenge_polynomial_lagrange,
                gemini_evaluation_challenge,
                &subgroup_generator_inverse,
                &vanishing_poly_eval,
            );

        let concatenated_at_r = libra_evaluations[0];
        let grand_sum_shifted_eval = libra_evaluations[1];
        let grand_sum_eval = libra_evaluations[2];
        let quotient_eval = libra_evaluations[3];

        // Compute the evaluation of
        // L_1(X) * A(X) + (X - 1/g) (A(gX) - A(X) - F(X) G(X)) + L_{|H|}(X)(A(X) - s) - Z_H(X) * Q(X)
        let mut diff = lagrange_first * grand_sum_eval;
        diff += (gemini_evaluation_challenge - subgroup_generator_inverse)
            * (grand_sum_shifted_eval - grand_sum_eval - concatenated_at_r * challenge_poly);
        diff += lagrange_last * (grand_sum_eval - inner_product_eval_claim)
            - vanishing_poly_eval * quotient_eval;

        Ok(diff == P::ScalarField::zero())
    }

    fn compute_challenge_polynomial(
        multivariate_challenge: &[P::ScalarField],
    ) -> Vec<P::ScalarField> {
        let mut challenge_polynomial_lagrange = vec![P::ScalarField::zero(); P::SUBGROUP_SIZE];

        challenge_polynomial_lagrange[0] = P::ScalarField::one();

        // Populate the vector with the powers of the challenges
        for (idx_poly, challenge) in multivariate_challenge
            .iter()
            .enumerate()
            .take(CONST_PROOF_SIZE_LOG_N)
        {
            let current_idx = 1 + P::LIBRA_UNIVARIATES_LENGTH * idx_poly;
            challenge_polynomial_lagrange[current_idx] = P::ScalarField::one();
            for idx in 1..P::LIBRA_UNIVARIATES_LENGTH {
                // Recursively compute the powers of the challenge
                challenge_polynomial_lagrange[current_idx + idx] =
                    challenge_polynomial_lagrange[current_idx + idx - 1] * challenge;
            }
        }

        challenge_polynomial_lagrange
    }

    fn compute_batched_barycentric_evaluations(
        coeffs: &[P::ScalarField],
        r: P::ScalarField,
        inverse_root_of_unity: &P::ScalarField,
        vanishing_poly_eval: &P::ScalarField,
    ) -> [P::ScalarField; 3] {
        let mut denominators = vec![P::ScalarField::zero(); P::SUBGROUP_SIZE];
        let one = P::ScalarField::one();
        let mut numerator = *vanishing_poly_eval;

        numerator *= P::ScalarField::from(P::SUBGROUP_SIZE as u64)
            .inverse()
            .expect("non-zero"); // (r^n - 1) / n

        denominators[0] = r - one;
        let mut work_root = *inverse_root_of_unity; // g^{-1}
        //
        // Compute the denominators of the Lagrange polynomials evaluated at r
        for denominator in denominators.iter_mut().skip(1) {
            *denominator = work_root * r;
            *denominator -= one; // r * g^{-i} - 1
            work_root *= *inverse_root_of_unity;
        }

        // Invert/Batch invert denominators
        co_builder::prelude::Utils::batch_invert(&mut denominators);

        let mut result = [P::ScalarField::zero(); 3];

        // Accumulate the evaluation of the polynomials given by `coeffs` vector
        for (coeff, denominator) in coeffs.iter().zip(denominators.iter()) {
            result[0] += *coeff * *denominator; // + coeffs_i * 1/(r * g^{-i}  - 1)
        }

        result[0] *= numerator; // The evaluation of the polynomials given by its evaluations over H
        result[1] = denominators[0] * numerator; // Lagrange first evaluated at r
        result[2] = denominators[P::SUBGROUP_SIZE - 1] * numerator; // Lagrange last evaluated at r

        result
    }

    /**
     * @brief A helper used by Shplemini Verifier. Precomputes a vector of the powers of \f$ \nu \f$ needed to batch all
     * univariate claims.
     *
     */
    fn compute_shplonk_batching_challenge_powers(
        shplonk_batching_challenge: P::ScalarField,
        virtual_log_n: usize,
        has_zk: ZeroKnowledge,
        // committed_sumcheck: bool, we don't have this (yet)
    ) -> Vec<P::ScalarField> {
        let mut num_powers = 2 * virtual_log_n + NUM_INTERLEAVING_CLAIMS as usize;
        // // Each round univariate is opened at 0, 1, and a round challenge.
        // const NUM_COMMITTED_SUMCHECK_CLAIMS_PER_ROUND: usize = 3;

        // Shplonk evaluation and batching challenges are re-used in SmallSubgroupIPA.
        if has_zk == ZeroKnowledge::Yes {
            num_powers += NUM_SMALL_IPA_EVALUATIONS;
        }

        // if committed_sumcheck {
        //     num_powers += NUM_COMMITTED_SUMCHECK_CLAIMS_PER_ROUND * CONST_PROOF_SIZE_LOG_N;
        // }

        let mut result = Vec::with_capacity(num_powers);
        result.push(P::ScalarField::one());
        for idx in 1..num_powers {
            result.push(result[idx - 1] * shplonk_batching_challenge);
        }
        result
    }
}
