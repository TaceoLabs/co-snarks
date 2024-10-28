use super::{
    types::{PolyF, PolyG, PolyGShift},
    ShpleminiVerifierOpeningClaim,
};
use crate::{
    decider::{
        types::{ClaimedEvaluations, VerifierCommitments},
        verifier::DeciderVerifier,
    },
    prelude::{HonkCurve, TranscriptFieldType},
    transcript::{Transcript, TranscriptHasher},
    verifier::HonkVerifyResult,
    Utils, CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    DeciderVerifier<P, H>
{
    pub fn get_g_shift_evaluations_shplemini(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyGShift<P::ScalarField> {
        PolyGShift {
            tables: &evaluations.shifted_tables,
            wires: &evaluations.shifted_witness,
        }
    }

    pub fn get_g_shift_comms_shplemini(
        evaluations: &VerifierCommitments<P::G1Affine>,
    ) -> PolyG<P::G1Affine> {
        PolyG {
            tables: evaluations
                .precomputed
                .get_table_polynomials()
                .try_into()
                .unwrap(),
            wires: evaluations.witness.to_be_shifted().try_into().unwrap(),
        }
    }

    pub fn get_f_evaluations_shplemini(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyF<P::ScalarField> {
        PolyF {
            precomputed: &evaluations.precomputed,
            witness: &evaluations.witness,
        }
    }
    pub fn get_f_comms_shplemini(
        evaluations: &ClaimedEvaluations<P::G1Affine>,
    ) -> PolyF<P::G1Affine> {
        PolyF {
            precomputed: &evaluations.precomputed,
            witness: &evaluations.witness,
        }
    }

    pub fn get_fold_commitments(
        _log_circuit_size: &u32,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<Vec<P::G1Affine>> {
        let fold_commitments: Vec<_> = (0..CONST_PROOF_SIZE_LOG_N - 1)
            .map(|i| transcript.receive_point_from_prover::<P>(format!("Gemini:FOLD_{}", i + 1)))
            .collect::<Result<_, _>>()?;
        Ok(fold_commitments)
    }
    pub fn get_gemini_evaluations(
        _log_circuit_size: &u32,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<Vec<P::ScalarField>> {
        let gemini_evaluations: Vec<_> = (0..CONST_PROOF_SIZE_LOG_N)
            .map(|i| transcript.receive_fr_from_prover::<P>(format!("Gemini:a_{}", i + 1)))
            .collect::<Result<_, _>>()?;
        Ok(gemini_evaluations)
    }
    pub fn powers_of_evaluation_challenge(
        gemini_evaluation_challenge: P::ScalarField,
        proof_size: &usize,
    ) -> Vec<P::ScalarField> {
        let mut squares = Vec::with_capacity(*proof_size);
        squares.push(gemini_evaluation_challenge);
        for j in 1..*proof_size {
            squares.push(squares[j - 1] * squares[j - 1]);
        }
        squares
    }

    fn compute_inverted_gemini_denominators(
        num_gemini_claims: usize,
        shplonk_eval_challenge: &P::ScalarField,
        gemini_eval_challenge_powers: &[P::ScalarField],
    ) -> Vec<P::ScalarField> {
        let mut inverted_denominators = Vec::with_capacity(num_gemini_claims);
        inverted_denominators.push(
            (*shplonk_eval_challenge - gemini_eval_challenge_powers[0])
                .inverse()
                .unwrap(),
        );

        for gemini_eval_challenge_power in gemini_eval_challenge_powers {
            let round_inverted_denominator = (*shplonk_eval_challenge
                + gemini_eval_challenge_power)
                .inverse()
                .unwrap();
            inverted_denominators.push(round_inverted_denominator);
        }

        inverted_denominators
    }

    pub fn compute_batch_opening_claim(
        &self,
        circuit_size: u32,
        multivariate_challenge: Vec<P::ScalarField>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        // const std::vector<RefVector<Commitment>>& concatenation_group_commitments = {},
        // RefSpan<P::ScalarField> concatenated_evaluations = {}
    ) -> HonkVerifyResult<ShpleminiVerifierOpeningClaim<P>> {
        // let unshifted_evaluations: PolyF<P::ScalarField> =
        //     Self::get_f_evaluations(&self.memory.claimed_evaluations);
        //     let shifted_evaluations: PolyGShift<P::ScalarField> =
        //     Self::get_g_shift_evaluations(&self.memory.claimed_evaluations);
        //     let unshifted_commitments = Self::get_f_comms(&self.memory.verifier_commitments);
        //     let to_be_shifted_commitments = Self::get_g_shift_comms(&self.memory.verifier_commitments);

        // Extract log_circuit_size
        let log_circuit_size = Utils::get_msb32(circuit_size);

        // Get the challenge ρ to batch commitments to multilinear polynomials and their shifts
        let multivariate_batching_challenge = transcript.get_challenge::<P>("rho".to_string());

        // Process Gemini transcript data:
        // - Get Gemini commitments (com(A₁), com(A₂), … , com(Aₙ₋₁))
        let fold_commitments: Vec<P::G1Affine> =
            Self::get_fold_commitments(&log_circuit_size, transcript)?;

        // - Get Gemini evaluation challenge for Aᵢ, i = 0, … , d−1
        let gemini_evaluation_challenge = transcript.get_challenge::<P>("Gemini:r".to_string());

        // - Get evaluations (A₀(−r), A₁(−r²), ... , Aₙ₋₁(−r²⁽ⁿ⁻¹⁾))
        let gemini_evaluations: Vec<P::ScalarField> =
            Self::get_gemini_evaluations(&log_circuit_size, transcript)?;

        // - Compute vector (r, r², ... , r²⁽ⁿ⁻¹⁾), where n = log_circuit_size
        let gemini_eval_challenge_powers: Vec<P::ScalarField> =
            Self::powers_of_evaluation_challenge(
                gemini_evaluation_challenge,
                &CONST_PROOF_SIZE_LOG_N,
            );

        // Process Shplonk transcript data:
        // - Get Shplonk batching challenge
        let shplonk_batching_challenge = transcript.get_challenge::<P>("Shplonk:nu".to_string());
        // - Get the quotient commitment for the Shplonk batching of Gemini opening claims
        let q_commitment = transcript.receive_point_from_prover::<P>("Shplonk:Q".to_string())?;

        // Start populating the vector (Q, f₀, ... , fₖ₋₁, g₀, ... , gₘ₋₁, com(A₁), ... , com(Aₙ₋₁), [1]₁) where fᵢ are
        // the k commitments to unshifted polynomials and gⱼ are the m commitments to shifted polynomials
        let mut commitments: Vec<P::G1Affine> = vec![q_commitment];

        // Get Shplonk opening point z
        let shplonk_evaluation_challenge = transcript.get_challenge::<P>("Shplonk:z".to_string());

        // Start computing the scalar to be multiplied by [1]₁
        let mut constant_term_accumulator = P::ScalarField::zero();

        // Initialize the vector of scalars placing the scalar 1 corresponding to Q_commitment
        let mut scalars: Vec<P::ScalarField> = Vec::new();

        scalars.push(P::ScalarField::one());

        // Compute 1/(z − r), 1/(z + r), 1/(z + r²), … , 1/(z + r²⁽ⁿ⁻¹⁾)
        // These represent the denominators of the summand terms in Shplonk partially evaluated polynomial Q_z
        let inverse_vanishing_evals: Vec<P::ScalarField> =
            Self::compute_inverted_gemini_denominators(
                (log_circuit_size + 1).try_into().unwrap(),
                &shplonk_evaluation_challenge,
                &gemini_eval_challenge_powers,
            );

        // Compute the additional factors to be multiplied with unshifted and shifted commitments when lazily
        // reconstructing the commitment of Q_z

        // i-th unshifted commitment is multiplied by −ρⁱ and the unshifted_scalar ( 1/(z−r) + ν/(z+r) )
        let unshifted_scalar =
            inverse_vanishing_evals[0] + shplonk_batching_challenge * inverse_vanishing_evals[1];

        // j-th shifted commitment is multiplied by −ρᵏ⁺ʲ⁻¹ and the shifted_scalar r⁻¹ ⋅ (1/(z−r) − ν/(z+r))
        let shifted_scalar = gemini_evaluation_challenge.inverse().unwrap()
            * (inverse_vanishing_evals[0]
                - shplonk_batching_challenge * inverse_vanishing_evals[1]);

        // let mut concatenation_scalars: Vec<P::ScalarField> = Vec::new();
        // if !concatenation_group_commitments.is_empty() {
        //     let concatenation_group_size: usize = concatenation_group_commitments[0].len();
        //     // The "real" size of polynomials in concatenation groups (i.e. the number of non-zero values)
        //     let mini_circuit_size: usize = (1 << log_circuit_size) / concatenation_group_size;
        //     let mut r_shift_pos: Fr = Fr(1);
        //     let mut r_shift_neg: Fr = Fr(1);
        //     let r_pow_minicircuit: Fr = gemini_evaluation_challenge.pow(mini_circuit_size);
        //     let r_neg_pow_minicircuit: Fr = (-gemini_evaluation_challenge).pow(mini_circuit_size);

        //     for i in 0..concatenation_group_size {
        //         // The l-th commitment in each concatenation group will be multiplied by  -ρᵏ⁺ᵐ⁺ˡ and
        //         // ( rˡˢ /(z−r) + ν ⋅ (-r)ˡˢ /(z+r) ) where s is the mini circuit size
        //         concatenation_scalars.push(r_shift_pos * inverse_vanishing_evals[0] +
        //                                    r_shift_neg * shplonk_batching_challenge *
        //                                        inverse_vanishing_evals[1]);

        //         r_shift_pos *= r_pow_minicircuit;
        //         r_shift_neg *= r_neg_pow_minicircuit;
        //     }
        // }

        // Place the commitments to prover polynomials in the commitments vector. Compute the evaluation of the
        // batched multilinear polynomial. Populate the vector of scalars for the final batch mul
        let mut batched_evaluation = P::ScalarField::zero();
        self.batch_multivariate_opening_claims(
            &multivariate_batching_challenge,
            &unshifted_scalar,
            &shifted_scalar,
            &mut commitments,
            &mut scalars,
            &mut batched_evaluation,
        );

        // Place the commitments to Gemini Aᵢ to the vector of commitments, compute the contributions from
        // Aᵢ(−r²ⁱ) for i=1, … , n−1 to the constant term accumulator, add corresponding scalars
        Self::batch_gemini_claims_received_from_prover(
            &log_circuit_size,
            &fold_commitments,
            &gemini_evaluations,
            &inverse_vanishing_evals,
            &shplonk_batching_challenge,
            &mut commitments,
            &mut scalars,
            &mut constant_term_accumulator,
        );

        // Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
        // - Compute A₀(r)
        let a_0_pos = Self::compute_gemini_batched_univariate_evaluation(
            &log_circuit_size,
            batched_evaluation,
            multivariate_challenge,
            gemini_eval_challenge_powers,
            gemini_evaluations.clone(),
        );
        // - Add A₀(r)/(z−r) to the constant term accumulator
        constant_term_accumulator += a_0_pos * inverse_vanishing_evals[0];
        // Add A₀(−r)/(z+r) to the constant term accumulator
        constant_term_accumulator +=
            gemini_evaluations[0] * shplonk_batching_challenge * inverse_vanishing_evals[1];

        // Finalize the batch opening claim
        commitments.push(P::G1Affine::generator());
        scalars.push(constant_term_accumulator);

        Ok(ShpleminiVerifierOpeningClaim {
            challenge: shplonk_evaluation_challenge,
            scalars,
            commitments,
        })
    }
    pub fn compute_gemini_batched_univariate_evaluation(
        num_variables: &u32,
        batched_eval_accumulator: P::ScalarField,
        evaluation_point: Vec<P::ScalarField>,
        challenge_powers: Vec<P::ScalarField>,
        fold_polynomial_evals: Vec<P::ScalarField>,
    ) -> P::ScalarField {
        let evals = fold_polynomial_evals;

        // Solve the sequence of linear equations
        for l in (1..=CONST_PROOF_SIZE_LOG_N).rev() {
            // Get r²⁽ˡ⁻¹⁾
            let challenge_power = &challenge_powers[l - 1];
            // Get uₗ₋₁
            let u = &evaluation_point[l - 1];
            let eval_neg = &evals[l - 1];
            // Compute the numerator
            let mut batched_eval_round_acc = (*challenge_power * batched_eval_accumulator
                + *challenge_power * batched_eval_accumulator)
                - (*eval_neg * (*challenge_power * (P::ScalarField::one() - *u) - *u));
            // Divide by the denominator
            batched_eval_round_acc *= (*challenge_power * (P::ScalarField::one() - *u) + *u)
                .inverse()
                .unwrap();

            if l <= *num_variables as usize {
                let batched_eval_accumulator = batched_eval_round_acc;
            }
        }

        batched_eval_accumulator
    }

    fn batch_multivariate_opening_claims(
        &self,
        multivariate_batching_challenge: &P::ScalarField,
        unshifted_scalar: &P::ScalarField,
        shifted_scalar: &P::ScalarField,
        commitments: &mut Vec<P::G1Affine>,
        scalars: &mut Vec<P::ScalarField>,
        batched_evaluation: &mut P::ScalarField,
        // concatenated_scalars: Vec<P::ScalarField>,
        // concatenation_group_commitments: &[Vec<P::G1Affine>],
        // concatenated_evaluations: &[P::ScalarField],
    ) {
        let mut current_batching_challenge = P::ScalarField::one();
        let unshifted_evaluations: PolyF<P::ScalarField> =
            Self::get_f_evaluations_shplemini(&self.memory.claimed_evaluations);
        let shifted_evaluations: PolyGShift<P::ScalarField> =
            Self::get_g_shift_evaluations_shplemini(&self.memory.claimed_evaluations);
        let unshifted_commitments = Self::get_f_comms_shplemini(&self.memory.verifier_commitments);
        let to_be_shifted_commitments =
            Self::get_g_shift_comms_shplemini(&self.memory.verifier_commitments);
        for (unshifted_commitment, unshifted_evaluation) in unshifted_commitments
            .iter()
            .zip(unshifted_evaluations.iter())
        {
            // Move unshifted commitments to the 'commitments' vector
            commitments.push(*unshifted_commitment);
            // Compute −ρⁱ ⋅ (1/(z−r) + ν/(z+r)) and place into 'scalars'
            scalars.push(-(*unshifted_scalar) * current_batching_challenge);
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
            commitments.push(*shifted_commitment);
            // Compute −ρ⁽ᵏ⁺ʲ⁾ ⋅ r⁻¹ ⋅ (1/(z−r) − ν/(z+r)) and place into 'scalars'
            scalars.push(-(*shifted_scalar) * current_batching_challenge);
            // Accumulate the evaluation of ∑ ρ⁽ᵏ⁺ʲ⁾ ⋅ f_shift at the sumcheck challenge
            *batched_evaluation += *shifted_evaluation * current_batching_challenge;
            // Update the batching challenge ρ
            current_batching_challenge *= *multivariate_batching_challenge;
        }

        // If we are performing an opening verification for the translator, add the contributions from the concatenation
        // commitments and evaluations to the result
        // assert_eq!(
        //     concatenated_evaluations.len(),
        //     concatenation_group_commitments.len()
        // );
        // if !concatenation_group_commitments.is_empty() {
        //     let concatenation_group_size = concatenation_group_commitments[0].len();
        //     let mut group_idx = 0;
        //     for concatenation_group_commitment in concatenation_group_commitments {
        //         for i in 0..concatenation_group_size {
        //             commitments.push(concatenation_group_commitment[i].clone());
        //             scalars.push(-current_batching_challenge * concatenated_scalars[i]);
        //         }
        //         // Accumulate the batched evaluations of concatenated polynomials
        //         *batched_evaluation +=
        //             concatenated_evaluations[group_idx] * current_batching_challenge;
        //         // Update the batching challenge ρ
        //         current_batching_challenge *= *multivariate_batching_challenge;
        //         group_idx += 1;
        //     }
        // }
    }
    fn batch_gemini_claims_received_from_prover(
        log_circuit_size: &u32,
        fold_commitments: &[P::G1Affine],
        gemini_evaluations: &[P::ScalarField],
        inverse_vanishing_evals: &[P::ScalarField],
        shplonk_batching_challenge: &P::ScalarField,
        commitments: &mut Vec<P::G1Affine>,
        scalars: &mut Vec<P::ScalarField>,
        constant_term_accumulator: &mut P::ScalarField,
    ) {
        // Initialize batching challenge as ν²
        let mut current_batching_challenge = shplonk_batching_challenge.square();
        for j in 0..CONST_PROOF_SIZE_LOG_N - 1 {
            // Compute the scaling factor  (ν²⁺ⁱ) / (z + r²⁽ⁱ⁺²⁾) for i = 0, … , d-2
            let mut scaling_factor = current_batching_challenge * inverse_vanishing_evals[j + 2];

            // Add Aᵢ(−r²ⁱ) for i = 1, … , n-1 to the constant term accumulator
            *constant_term_accumulator += scaling_factor * gemini_evaluations[j + 1];

            // Update the batching challenge
            current_batching_challenge *= *shplonk_batching_challenge;

            if j >= (*log_circuit_size as usize - 1) {
                scaling_factor = P::ScalarField::zero();
            }

            // Place the scaling factor to the 'scalars' vector
            scalars.push(-scaling_factor);
            // Move com(Aᵢ) to the 'commitments' vector
            commitments.push(fold_commitments[j]);
        }
    }
}
