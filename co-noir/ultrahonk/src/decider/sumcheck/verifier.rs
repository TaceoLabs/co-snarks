use super::SumcheckVerifierOutput;
use crate::{
    decider::{
        sumcheck::{round_prover::SumcheckRoundOutput, round_verifier::SumcheckVerifierRound},
        verifier::DeciderVerifier,
    },
    prelude::{GateSeparatorPolynomial, TranscriptFieldType},
    transcript::{Transcript, TranscriptHasher},
    types::NUM_ALL_ENTITIES,
    verifier::HonkVerifyResult,
    CONST_PROOF_SIZE_LOG_N,
};
use ark_ff::{One, Zero};
use co_builder::prelude::RowDisablingPolynomial;
use co_builder::prelude::{HonkCurve, ZeroKnowledge};

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    DeciderVerifier<P, H>
{
    pub(crate) fn sumcheck_verify<const SIZE: usize>(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        has_zk: ZeroKnowledge,
        padding_indicator_array: &[P::ScalarField; CONST_PROOF_SIZE_LOG_N],
    ) -> HonkVerifyResult<SumcheckVerifierOutput<P::ScalarField>> {
        tracing::trace!("Sumcheck verify");

        let mut verified: bool = true;

        // Pad gate challenges for Protogalaxy DeciderVerifier and AVM
        self.pad_gate_challenges();

        let mut gate_separators = GateSeparatorPolynomial::new_without_products(
            self.memory.relation_parameters.gate_challenges.to_owned(),
        );

        let mut sum_check_round = SumcheckVerifierRound::<P>::default();
        let mut libra_challenge = P::ScalarField::one();
        if has_zk == ZeroKnowledge::Yes {
            // If running zero-knowledge sumcheck the target total sum is corrected by the claimed sum of libra masking
            // multivariate over the hypercube

            let libra_total_sum =
                transcript.receive_fr_from_prover::<P>("Libra:Sum".to_string())?;
            libra_challenge = transcript.get_challenge::<P>("Libra:Challenge".to_string());
            sum_check_round.target_total_sum += libra_total_sum * libra_challenge;
        }

        let mut multivariate_challenge = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for (round_idx, &padding_value) in padding_indicator_array.iter().enumerate() {
            tracing::trace!("Sumcheck verify round {}", round_idx);
            let round_univariate_label = format!("Sumcheck:univariate_{}", round_idx);

            let evaluations =
                transcript.receive_fr_array_from_verifier::<P, SIZE>(round_univariate_label)?;
            let round_univariate = SumcheckRoundOutput { evaluations };

            let round_challenge =
                transcript.get_challenge::<P>(format!("Sumcheck:u_{}", round_idx));

            let checked = sum_check_round.check_sum(&round_univariate, padding_value);
            verified = verified && checked;

            multivariate_challenge.push(round_challenge);

            sum_check_round.compute_next_target_sum(
                &round_univariate,
                round_challenge,
                padding_value,
            );
            gate_separators.partially_evaluate_with_padding(
                round_challenge,
                padding_indicator_array[round_idx],
            );
        }

        // Final round
        let transcript_evaluations = transcript.receive_fr_vec_from_verifier::<P>(
            "Sumcheck:evaluations".to_string(),
            NUM_ALL_ENTITIES,
        )?;

        for (eval, &transcript_eval) in self
            .memory
            .claimed_evaluations
            .iter_mut()
            .zip(transcript_evaluations.iter())
        {
            *eval = transcript_eval;
        }

        // Evaluate the Honk relation at the point (u_0, ..., u_{d-1}) using claimed evaluations of prover polynomials.

        let mut full_honk_purported_value =
            SumcheckVerifierRound::<P>::compute_full_relation_purported_value(
                &self.memory.claimed_evaluations,
                &self.memory.relation_parameters,
                gate_separators,
            );

        // For ZK Flavors: the evaluation of the Row Disabling Polynomial at the sumcheck challenge
        let claimed_libra_evaluation = if has_zk == ZeroKnowledge::Yes {
            let libra_evaluation =
                transcript.receive_fr_from_prover::<P>("Libra:claimed_evaluation".to_string())?;
            // No recursive flavor, otherwise we need to make some modifications to the following

            let correcting_factor = RowDisablingPolynomial::evaluate_at_challenge_with_padding(
                &multivariate_challenge,
                padding_indicator_array,
            );

            full_honk_purported_value =
                full_honk_purported_value * correcting_factor + libra_evaluation * libra_challenge;
            Some(libra_evaluation)
        } else {
            None
        };

        let checked = full_honk_purported_value == sum_check_round.target_total_sum;
        verified = verified && checked;
        Ok(SumcheckVerifierOutput {
            multivariate_challenge,
            verified,
            claimed_libra_evaluation,
        })
    }

    fn pad_gate_challenges(&mut self) {
        if self.memory.relation_parameters.gate_challenges.len() < CONST_PROOF_SIZE_LOG_N {
            let zero = P::ScalarField::zero();
            for _ in self.memory.relation_parameters.gate_challenges.len()..CONST_PROOF_SIZE_LOG_N {
                self.memory.relation_parameters.gate_challenges.push(zero);
            }
        }
    }
}
