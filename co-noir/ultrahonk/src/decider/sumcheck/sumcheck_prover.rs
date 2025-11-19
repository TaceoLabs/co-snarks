use ark_ff::One;
use ark_ff::Zero;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::polynomials::polynomial::RowDisablingPolynomial;
use co_noir_common::transcript::{Transcript, TranscriptHasher};

use crate::Utils;
use crate::decider::decider_prover::Decider;
use crate::decider::sumcheck::SumcheckOutput;
use crate::decider::sumcheck::sumcheck_round_prover::{SumcheckProverRound, SumcheckRoundOutput};
use crate::decider::sumcheck::zk_data::ZKSumcheckData;
use crate::decider::types::{
    BATCHED_RELATION_PARTIAL_LENGTH_ZK, ClaimedEvaluations, GateSeparatorPolynomial,
    PartiallyEvaluatePolys,
};
use crate::types::AllEntities;

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Decider<P, H> {
    pub(crate) fn partially_evaluate_init(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<P::ScalarField>,
        polys: &AllEntities<Vec<P::ScalarField>>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate init");

        // Barretenberg uses multithreading here
        for (poly_src, poly_des) in polys.iter().zip(partially_evaluated_poly.iter_mut()) {
            for i in (0..round_size).step_by(2) {
                poly_des[i >> 1] = poly_src[i] + (poly_src[i + 1] - poly_src[i]) * round_challenge;
            }
        }
    }

    pub(crate) fn partially_evaluate_inplace(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<P::ScalarField>,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate inplace");

        // Barretenberg uses multithreading here
        for poly in partially_evaluated_poly.iter_mut() {
            let limit = poly.len();
            for i in (0..limit).step_by(2) {
                poly[i >> 1] = poly[i] + (poly[i + 1] - poly[i]) * round_challenge;
            }

            poly.truncate(limit / 2 + limit % 2);
            if poly.len() < 2 {
                poly.push(P::ScalarField::zero());
            }
        }
    }

    fn add_evals_to_transcript(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) {
        tracing::trace!("Add Evals to Transcript");

        transcript.send_fr_iter_to_verifier::<P, _>(
            "Sumcheck:evaluations".to_string(),
            evaluations.iter(),
        );
    }

    fn extract_claimed_evaluations(
        partially_evaluated_polynomials: PartiallyEvaluatePolys<P::ScalarField>,
    ) -> ClaimedEvaluations<P::ScalarField> {
        let mut multivariate_evaluations = ClaimedEvaluations::default();

        #[expect(unused_mut)] // TACEO TODO: This is for the linter, remove once its fixed...
        for (src, mut des) in partially_evaluated_polynomials
            .into_iter()
            .zip(multivariate_evaluations.iter_mut())
        {
            *des = src[0];
        }

        multivariate_evaluations
    }

    pub(crate) fn sumcheck_prove(
        &self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        virtual_log_n: usize,
    ) -> SumcheckOutput<P::ScalarField> {
        tracing::trace!("Sumcheck prove");

        let multivariate_n = circuit_size;
        let multivariate_d = Utils::get_msb64(multivariate_n as u64);

        let mut sum_check_round = SumcheckProverRound::new(multivariate_n as usize);

        let mut gate_separators = GateSeparatorPolynomial::new(
            self.memory.gate_challenges.to_owned(),
            multivariate_d as usize,
        );

        let mut multivariate_challenge = Vec::with_capacity(virtual_log_n);
        let round_idx = 0;

        tracing::trace!("Sumcheck prove round {}", round_idx);

        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns. When the Flavor has ZK,
        // compute_univariate also takes into account the zk_sumcheck_data.
        let round_univariate = sum_check_round.compute_univariate::<P>(
            round_idx,
            &self.memory.relation_parameters,
            &gate_separators,
            &self.memory.alphas,
            &self.memory.polys,
        );

        // Place the evaluations of the round univariate into transcript.
        transcript.send_fr_iter_to_verifier::<P, _>(
            "Sumcheck:univariate_0".to_string(),
            &round_univariate.evaluations,
        );
        let round_challenge = transcript.get_challenge::<P>("Sumcheck:u_0".to_string());
        multivariate_challenge.push(round_challenge);

        // Prepare sumcheck book-keeping table for the next round
        let mut partially_evaluated_polys =
            PartiallyEvaluatePolys::new(multivariate_n as usize >> 1);
        Self::partially_evaluate_init(
            &mut partially_evaluated_polys,
            &self.memory.polys,
            multivariate_n as usize,
            &round_challenge,
        );
        gate_separators.partially_evaluate(round_challenge);
        sum_check_round.round_size >>= 1; // AZTEC TODO(#224)(Cody): Maybe partially_evaluate should do this and
        // release memory?        // All but final round
        // We operate on partially_evaluated_polynomials in place.

        for round_idx in 1..multivariate_d as usize {
            tracing::trace!("Sumcheck prove round {}", round_idx);
            // Write the round univariate to the transcript

            let round_univariate = sum_check_round.compute_univariate::<P>(
                round_idx,
                &self.memory.relation_parameters,
                &gate_separators,
                &self.memory.alphas,
                &partially_evaluated_polys,
            );
            // Place the evaluations of the round univariate into transcript.
            transcript.send_fr_iter_to_verifier::<P, _>(
                format!("Sumcheck:univariate_{round_idx}"),
                &round_univariate.evaluations,
            );
            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{round_idx}"));
            multivariate_challenge.push(round_challenge);
            // Prepare sumcheck book-keeping table for the next round
            Self::partially_evaluate_inplace(&mut partially_evaluated_polys, &round_challenge);
            gate_separators.partially_evaluate(round_challenge);
            sum_check_round.round_size >>= 1;
        }
        let mut virtual_gate_separator = GateSeparatorPolynomial::construct_virtual_separator(
            &self.memory.gate_challenges,
            &multivariate_challenge,
        );
        // If required, extend prover's multilinear polynomials in `multivariate_d` variables by zero to get multilinear
        // polynomials in `virtual_log_n` variables.
        for k in multivariate_d as usize..virtual_log_n {
            // Compute the contribution from the extensions by zero. It is sufficient to evaluate the main constraint at
            // `MAX_PARTIAL_RELATION_LENGTH` points.
            let virtual_round_univariate = SumcheckProverRound::compute_virtual_contribution::<P>(
                &partially_evaluated_polys,
                &self.memory.relation_parameters,
                &virtual_gate_separator,
                &self.memory.alphas,
            );
            transcript.send_fr_iter_to_verifier::<P, _>(
                format!("Sumcheck:univariate_{k}"),
                &virtual_round_univariate.evaluations,
            );

            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{k}"));
            multivariate_challenge.push(round_challenge);

            // Update the book-keeping table of partial evaluations of the prover polynomials extended by zero.
            for poly in partially_evaluated_polys.iter_mut() {
                // Avoid bad access if polynomials are set to be of size 0, which can happen in AVM.
                if !poly.is_empty() {
                    poly[0] *= P::ScalarField::one() - round_challenge;
                }
            }
            virtual_gate_separator.partially_evaluate(round_challenge);
        }

        // Claimed evaluations of Prover polynomials are extracted and added to the transcript. When Flavor has ZK, the
        // evaluations of all witnesses are masked.
        let multivariate_evaluations = Self::extract_claimed_evaluations(partially_evaluated_polys);
        Self::add_evals_to_transcript(transcript, &multivariate_evaluations);

        SumcheckOutput {
            challenges: multivariate_challenge,
            claimed_libra_evaluation: None,
        }
    }

    pub(crate) fn sumcheck_prove_zk(
        &self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        zk_sumcheck_data: &mut ZKSumcheckData<P>,
        virtual_log_n: usize,
    ) -> SumcheckOutput<P::ScalarField> {
        tracing::trace!("Sumcheck prove");
        // Ensure that the length of Sumcheck Round Univariates does not exceed the length of Libra masking
        // polynomials.
        assert!(BATCHED_RELATION_PARTIAL_LENGTH_ZK <= P::LIBRA_UNIVARIATES_LENGTH);

        let multivariate_n = circuit_size;
        let multivariate_d = Utils::get_msb64(multivariate_n as u64);

        let mut sum_check_round = SumcheckProverRound::new(multivariate_n as usize);
        let mut row_disabling_polynomial = RowDisablingPolynomial::<P::ScalarField>::default();
        let mut gate_separators = GateSeparatorPolynomial::new(
            self.memory.gate_challenges.to_owned(),
            multivariate_d as usize,
        );

        let mut multivariate_challenge = Vec::with_capacity(multivariate_d as usize);
        let round_idx = 0;

        tracing::trace!("Sumcheck prove round {}", round_idx);

        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns. When the Flavor has ZK,
        // compute_univariate also takes into account the zk_sumcheck_data.
        let round_univariate = sum_check_round.compute_univariate_zk::<P>(
            round_idx,
            &self.memory.relation_parameters,
            &gate_separators,
            &self.memory.alphas,
            &self.memory.polys,
            zk_sumcheck_data,
            &mut row_disabling_polynomial,
        );

        // Place the evaluations of the round univariate into transcript.
        transcript.send_fr_iter_to_verifier::<P, _>(
            "Sumcheck:univariate_0".to_string(),
            &round_univariate.evaluations,
        );
        let round_challenge = transcript.get_challenge::<P>("Sumcheck:u_0".to_string());
        multivariate_challenge.push(round_challenge);

        // Prepare sumcheck book-keeping table for the next round
        let mut partially_evaluated_polys =
            PartiallyEvaluatePolys::new(multivariate_n as usize >> 1);
        Self::partially_evaluate_init(
            &mut partially_evaluated_polys,
            &self.memory.polys,
            multivariate_n as usize,
            &round_challenge,
        );
        zk_sumcheck_data.update_zk_sumcheck_data(round_challenge, round_idx);

        row_disabling_polynomial.update_evaluations(round_challenge, round_idx);

        gate_separators.partially_evaluate(round_challenge);
        sum_check_round.round_size >>= 1; // AZTEC TODO(#224)(Cody): Maybe partially_evaluate should do this and
        // release memory?        // All but final round
        // We operate on partially_evaluated_polynomials in place.
        for round_idx in 1..multivariate_d as usize {
            tracing::trace!("Sumcheck prove round {}", round_idx);
            // Write the round univariate to the transcript

            let round_univariate = sum_check_round.compute_univariate_zk::<P>(
                round_idx,
                &self.memory.relation_parameters,
                &gate_separators,
                &self.memory.alphas,
                &partially_evaluated_polys,
                zk_sumcheck_data,
                &mut row_disabling_polynomial,
            );

            // Place the evaluations of the round univariate into transcript.
            transcript.send_fr_iter_to_verifier::<P, _>(
                format!("Sumcheck:univariate_{round_idx}"),
                &round_univariate.evaluations,
            );
            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{round_idx}"));
            multivariate_challenge.push(round_challenge);
            // Prepare sumcheck book-keeping table for the next round
            Self::partially_evaluate_inplace(&mut partially_evaluated_polys, &round_challenge);
            // Prepare evaluation masking and libra structures for the next round (for ZK Flavors)
            zk_sumcheck_data.update_zk_sumcheck_data(round_challenge, round_idx);
            row_disabling_polynomial.update_evaluations(round_challenge, round_idx);

            gate_separators.partially_evaluate(round_challenge);
            sum_check_round.round_size >>= 1;
        }
        tracing::trace!("Completed {multivariate_d} rounds of sumcheck");

        // Zero univariates are used to pad the proof to the fixed size CONST_PROOF_SIZE_LOG_N.
        let zero_univariate =
            SumcheckRoundOutput::<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::default();
        for idx in multivariate_d as usize..virtual_log_n {
            transcript.send_fr_iter_to_verifier::<P, _>(
                format!("Sumcheck:univariate_{idx}"),
                &zero_univariate.evaluations,
            );
            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{idx}"));
            multivariate_challenge.push(round_challenge);
        }

        // Claimed evaluations of Prover polynomials are extracted and added to the transcript. When Flavor has ZK, the
        // evaluations of all witnesses are masked.
        let multivariate_evaluations = Self::extract_claimed_evaluations(partially_evaluated_polys);
        Self::add_evals_to_transcript(transcript, &multivariate_evaluations);

        // The evaluations of Libra uninvariates at \f$ g_0(u_0), \ldots, g_{d-1} (u_{d-1}) \f$ are added to the
        // transcript.
        let mut libra_evaluation = zk_sumcheck_data.constant_term;
        for libra_eval in zk_sumcheck_data.libra_evaluations.iter() {
            libra_evaluation += libra_eval;
        }
        transcript
            .send_fr_to_verifier::<P>("Libra:claimed_evaluation".to_string(), libra_evaluation);

        SumcheckOutput {
            challenges: multivariate_challenge,
            claimed_libra_evaluation: Some(libra_evaluation),
        }
    }
}
