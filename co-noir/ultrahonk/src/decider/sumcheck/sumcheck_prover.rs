use crate::decider::decider_prover::Decider;
use crate::decider::sumcheck::SumcheckOutput;
use crate::decider::sumcheck::sumcheck_round_prover::SumcheckProverRound;
use crate::decider::types::{ClaimedEvaluations, GateSeparatorPolynomial, PartiallyEvaluatePolys};
use crate::plain_prover_flavour::{PlainProverFlavour, UnivariateTrait};
use crate::types::AllEntities;
use crate::{CONST_PROOF_SIZE_LOG_N, Utils};
use ark_ff::Zero;
use co_builder::HonkProofResult;
use co_builder::prelude::{HonkCurve, RowDisablingPolynomial};
use co_builder::prelude::{Polynomial, ProverCrs};
use common::transcript::TranscriptFieldType;
use common::transcript::{Transcript, TranscriptHasher};

use super::zk_data::ZKSumcheckData;

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> Decider<P, H, L>
{
    pub(crate) fn partially_evaluate_init(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<P::ScalarField, L>,
        polys: &AllEntities<Vec<P::ScalarField>, L>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate init");

        // Barretenberg uses multithreading here
        for (poly_src, poly_des) in polys.iter().zip(partially_evaluated_poly.iter_mut()) {
            let min_size = round_size.min(poly_src.len());
            for i in (0..min_size).step_by(2) {
                let final_value = if i + 1 >= min_size {
                    P::ScalarField::zero()
                } else {
                    poly_src[i + 1]
                };
                poly_des[i >> 1] = poly_src[i] + (final_value - poly_src[i]) * round_challenge;
            }
        }
    }

    pub(crate) fn partially_evaluate_inplace(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<P::ScalarField, L>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate inplace");

        // Barretenberg uses multithreading here

        for poly in partially_evaluated_poly.iter_mut() {
            let min_size = round_size.min(poly.len());
            for i in (0..min_size).step_by(2) {
                let final_value = if i + 1 >= min_size {
                    P::ScalarField::zero()
                } else {
                    poly[i + 1]
                };
                poly[i >> 1] = poly[i] + (final_value - poly[i]) * round_challenge;
            }
        }
    }

    fn add_evals_to_transcript(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        evaluations: &ClaimedEvaluations<P::ScalarField, L>,
    ) {
        tracing::trace!("Add Evals to Transcript");
        transcript.send_fr_iter_to_verifier::<P, _>(
            "Sumcheck:evaluations".to_string(),
            evaluations.iter(),
        );
    }

    fn extract_claimed_evaluations(
        partially_evaluated_polynomials: PartiallyEvaluatePolys<P::ScalarField, L>,
    ) -> ClaimedEvaluations<P::ScalarField, L> {
        let mut multivariate_evaluations = ClaimedEvaluations::default();

        #[expect(unused_mut)] // TACEO TODO: This is for the linter, remove once its fixed...
        for (src, mut des) in partially_evaluated_polynomials
            .into_iterator()
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
    ) -> SumcheckOutput<P::ScalarField, L> {
        tracing::trace!("Sumcheck prove");

        let multivariate_n = circuit_size;
        let multivariate_d = Utils::get_msb64(multivariate_n as u64);

        let mut sum_check_round =
            SumcheckProverRound::<P::ScalarField, L>::new(multivariate_n as usize);

        let mut gate_separators = GateSeparatorPolynomial::new(
            self.memory.gate_challenges.to_owned(),
            multivariate_d as usize,
        );

        let mut multivariate_challenge = Vec::with_capacity(multivariate_d as usize);
        let round_idx = 0;

        tracing::trace!("Sumcheck prove round {}", round_idx);
        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns.
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
            round_univariate.evaluations_as_ref(),
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
                round_univariate.evaluations_as_ref(),
            );
            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{round_idx}"));
            multivariate_challenge.push(round_challenge);
            // Prepare sumcheck book-keeping table for the next round
            Self::partially_evaluate_inplace(
                &mut partially_evaluated_polys,
                sum_check_round.round_size,
                &round_challenge,
            );
            gate_separators.partially_evaluate(round_challenge);
            sum_check_round.round_size >>= 1;
        }

        // Zero univariates are used to pad the proof to the fixed size CONST_PROOF_SIZE_LOG_N.
        let zero_univariate = L::SumcheckRoundOutput::default();
        for idx in multivariate_d as usize..CONST_PROOF_SIZE_LOG_N {
            transcript.send_fr_iter_to_verifier::<P, _>(
                format!("Sumcheck:univariate_{idx}"),
                zero_univariate.evaluations_as_ref(),
            );
            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{idx}"));
            multivariate_challenge.push(round_challenge);
        }

        // Claimed evaluations of Prover polynomials are extracted and added to the transcript. When Flavor has ZK, the
        // evaluations of all witnesses are masked.
        let multivariate_evaluations = Self::extract_claimed_evaluations(partially_evaluated_polys);
        Self::add_evals_to_transcript(transcript, &multivariate_evaluations);

        SumcheckOutput {
            _claimed_evaluations: multivariate_evaluations,
            challenges: multivariate_challenge,
            claimed_libra_evaluation: None,
            round_univariates: None,
            round_univariate_evaluations: None,
        }
    }

    pub fn sumcheck_prove_zk<const VIRTUAL_LOG_N: usize>(
        &self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        zk_sumcheck_data: &mut ZKSumcheckData<P>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<SumcheckOutput<P::ScalarField, L>> {
        tracing::trace!("Sumcheck prove");
        let mut eval_domain = Vec::new();
        let mut round_univariates: Vec<Polynomial<P::ScalarField>> = Vec::new();
        let mut round_univariate_evaluations: Vec<[P::ScalarField; 3]> = Vec::new();
        if L::IS_GRUMPKIN_FLAVOUR {
            for i in 0..L::BATCHED_RELATION_PARTIAL_LENGTH_ZK {
                eval_domain.push(P::ScalarField::from(i as u32));
            }
        } else {
            // Ensure that the length of Sumcheck Round Univariates does not exceed the length of Libra masking
            // polynomials.
            assert!(L::BATCHED_RELATION_PARTIAL_LENGTH_ZK <= P::LIBRA_UNIVARIATES_LENGTH);
        }
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
        let mut round_univariate = sum_check_round.compute_univariate_zk::<P>(
            round_idx,
            &self.memory.relation_parameters,
            &gate_separators,
            &self.memory.alphas,
            &self.memory.polys,
            zk_sumcheck_data,
            &mut row_disabling_polynomial,
        );

        if L::IS_GRUMPKIN_FLAVOUR {
            Self::commit_to_round_univariate(
                round_idx,
                &round_univariate,
                &eval_domain,
                transcript,
                crs,
                &mut round_univariates,
                &mut round_univariate_evaluations,
            )?;
        } else {
            // Place the evaluations of the round univariate into transcript.
            transcript.send_fr_iter_to_verifier::<P, _>(
                "Sumcheck:univariate_0".to_string(),
                round_univariate.evaluations_as_ref(),
            );
        }
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

            round_univariate = sum_check_round.compute_univariate_zk::<P>(
                round_idx,
                &self.memory.relation_parameters,
                &gate_separators,
                &self.memory.alphas,
                &partially_evaluated_polys,
                zk_sumcheck_data,
                &mut row_disabling_polynomial,
            );
            if L::IS_GRUMPKIN_FLAVOUR {
                // Compute monomial coefficients of the round univariate, commit to it, populate an auxiliary structure
                // needed in the PCS round
                Self::commit_to_round_univariate(
                    round_idx,
                    &round_univariate,
                    &eval_domain,
                    transcript,
                    crs,
                    &mut round_univariates,
                    &mut round_univariate_evaluations,
                )?;
            } else {
                // Place the evaluations of the round univariate into transcript.
                transcript.send_fr_iter_to_verifier::<P, _>(
                    format!("Sumcheck:univariate_{round_idx}"),
                    round_univariate.evaluations_as_ref(),
                );
            }
            let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{round_idx}"));
            multivariate_challenge.push(round_challenge);
            // Prepare sumcheck book-keeping table for the next round
            Self::partially_evaluate_inplace(
                &mut partially_evaluated_polys,
                sum_check_round.round_size,
                &round_challenge,
            );
            // Prepare evaluation masking and libra structures for the next round (for ZK Flavors)
            zk_sumcheck_data.update_zk_sumcheck_data(round_challenge, round_idx);
            row_disabling_polynomial.update_evaluations(round_challenge, round_idx);

            gate_separators.partially_evaluate(round_challenge);
            sum_check_round.round_size >>= 1;
        }
        if L::IS_GRUMPKIN_FLAVOUR {
            round_univariate_evaluations[multivariate_d as usize - 1][2] =
                round_univariate.evaluate(multivariate_challenge[multivariate_d as usize - 1]);
        }
        tracing::trace!("Completed {multivariate_d} rounds of sumcheck");
        // Zero univariates are used to pad the proof to the fixed size CONST_PROOF_SIZE_LOG_N.
        let zero_univariate = L::SumcheckRoundOutputZK::default();
        for idx in multivariate_d as usize..VIRTUAL_LOG_N {
            if L::IS_GRUMPKIN_FLAVOUR {
                let commitment = Utils::commit(zero_univariate.evaluations_as_ref(), crs)?;
                transcript.send_point_to_verifier::<P>(
                    format!("Sumcheck:univariate_comm_{idx}"),
                    commitment.into(),
                );
                transcript.send_fr_to_verifier::<P>(
                    format!("Sumcheck:univariate_{idx}_eval_0"),
                    P::ScalarField::zero(),
                );
                transcript.send_fr_to_verifier::<P>(
                    format!("Sumcheck:univariate_{idx}_eval_1"),
                    P::ScalarField::zero(),
                );
            } else {
                transcript.send_fr_iter_to_verifier::<P, _>(
                    format!("Sumcheck:univariate_{idx}"),
                    zero_univariate.evaluations_as_ref(),
                );
            }
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

        if L::IS_GRUMPKIN_FLAVOUR {
            Ok(SumcheckOutput {
                _claimed_evaluations: multivariate_evaluations,
                challenges: multivariate_challenge,
                claimed_libra_evaluation: Some(libra_evaluation),
                round_univariates: Some(round_univariates),
                round_univariate_evaluations: Some(round_univariate_evaluations),
            })
        } else {
            Ok(SumcheckOutput {
                _claimed_evaluations: multivariate_evaluations,
                challenges: multivariate_challenge,
                claimed_libra_evaluation: Some(libra_evaluation),
                round_univariates: None,
                round_univariate_evaluations: None,
            })
        }
    }
    // this is a helper function for committing in Grumpkin Flavours
    fn commit_to_round_univariate(
        round_idx: usize,
        round_univariate: &L::SumcheckRoundOutputZK<P::ScalarField>,
        eval_domain: &[P::ScalarField],
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        round_univariates: &mut Vec<Polynomial<P::ScalarField>>,
        round_univariate_evaluations: &mut Vec<[P::ScalarField; 3]>,
    ) -> HonkProofResult<()> {
        // Transform to monomial form and commit to it
        let round_poly_monomial = Polynomial::interpolate_from_evals(
            eval_domain,
            round_univariate.evaluations_as_ref(),
            L::BATCHED_RELATION_PARTIAL_LENGTH_ZK,
        );

        let commitment = Utils::commit(round_poly_monomial.as_ref(), crs)?;
        transcript.send_point_to_verifier::<P>(
            format!("Sumcheck:univariate_comm_{round_idx}"),
            commitment.into(),
        );

        // Store round univariate in monomial, as it is required by Shplemini
        round_univariates.push(round_poly_monomial);

        // Send the evaluations of the round univariate at 0 and 1
        transcript.send_fr_to_verifier::<P>(
            format!("Sumcheck:univariate_{round_idx}_eval_0"),
            round_univariate.value_at(0),
        );
        transcript.send_fr_to_verifier::<P>(
            format!("Sumcheck:univariate_{round_idx}_eval_1"),
            round_univariate.value_at(1),
        );

        // Store the evaluations to be used by ShpleminiProver
        round_univariate_evaluations.push([
            round_univariate.value_at(0),
            round_univariate.value_at(1),
            P::ScalarField::zero(),
        ]);
        if round_idx > 0 {
            round_univariate_evaluations[round_idx - 1][2] =
                round_univariate.value_at(0) + round_univariate.value_at(1);
        }
        Ok(())
    }
}
