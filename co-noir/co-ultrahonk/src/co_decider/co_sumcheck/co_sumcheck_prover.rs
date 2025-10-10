use super::{SumcheckOutput, zk_data::SharedZKSumcheckData};
use crate::co_decider::types::ClaimedEvaluationsNonOpened;
use crate::mpc_prover_flavour::MPCProverFlavour;
use crate::mpc_prover_flavour::SharedUnivariateTrait;
use crate::{
    CONST_PROOF_SIZE_LOG_N,
    co_decider::{
        co_decider_prover::CoDecider,
        co_sumcheck::co_sumcheck_round::SumcheckRound,
        types::{ClaimedEvaluations, PartiallyEvaluatePolys},
    },
    types::AllEntities,
};
use ark_ff::Zero;
use co_noir_common::CoUtils;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::polynomials::polynomial::RowDisablingPolynomial;
use co_noir_common::polynomials::shared_polynomial::SharedPolynomial;
use co_noir_common::transcript::{Transcript, TranscriptHasher};
use co_noir_common::transcript_mpc::TranscriptRef;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::Utils;
use ultrahonk::plain_prover_flavour::UnivariateTrait;
use ultrahonk::prelude::GateSeparatorPolynomial;

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
impl<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, P>,
    N: Network,
    L: MPCProverFlavour,
> CoDecider<'_, T, P, H, N, L>
{
    pub(crate) fn partially_evaluate_init(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<T, P, L>,
        polys: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate init");

        // Barretenberg uses multithreading here

        for (poly_src, poly_des) in polys
            .public_iter()
            .zip(partially_evaluated_poly.public_iter_mut())
        {
            let min_size = round_size.min(poly_src.len()); // We need to do this due to some different sizes in the Translator polys
            for i in (0..min_size).step_by(2) {
                let final_value = if i + 1 >= min_size {
                    P::ScalarField::zero()
                } else {
                    poly_src[i + 1]
                };
                poly_des[i >> 1] = poly_src[i] + (final_value - poly_src[i]) * round_challenge;
            }
        }

        for (poly_src, poly_des) in polys
            .shared_iter()
            .zip(partially_evaluated_poly.shared_iter_mut())
        {
            let min_size = round_size.min(poly_src.len());
            for i in (0..min_size).step_by(2) {
                let final_value = if i + 1 >= min_size {
                    T::ArithmeticShare::default()
                } else {
                    poly_src[i + 1]
                };
                let tmp = T::sub(final_value, poly_src[i]);
                let tmp = T::mul_with_public(*round_challenge, tmp);
                poly_des[i >> 1] = T::add(poly_src[i], tmp);
            }
        }
    }

    pub(crate) fn partially_evaluate_inplace(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<T, P, L>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate inplace");

        // Barretenberg uses multithreading here

        for poly in partially_evaluated_poly.public_iter_mut() {
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

        for poly in partially_evaluated_poly.shared_iter_mut() {
            let min_size = round_size.min(poly.len());
            for i in (0..min_size).step_by(2) {
                let final_value = if i + 1 >= min_size {
                    T::ArithmeticShare::default()
                } else {
                    poly[i + 1]
                };
                let tmp = T::sub(final_value, poly[i]);
                let tmp = T::mul_with_public(*round_challenge, tmp);
                poly[i >> 1] = T::add(poly[i], tmp);
            }
        }
    }

    fn add_evals_to_transcript(
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
        evaluations: &ClaimedEvaluations<P::ScalarField, L>,
    ) {
        tracing::trace!("Add Evals to Transcript");

        transcript.send_fr_iter_to_verifier::<P, _>(
            "Sumcheck:evaluations".to_string(),
            evaluations.iter(),
        );
    }

    fn extract_claimed_evaluations(
        net: &N,
        state: &mut T::State,
        partially_evaluated_polynomials: PartiallyEvaluatePolys<T, P, L>,
    ) -> HonkProofResult<ClaimedEvaluations<P::ScalarField, L>> {
        let mut multivariate_evaluations = ClaimedEvaluations::default();

        for (src, des) in partially_evaluated_polynomials
            .public_iter()
            .zip(multivariate_evaluations.public_iter_mut())
        {
            *des = src[0];
        }

        let shared = partially_evaluated_polynomials
            .into_shared_iter()
            .map(|x| x[0])
            .collect::<Vec<_>>();

        let opened = T::open_many(&shared, net, state)?;

        for (src, des) in opened
            .into_iter()
            .zip(multivariate_evaluations.shared_iter_mut())
        {
            *des = src;
        }

        Ok(multivariate_evaluations)
    }

    fn extract_claimed_evaluations_non_opened(
        partially_evaluated_polynomials: PartiallyEvaluatePolys<T, P, L>,
    ) -> HonkProofResult<ClaimedEvaluationsNonOpened<T, P, L>> {
        let mut multivariate_evaluations = ClaimedEvaluationsNonOpened::<T, P, L>::default();

        for (src, des) in partially_evaluated_polynomials
            .public_iter()
            .zip(multivariate_evaluations.public_iter_mut())
        {
            *des = src[0];
        }

        let shared = partially_evaluated_polynomials
            .into_shared_iter()
            .map(|x| x[0])
            .collect::<Vec<_>>();

        for (src, des) in shared
            .into_iter()
            .zip(multivariate_evaluations.shared_iter_mut())
        {
            *des = src;
        }

        Ok(multivariate_evaluations)
    }

    pub(crate) fn sumcheck_prove(
        &mut self,
        transcript: &mut TranscriptRef<TranscriptFieldType, T, P, H>,
        circuit_size: u32,
    ) -> HonkProofResult<SumcheckOutput<T, P>> {
        tracing::trace!("Sumcheck prove");

        let multivariate_n = circuit_size;
        let multivariate_d = Utils::get_msb64(multivariate_n as u64);

        let mut sum_check_round = SumcheckRound::new(multivariate_n as usize);

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
        let round_univariate = sum_check_round.compute_univariate::<T, P, N, L>(
            self.net,
            self.state,
            round_idx,
            &self.memory.relation_parameters,
            &self.memory.alphas,
            &gate_separators,
            &self.memory.polys,
        )?;

        let round_challenge = match transcript {
            TranscriptRef::Plain(transcript) => {
                let round_univariate =
                    T::open_many(round_univariate.evaluations_as_ref(), self.net, self.state)?;

                // Place the evaluations of the round univariate into transcript.
                transcript.send_fr_iter_to_verifier::<P, _>(
                    "Sumcheck:univariate_0".to_string(),
                    &round_univariate,
                );
                transcript.get_challenge::<P>("Sumcheck:u_0".to_string())
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                // Place the evaluations of the round univariate into transcript.
                transcript_rep3.send_fr_iter_to_verifier_shared(
                    "Sumcheck:univariate_0".to_string(),
                    round_univariate.evaluations_as_ref(),
                );
                transcript_rep3.get_challenge("Sumcheck:u_0".to_string(), self.net, self.state)?
            }
        };
        multivariate_challenge.push(round_challenge);

        // Prepare sumcheck book-keeping table for the next round
        let mut partially_evaluated_polys =
            PartiallyEvaluatePolys::<T, P, L>::new(multivariate_n as usize >> 1);
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
            // Write the round univariate to the transcript
            tracing::trace!("Sumcheck prove round {}", round_idx);

            let round_univariate = sum_check_round.compute_univariate::<T, P, N, L>(
                self.net,
                self.state,
                round_idx,
                &self.memory.relation_parameters,
                &self.memory.alphas,
                &gate_separators,
                &partially_evaluated_polys,
            )?;

            // Place the evaluations of the round univariate into transcript.
            let round_challenge = match transcript {
                TranscriptRef::Plain(transcript) => {
                    let round_univariate =
                        T::open_many(round_univariate.evaluations_as_ref(), self.net, self.state)?;
                    transcript.send_fr_iter_to_verifier::<P, _>(
                        format!("Sumcheck:univariate_{round_idx}"),
                        &round_univariate,
                    );

                    transcript.get_challenge::<P>(format!("Sumcheck:u_{round_idx}"))
                }
                TranscriptRef::Rep3(transcript_rep3) => {
                    transcript_rep3.send_fr_iter_to_verifier_shared(
                        format!("Sumcheck:univariate_{round_idx}"),
                        round_univariate.evaluations_as_ref(),
                    );
                    transcript_rep3.get_challenge(
                        format!("Sumcheck:u_{round_idx}"),
                        self.net,
                        self.state,
                    )?
                }
            };
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
        let zero_univariate = L::SumcheckRoundOutputPublic::default();
        for idx in multivariate_d as usize..CONST_PROOF_SIZE_LOG_N {
            match transcript {
                TranscriptRef::Plain(transcript) => {
                    transcript.send_fr_iter_to_verifier::<P, _>(
                        format!("Sumcheck:univariate_{idx}"),
                        zero_univariate.evaluations_as_ref(),
                    );
                    let round_challenge =
                        transcript.get_challenge::<P>(format!("Sumcheck:u_{idx}"));
                    multivariate_challenge.push(round_challenge);
                }
                TranscriptRef::Rep3(transcript_rep3) => {
                    transcript_rep3.send_fr_iter_to_verifier(
                        format!("Sumcheck:univariate_{idx}"),
                        zero_univariate.evaluations_as_ref(),
                    );
                    let round_challenge = transcript_rep3.get_challenge(
                        format!("Sumcheck:u_{idx}"),
                        self.net,
                        self.state,
                    )?;
                    multivariate_challenge.push(round_challenge);
                }
            }
        }

        // Claimed evaluations of Prover polynomials are extracted and added to the transcript. When Flavor has ZK, the
        // evaluations of all witnesses are masked.

        match transcript {
            TranscriptRef::Plain(transcript) => {
                let multivariate_evaluations = Self::extract_claimed_evaluations(
                    self.net,
                    self.state,
                    partially_evaluated_polys,
                )?;
                Self::add_evals_to_transcript(transcript, &multivariate_evaluations);
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                let multivariate_evaluations =
                    Self::extract_claimed_evaluations_non_opened(partially_evaluated_polys)?;
                let public_evals = multivariate_evaluations.public_iter();
                let shared_evals = multivariate_evaluations.shared_iter();
                let promoted_public_evals =
                    public_evals.map(|x| T::promote_to_trivial_share(self.state.id(), *x));

                transcript_rep3.send_fr_iter_to_verifier_shared(
                    "Sumcheck:evaluations".to_string(),
                    promoted_public_evals
                        .chain(shared_evals.cloned())
                        .collect::<Vec<_>>()
                        .as_ref(),
                );
            }
        }

        let res = SumcheckOutput {
            // claimed_evaluations: multivariate_evaluations,
            challenges: multivariate_challenge,
            claimed_libra_evaluation: None,
            round_univariates: None,
            round_univariate_evaluations: None,
        };
        Ok(res)
    }

    pub fn sumcheck_prove_zk<const VIRTUAL_LOG_N: usize>(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
        circuit_size: u32,
        zk_sumcheck_data: &mut SharedZKSumcheckData<T, P>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<SumcheckOutput<T, P>> {
        tracing::trace!("Sumcheck prove");

        let mut eval_domain = Vec::new();
        let mut round_univariates: Vec<SharedPolynomial<T, P>> = Vec::new();
        let mut round_univariate_evaluations: Vec<[T::ArithmeticShare; 3]> = Vec::new();
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

        let mut sum_check_round = SumcheckRound::new(multivariate_n as usize);
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
        let mut round_univariate = sum_check_round.compute_univariate_zk::<T, P, N, L>(
            self.net,
            self.state,
            round_idx,
            &self.memory.relation_parameters,
            &self.memory.alphas,
            &gate_separators,
            &self.memory.polys,
            zk_sumcheck_data,
            &mut row_disabling_polynomial,
        )?;

        if L::IS_GRUMPKIN_FLAVOUR {
            self.commit_to_round_univariate(
                round_idx,
                &round_univariate,
                &eval_domain,
                transcript,
                crs,
                &mut round_univariates,
                &mut round_univariate_evaluations,
            )?;
        } else {
            let round_univariate =
                T::open_many(round_univariate.evaluations_as_ref(), self.net, self.state)?;

            // Place the evaluations of the round univariate into transcript.
            transcript.send_fr_iter_to_verifier::<P, _>(
                "Sumcheck:univariate_0".to_string(),
                &round_univariate,
            );
        }
        let round_challenge = transcript.get_challenge::<P>("Sumcheck:u_0".to_string());
        multivariate_challenge.push(round_challenge);

        // Prepare sumcheck book-keeping table for the next round
        let mut partially_evaluated_polys =
            PartiallyEvaluatePolys::<T, P, L>::new(multivariate_n as usize >> 1);
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

            round_univariate = sum_check_round.compute_univariate_zk::<T, P, N, L>(
                self.net,
                self.state,
                round_idx,
                &self.memory.relation_parameters,
                &self.memory.alphas,
                &gate_separators,
                &partially_evaluated_polys,
                zk_sumcheck_data,
                &mut row_disabling_polynomial,
            )?;
            if L::IS_GRUMPKIN_FLAVOUR {
                // Compute monomial coefficients of the round univariate, commit to it, populate an auxiliary structure
                // needed in the PCS round
                self.commit_to_round_univariate(
                    round_idx,
                    &round_univariate,
                    &eval_domain,
                    transcript,
                    crs,
                    &mut round_univariates,
                    &mut round_univariate_evaluations,
                )?;
            } else {
                let round_univariate =
                    T::open_many(round_univariate.evaluations_as_ref(), self.net, self.state)?;

                // Place the evaluations of the round univariate into transcript.
                transcript.send_fr_iter_to_verifier::<P, _>(
                    format!("Sumcheck:univariate_{round_idx}"),
                    &round_univariate,
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
            round_univariate_evaluations[multivariate_d as usize - 1][2] = CoUtils::evaluate::<T, _>(
                round_univariate.evaluations_as_ref(),
                multivariate_challenge[multivariate_d as usize - 1],
            );
        }
        tracing::trace!("Completed {multivariate_d} rounds of sumcheck");

        // Zero univariates are used to pad the proof to the fixed size CONST_PROOF_SIZE_LOG_N.
        let zero_univariate = L::SumcheckRoundOutputZKPublic::default();
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
        let multivariate_evaluations =
            Self::extract_claimed_evaluations(self.net, self.state, partially_evaluated_polys)?;
        Self::add_evals_to_transcript(transcript, &multivariate_evaluations);

        // The evaluations of Libra uninvariates at \f$ g_0(u_0), \ldots, g_{d-1} (u_{d-1}) \f$ are added to the
        // transcript.
        let mut libra_evaluation = zk_sumcheck_data.constant_term;
        for libra_eval in &zk_sumcheck_data.libra_evaluations {
            libra_evaluation = T::add(libra_evaluation, *libra_eval);
        }
        let libra_evaluation = T::open_many(&[libra_evaluation], self.net, self.state)?[0];
        transcript
            .send_fr_to_verifier::<P>("Libra:claimed_evaluation".to_string(), libra_evaluation);

        if L::IS_GRUMPKIN_FLAVOUR {
            Ok(SumcheckOutput {
                // claimed_evaluations: multivariate_evaluations,
                challenges: multivariate_challenge,
                claimed_libra_evaluation: Some(libra_evaluation),
                round_univariates: Some(round_univariates),
                round_univariate_evaluations: Some(round_univariate_evaluations),
            })
        } else {
            Ok(SumcheckOutput {
                // claimed_evaluations: multivariate_evaluations,
                challenges: multivariate_challenge,
                claimed_libra_evaluation: Some(libra_evaluation),
                round_univariates: None,
                round_univariate_evaluations: None,
            })
        }
    }

    // this is a helper function for committing in Grumpkin Flavours
    #[expect(clippy::too_many_arguments)]
    fn commit_to_round_univariate(
        &mut self,
        round_idx: usize,
        round_univariate: &L::SumcheckRoundOutputZK<T, P>,
        eval_domain: &[P::ScalarField],
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
        crs: &ProverCrs<P>,
        round_univariates: &mut Vec<SharedPolynomial<T, P>>,
        round_univariate_evaluations: &mut Vec<[T::ArithmeticShare; 3]>,
    ) -> HonkProofResult<()> {
        let id = self.state.id();
        // Transform to monomial form and commit to it
        let round_poly_monomial = SharedPolynomial::interpolate_from_evals(
            eval_domain,
            round_univariate.evaluations_as_ref(),
            L::BATCHED_RELATION_PARTIAL_LENGTH_ZK,
        );

        let commitment = CoUtils::commit::<T, P>(round_poly_monomial.as_ref(), crs);

        // Store round univariate in monomial, as it is required by Shplemini
        round_univariates.push(round_poly_monomial);
        let eval_at_0 = round_univariate.evaluations_as_ref()[0];
        let eval_at_1 = round_univariate.evaluations_as_ref()[1];
        let (points, fields) = T::open_point_and_field_many(
            &[commitment],
            &[eval_at_0, eval_at_1],
            self.net,
            self.state,
        )?;
        transcript.send_point_to_verifier::<P>(
            format!("Sumcheck:univariate_comm_{round_idx}"),
            points[0].into(),
        );

        // Send the evaluations of the round univariate at 0 and 1
        transcript
            .send_fr_to_verifier::<P>(format!("Sumcheck:univariate_{round_idx}_eval_0"), fields[0]);
        transcript
            .send_fr_to_verifier::<P>(format!("Sumcheck:univariate_{round_idx}_eval_1"), fields[1]);

        // Store the evaluations to be used by ShpleminiProver
        round_univariate_evaluations.push([
            T::promote_to_trivial_share(id, fields[0]),
            T::promote_to_trivial_share(id, fields[1]),
            T::ArithmeticShare::default(),
        ]);
        if round_idx > 0 {
            round_univariate_evaluations[round_idx - 1][2] =
                T::promote_to_trivial_share(id, fields[0] + fields[1]);
        }
        Ok(())
    }
}
