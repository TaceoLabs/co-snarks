// CESAR TODO: Use reference counters
use ark_ec::AdditiveGroup;
use ark_ff::Field;
use co_builder::{
    HonkProofResult, TranscriptFieldType,
    prelude::{HonkCurve, Polynomial, ProverCrs, Utils},
};
use ultrahonk::prelude::{
    HonkProof, OpeningPair, ShpleminiOpeningClaim, Transcript, TranscriptHasher,
};

use crate::eccvm::ecc_op_queue::ECCOpQueue;

pub(crate) struct MergeProver<C, const NUM_WIRES: usize>
where
    C: HonkCurve<TranscriptFieldType>,
    C::Affine: HonkCurve<TranscriptFieldType>,
{
    ecc_op_queue: ECCOpQueue<C>,
    commitment_key: ProverCrs<C>,
}

impl<C, const NUM_WIRES: usize> MergeProver<C, NUM_WIRES>
where
    C: HonkCurve<TranscriptFieldType>,
    C::Affine: HonkCurve<TranscriptFieldType>,
{
    pub fn new(ecc_op_queue: ECCOpQueue<C>, commitment_key: ProverCrs<C>) -> Self {
        Self {
            ecc_op_queue,
            commitment_key,
        }
    }

    pub fn construct_proof<H: TranscriptHasher<TranscriptFieldType>>(
        &mut self,
    ) -> HonkProof<TranscriptFieldType> {
        let mut transcript = Transcript::<TranscriptFieldType, H>::default();

        let T_current = self.ecc_op_queue.construct_ultra_ops_table_columns();
        let T_prev = self
            .ecc_op_queue
            .construct_previous_ultra_ops_table_columns();
        let t_current = self
            .ecc_op_queue
            .construct_current_ultra_ops_subtable_columns();

        let (current_table_size, current_subtable_size) = (
            T_current[0].coefficients.len(),
            t_current[0].coefficients.len(),
        );

        transcript.send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64);

        for i in 0..NUM_WIRES {
            let t_commitment = Utils::commit(&t_current[i].coefficients, &self.commitment_key)
                .expect("Failed to commit to subtable column");
            let T_prev_commitment = Utils::commit(&T_prev[i].coefficients, &self.commitment_key)
                .expect("Failed to commit to previous table column");
            let T_commitment = Utils::commit(&T_current[i].coefficients, &self.commitment_key)
                .expect("Failed to commit to current table column");

            transcript.send_point_to_verifier::<C>(
                format!("subtable_commitment_{i}"),
                t_commitment.into(),
            );
            transcript.send_point_to_verifier::<C>(
                format!("previous_table_commitment_{i}"),
                T_prev_commitment.into(),
            );
            transcript.send_point_to_verifier::<C>(
                format!("current_table_commitment_{i}"),
                T_commitment.into(),
            );
        }

        let kappa = transcript.get_challenge::<C>("kappa".to_owned());

        let mut opening_claims = Vec::with_capacity(3 * NUM_WIRES);

        // CESAR TODO: Avoid verbose code by using a loop or macro
        // CESAR TODO: Avoid cloning the polynomials
        for i in 0..NUM_WIRES {
            let evaluation = t_current[i].eval_poly(kappa);
            transcript.send_fr_to_verifier::<C>(format!("subtable_evaluation_{i}"), evaluation);
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: t_current[i].clone(),
                opening_pair: OpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        }

        for i in 0..NUM_WIRES {
            let evaluation = T_prev[i].eval_poly(kappa);
            transcript
                .send_fr_to_verifier::<C>(format!("previous_table_evaluation_{i}"), evaluation);
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: T_prev[i].clone(),
                opening_pair: OpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        }

        for i in 0..NUM_WIRES {
            let evaluation = T_current[i].eval_poly(kappa);
            transcript
                .send_fr_to_verifier::<C>(format!("current_table_evaluation_{i}"), evaluation);
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: T_current[i].clone(),
                opening_pair: OpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        }

        let alpha = transcript.get_challenge::<C>("alpha".to_owned());

        let mut batched_eval = C::ScalarField::ZERO;
        let mut alpha_pow = C::ScalarField::ONE;

        let batched_polynomial = opening_claims.iter().fold(
            Polynomial::new_zero(current_table_size),
            |mut acc, claim| {
                acc.add_scaled(&claim.polynomial, &alpha_pow);
                batched_eval += claim.opening_pair.evaluation * alpha_pow;
                alpha_pow *= alpha;
                acc
            },
        );

        let batched_claim = ShpleminiOpeningClaim {
            polynomial: batched_polynomial,
            opening_pair: OpeningPair {
                challenge: kappa,
                evaluation: batched_eval,
            },
            gemini_fold: false,
        };

        Self::compute_opening_proof(batched_claim, &mut transcript, &self.commitment_key)
            .expect("Failed to compute opening proof");

        transcript.get_proof().clone()
    }

    // CESAR TODO: Avoid duplicate code in co-noir/ultrahonk/src/decider/decider_prover.rs#48
    fn compute_opening_proof(
        opening_claim: ShpleminiOpeningClaim<C::ScalarField>,
        transcript: &mut Transcript<
            TranscriptFieldType,
            impl TranscriptHasher<TranscriptFieldType>,
        >,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        let mut quotient = opening_claim.polynomial;
        let pair = opening_claim.opening_pair;
        quotient[0] -= pair.evaluation;
        // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
        quotient.factor_roots(&pair.challenge);
        let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
        // AZTEC TODO(#479): compute_opening_proof
        // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
        // pthreads) or even the work queue itself
        transcript.send_point_to_verifier::<C>("KZG:W".to_string(), quotient_commitment.into());
        Ok(())
    }
}
