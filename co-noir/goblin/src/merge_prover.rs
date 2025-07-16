use std::sync::Arc;

use ark_ec::CurveGroup;
use ark_poly::evaluations;
use co_builder::prelude::{Polynomial, ProverCrs, Utils};
use ultrahonk::{prelude::ShpleminiOpeningClaim, transcript::{Transcript, TranscriptFieldType, TranscriptHasher}};

use crate::eccvm::ecc_op_queue::{self, ECCOpQueue};

pub(crate) type MergeProof<F> = Vec<F>;

pub(crate) struct MergeProver<C, H, const NUM_WIRES: usize>
where
    C: CurveGroup,
    H: TranscriptHasher<TranscriptFieldType>,
{
    ecc_op_queue: ECCOpQueue<C>,
    commitment_key: ProverCrs<C>,
    transcript: Transcript<TranscriptFieldType, H>,
}

impl<C, H, NUM_WIRES> MergeProver<C, H, NUM_WIRES> 
where
    C: CurveGroup,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub fn new(
        ecc_op_queue: ECCOpQueue<C>,
        commitment_key: ProverCrs<C>,
     ) -> Self {
        Self {
            ecc_op_queue,
            commitment_key,
            ..Default::default()
        }
    }

    pub fn construct_proof(&self) -> MergeProof<C::G1Affine> {
        let T_current = self.ecc_op_queue.construct_ultra_ops_table_columns();
        let T_prev = self.ecc_op_queue.construct_previous_ultra_ops_table_columns();
        let t_current = self.ecc_op_queue.construct_current_ultra_ops_subtable_columns();
    
        let (current_table_size, current_subtable_size) = (
            T_current[0].coefficients.len(),
            t_current[0].coefficients.len(),
        );

        self.transcript.send_u64_to_verifier("subtable_size", current_subtable_size as u64);  
    
        for i in 0..NUM_WIRES {
            let t_commitment = Utils::commit(&t_current[i].coefficients, &self.commitment_key)
                .expect("Failed to commit to subtable column");
            let T_prev_commitment = Utils::commit(&T_prev[i].coefficients, &self.commitment_key)
                            .expect("Failed to commit to previous table column");
            let T_commitment = Utils::commit(&T_current[i].coefficients, &self.commitment_key)
                            .expect("Failed to commit to current table column");

            self.transcript.send_point_to_verifier::<C>(
                format!("subtable_commitment_{i}"),
                t_commitment,
            );
            self.transcript.send_point_to_verifier::<C>(
                format!("previous_table_commitment_{i}"),
                T_prev_commitment,
            );
            self.transcript.send_point_to_verifier::<C>(
                format!("current_table_commitment_{i}"),
                T_commitment,
            );
        }

        let kappa = self.transcript.get_challenge::<C::ScalarField>("kappa");

        let mut opening_claims = Vec::with_capacity(3 * NUM_WIRES);
        for i in 0..NUM_WIRES {
            let evaluation = t_current[i].eval_poly(kappa);
            self.transcript.send_fr_to_verifier(
                format!("subtable_evaluation_{i}"),
                evaluation,
            );
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: t_current[i],
                opening_pair: ShpleminiOpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        }

        for i in 0..NUM_WIRES {
            let evaluation = T_prev[i].eval_poly(kappa);
            self.transcript.send_fr_to_verifier(
                format!("previous_table_evaluation_{i}"),
                evaluation,
            );
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: T_prev[i].clone(),
                opening_pair: ShpleminiOpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        }

        for i in 0..NUM_WIRES {
            let evaluation = T_current[i].eval_poly(kappa); 
            self.transcript.send_fr_to_verifier(
                format!("current_table_evaluation_{i}"),
                evaluation,
            );
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: T_current[i].clone(),
                opening_pair: ShpleminiOpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        }

        let alpha = self.transcript.get_challenge::<C::ScalarField>("alpha");

        let mut batched_eval = C::ScalarField::ZERO;
        let mut alpha_pow = C::ScalarField::ONE;

        let batched_polynomial = opening_claims.iter().fold(
            Polynomial::new_zero(
                current_table_size
            ),
            |mut acc, claim| {
                acc += claim.polynomial * alpha_pow;
                batched_eval += claim.opening_pair.evaluation * alpha_pow;
                alpha_pow *= alpha;
                acc
            },
        );

        let batched_claim = ShpleminiOpeningClaim {
            polynomial: batched_polynomial,
            opening_pair: ShpleminiOpeningPair {
                challenge: kappa,
                evaluation: batched_eval,
            },
            gemini_fold: false,
        };

        Self::compute_opening_proof(batched_claim, &mut self.transcript, &self.commitment_key)
            .expect("Failed to compute opening proof");

        self.transcript.get_proof().inner()
    }

    // CESAR TODO: Avoid duplicate code in co-noir/ultrahonk/src/decider/decider_prover.rs#48
    fn compute_opening_proof(
        opening_claim: ShpleminiOpeningClaim<P::ScalarField>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
    ) -> Result<()> {
        let mut quotient = opening_claim.polynomial;
        let pair = opening_claim.opening_pair;
        quotient[0] -= pair.evaluation;
        // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
        quotient.factor_roots(&pair.challenge);
        let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
        // AZTEC TODO(#479): compute_opening_proof
        // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
        // pthreads) or even the work queue itself
        transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());
        Ok(())
    }
}