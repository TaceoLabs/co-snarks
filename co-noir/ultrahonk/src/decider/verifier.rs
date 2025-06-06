use super::{shplemini::ShpleminiVerifierOpeningClaim, types::VerifierMemory};
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::NUM_LIBRA_COMMITMENTS;
use crate::{
    Utils,
    plain_prover_flavour::PlainProverFlavour,
    transcript::{Transcript, TranscriptHasher},
    verifier::HonkVerifyResult,
};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use co_builder::{
    TranscriptFieldType,
    prelude::{HonkCurve, ZeroKnowledge},
};
use std::marker::PhantomData;

pub(crate) struct DeciderVerifier<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> {
    pub(super) memory: VerifierMemory<P, L>,
    phantom_data: PhantomData<(P, H, L)>,
}

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> DeciderVerifier<P, H, L>
{
    pub(crate) fn new(memory: VerifierMemory<P, L>) -> Self {
        Self {
            memory,
            phantom_data: PhantomData,
        }
    }

    pub(crate) fn reduce_verify_shplemini(
        opening_pair: &mut ShpleminiVerifierOpeningClaim<P>,
        mut transcript: Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<(P::G1Affine, P::G1Affine)> {
        tracing::trace!("Reduce and verify opening pair");

        let quotient_commitment = transcript.receive_point_from_prover::<P>("KZG:W".to_string())?;
        opening_pair.commitments.push(quotient_commitment);
        opening_pair.scalars.push(opening_pair.challenge);
        let p_1 = -quotient_commitment.into_group();
        let p_0 = Utils::msm::<P>(&opening_pair.scalars, &opening_pair.commitments)?;

        Ok((p_0.into(), p_1.into()))
    }

    pub fn pairing_check(
        p0: P::G1Affine,
        p1: P::G1Affine,
        g2_x: P::G2Affine,
        g2_gen: P::G2Affine,
    ) -> bool {
        tracing::trace!("Pairing check");
        let p = [g2_gen, g2_x];
        let g1_prepared = [P::G1Prepared::from(p0), P::G1Prepared::from(p1)];
        P::multi_pairing(g1_prepared, p).0 == P::TargetField::one()
    }

    pub(crate) fn verify(
        mut self,
        circuit_size: u32,
        crs: &P::G2Affine,
        mut transcript: Transcript<TranscriptFieldType, H>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("Decider verification");
        let log_circuit_size = Utils::get_msb32(circuit_size);

        let mut padding_indicator_array = [P::ScalarField::zero(); CONST_PROOF_SIZE_LOG_N];

        for (idx, value) in padding_indicator_array.iter_mut().enumerate() {
            *value = if idx < log_circuit_size as usize {
                P::ScalarField::one()
            } else {
                P::ScalarField::zero()
            };
        }
        let (sumcheck_output, libra_commitments) = if has_zk == ZeroKnowledge::Yes {
            let mut libra_commitments = Vec::with_capacity(NUM_LIBRA_COMMITMENTS);

            libra_commitments
                .push(transcript.receive_point_from_prover::<P>(
                    "Libra:concatenation_commitment".to_string(),
                )?);

            let sumcheck_output =
                self.sumcheck_verify(&mut transcript, has_zk, &padding_indicator_array)?;
            if !sumcheck_output.verified {
                tracing::trace!("Sumcheck failed");
                return Ok(false);
            }

            libra_commitments.push(
                transcript
                    .receive_point_from_prover::<P>("Libra:grand_sum_commitment".to_string())?,
            );
            libra_commitments.push(
                transcript
                    .receive_point_from_prover::<P>("Libra:quotient_commitment".to_string())?,
            );

            (sumcheck_output, Some(libra_commitments))
        } else {
            let sumcheck_output =
                self.sumcheck_verify(&mut transcript, has_zk, &padding_indicator_array)?;
            if !sumcheck_output.verified {
                tracing::trace!("Sumcheck failed");
                return Ok(false);
            }

            (sumcheck_output, None)
        };

        let mut consistency_checked = true;
        let mut opening_claim = self.compute_batch_opening_claim(
            sumcheck_output.multivariate_challenge,
            &mut transcript,
            libra_commitments,
            sumcheck_output.claimed_libra_evaluation,
            &mut consistency_checked,
            &padding_indicator_array,
        )?;

        let pairing_points = Self::reduce_verify_shplemini(&mut opening_claim, transcript)?;
        let pcs_verified = Self::pairing_check(
            pairing_points.0,
            pairing_points.1,
            *crs,
            P::G2Affine::generator(),
        );
        Ok(sumcheck_output.verified && pcs_verified && consistency_checked)
    }
}
