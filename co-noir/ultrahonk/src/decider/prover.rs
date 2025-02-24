use super::{
    shplemini::ShpleminiOpeningClaim,
    sumcheck::{zk_data::ZKSumcheckData, SumcheckOutput},
    types::ProverMemory,
};

use crate::{
    decider::small_subgroup_ipa::SmallSubgroupIPAProver,
    prover::ZeroKnowledge,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
    types::HonkProof,
    Utils,
};
use co_builder::{
    prelude::{HonkCurve, ProverCrs},
    HonkProofResult,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;

pub(crate) struct Decider<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    pub(super) memory: ProverMemory<P>,
    pub(super) rng: ChaCha12Rng,
    phantom_data: PhantomData<P>,
    phantom_hasher: PhantomData<H>,
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Decider<P, H> {
    pub(crate) fn new(memory: ProverMemory<P>) -> Self {
        Self {
            memory,
            rng: ChaCha12Rng::from_entropy(),
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
        }
    }

    fn compute_opening_proof(
        opening_claim: ShpleminiOpeningClaim<P::ScalarField>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
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
        transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());
        Ok(())
    }

    /**
     * @brief Run Sumcheck to establish that ∑_i pow(\vec{β*})f_i(ω) = e*. This results in u = (u_1,...,u_d) sumcheck round
     * challenges and all evaluations at u being calculated.
     *
     */
    #[expect(clippy::type_complexity)]
    fn execute_relation_check_rounds(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<(SumcheckOutput<P::ScalarField>, Option<ZKSumcheckData<P>>)> {
        if has_zk == ZeroKnowledge::Yes {
            let log_subgroup_size = Utils::get_msb64(P::SUBGROUP_SIZE as u64);
            let commitment_key = crs.monomials[..1 << (log_subgroup_size + 1)].to_vec();
            let mut zk_sumcheck_data: ZKSumcheckData<P> = ZKSumcheckData::<P>::new::<H, _>(
                Utils::get_msb64(circuit_size as u64) as usize,
                transcript,
                &commitment_key,
                &mut self.rng,
            )?;
            Ok((
                self.sumcheck_prove_zk(transcript, circuit_size, &mut zk_sumcheck_data),
                Some(zk_sumcheck_data),
            ))
        } else {
            // This is just Sumcheck.prove without ZK
            Ok((self.sumcheck_prove(transcript, circuit_size), None))
        }
    }

    /**
     * @brief Execute the ZeroMorph protocol to produce an opening claim for the multilinear evaluations produced by
     * Sumcheck and then produce an opening proof with a univariate PCS.
     * @details See https://hackmd.io/dlf9xEwhTQyE3hiGbq4FsA?view for a complete description of the unrolled protocol.
     *
     * */
    fn execute_pcs_rounds(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
        has_zk: ZeroKnowledge,
        zk_sumcheck_data: Option<&mut ZKSumcheckData<P>>,
    ) -> HonkProofResult<()> {
        if has_zk == ZeroKnowledge::No {
            let prover_opening_claim =
                self.shplemini_prove(transcript, circuit_size, crs, sumcheck_output, None)?;
            Self::compute_opening_proof(prover_opening_claim, transcript, crs)
        } else {
            let small_subgroup_ipa_prover = SmallSubgroupIPAProver::<_>::new::<H, _>(
                zk_sumcheck_data.expect("We have ZK"),
                &sumcheck_output.challenges,
                sumcheck_output
                    .claimed_libra_evaluation
                    .expect("We have ZK"),
                transcript,
                crs,
                &mut self.rng,
            )?;
            let witness_polynomials = small_subgroup_ipa_prover.get_witness_polynomials();
            let prover_opening_claim = self.shplemini_prove(
                transcript,
                circuit_size,
                crs,
                sumcheck_output,
                Some(witness_polynomials),
            )?;
            Self::compute_opening_proof(prover_opening_claim, transcript, crs)
        }
    }

    pub(crate) fn prove(
        mut self,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        mut transcript: Transcript<TranscriptFieldType, H>,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("Decider prove");

        // Run sumcheck subprotocol.
        let (sumcheck_output, mut zk_sumcheck_data) =
            self.execute_relation_check_rounds(&mut transcript, crs, circuit_size, has_zk)?;

        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds(
            &mut transcript,
            circuit_size,
            crs,
            sumcheck_output,
            has_zk,
            zk_sumcheck_data.as_mut(),
        )?;
        Ok(transcript.get_proof())
    }
}
