use super::{
    sumcheck::{SumcheckOutput, zk_data::ZKSumcheckData},
    types::ProverMemory,
};

use crate::{
    Utils, decider::small_subgroup_ipa::SmallSubgroupIPAProver,
    plain_prover_flavour::PlainProverFlavour,
};
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, ProverCrs, ZeroKnowledge},
};
use common::HonkProof;
use common::transcript::{Transcript, TranscriptFieldType, TranscriptHasher};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;
pub(crate) struct Decider<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> {
    pub(super) memory: ProverMemory<P, L>,
    pub(super) rng: ChaCha12Rng,
    pub(crate) has_zk: ZeroKnowledge,
    phantom_data: PhantomData<(P, H)>,
}

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> Decider<P, H, L>
{
    pub(crate) fn new(memory: ProverMemory<P, L>, has_zk: ZeroKnowledge) -> Self {
        Self {
            memory,
            rng: ChaCha12Rng::from_entropy(),
            has_zk,
            phantom_data: PhantomData,
        }
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
    ) -> HonkProofResult<(SumcheckOutput<P::ScalarField, L>, Option<ZKSumcheckData<P>>)> {
        if self.has_zk == ZeroKnowledge::Yes {
            let log_subgroup_size = Utils::get_msb64(P::SUBGROUP_SIZE as u64);
            let commitment_key = &crs.monomials[..1 << (log_subgroup_size + 1)];
            let mut zk_sumcheck_data: ZKSumcheckData<P> = ZKSumcheckData::<P>::new::<H, _>(
                Utils::get_msb64(circuit_size as u64) as usize,
                transcript,
                commitment_key,
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
        sumcheck_output: SumcheckOutput<P::ScalarField, L>,
        zk_sumcheck_data: Option<ZKSumcheckData<P>>,
    ) -> HonkProofResult<()> {
        if self.has_zk == ZeroKnowledge::No {
            let prover_opening_claim =
                self.shplemini_prove(transcript, circuit_size, crs, sumcheck_output, None)?;
            common::compute_opening_proof(prover_opening_claim, transcript, crs)
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
            let witness_polynomials = small_subgroup_ipa_prover.into_witness_polynomials();
            let prover_opening_claim = self.shplemini_prove(
                transcript,
                circuit_size,
                crs,
                sumcheck_output,
                Some(witness_polynomials),
            )?;
            common::compute_opening_proof(prover_opening_claim, transcript, crs)
        }
    }

    pub(crate) fn prove(
        mut self,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        mut transcript: Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("Decider prove");

        // Run sumcheck subprotocol.
        let (sumcheck_output, zk_sumcheck_data) =
            self.execute_relation_check_rounds(&mut transcript, crs, circuit_size)?;

        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds(
            &mut transcript,
            circuit_size,
            crs,
            sumcheck_output,
            zk_sumcheck_data,
        )?;
        Ok(transcript.get_proof())
    }
}
