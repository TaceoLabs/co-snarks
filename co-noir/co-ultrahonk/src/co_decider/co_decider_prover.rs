use super::{
    co_sumcheck::{SumcheckOutput, zk_data::SharedZKSumcheckData},
    small_subgroup_ipa::SharedSmallSubgroupIPAProver,
    types::ProverMemory,
};
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
    utils::Utils,
};
use mpc_net::Network;
use noir_types::HonkProof;
use std::marker::PhantomData;

pub(crate) struct CoDecider<
    'a,
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> {
    pub(crate) net: &'a N,
    pub(crate) state: &'a mut T::State,
    pub(super) memory: ProverMemory<T, P>,
    pub(crate) has_zk: ZeroKnowledge,
    phantom_data: PhantomData<P>,
    phantom_hasher: PhantomData<H>,
}

impl<
    'a,
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> CoDecider<'a, T, P, H, N>
{
    pub fn new(
        net: &'a N,
        state: &'a mut T::State,
        memory: ProverMemory<T, P>,
        has_zk: ZeroKnowledge,
    ) -> Self {
        Self {
            net,
            state,
            memory,
            has_zk,
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
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
    ) -> HonkProofResult<(
        SumcheckOutput<P::ScalarField>,
        Option<SharedZKSumcheckData<T, P>>,
    )> {
        if self.has_zk == ZeroKnowledge::Yes {
            let log_subgroup_size = Utils::get_msb64(P::SUBGROUP_SIZE as u64);
            let commitment_key = &crs.monomials[..1 << (log_subgroup_size + 1)];
            let mut zk_sumcheck_data: SharedZKSumcheckData<T, P> =
                SharedZKSumcheckData::<T, P>::new(
                    Utils::get_msb64(circuit_size as u64) as usize,
                    transcript,
                    commitment_key,
                    self.net,
                    self.state,
                )?;

            Ok((
                self.sumcheck_prove_zk(transcript, circuit_size, &mut zk_sumcheck_data)?,
                Some(zk_sumcheck_data),
            ))
        } else {
            // This is just Sumcheck.prove without ZK
            Ok((self.sumcheck_prove(transcript, circuit_size)?, None))
        }
    }

    /**
     * @brief Produce a univariate opening claim for the sumcheck multivariate evalutions and a batched univariate claim
     * for the transcript polynomials (for the Translator consistency check). Reduce the two opening claims to a single one
     * via Shplonk and produce an opening proof with the univariate PCS of choice (IPA when operating on Grumpkin).
     *
     */
    fn execute_pcs_rounds(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
        zk_sumcheck_data: Option<SharedZKSumcheckData<T, P>>,
    ) -> HonkProofResult<()> {
        if self.has_zk == ZeroKnowledge::No {
            let prover_opening_claim =
                self.shplemini_prove(transcript, circuit_size, crs, sumcheck_output, None)?;
            co_noir_common::compute_co_opening_proof(
                self.net,
                self.state,
                prover_opening_claim,
                transcript,
                crs,
            )
        } else {
            let small_subgroup_ipa_prover = SharedSmallSubgroupIPAProver::<T, P>::new(
                self.net,
                self.state,
                zk_sumcheck_data.expect("We have ZK"),
                &sumcheck_output.challenges,
                sumcheck_output
                    .claimed_libra_evaluation
                    .expect("We have ZK"),
                transcript,
                crs,
            )?;
            let witness_polynomials = small_subgroup_ipa_prover.into_witness_polynomials();
            let prover_opening_claim = self.shplemini_prove(
                transcript,
                circuit_size,
                crs,
                sumcheck_output,
                Some(witness_polynomials),
            )?;
            co_noir_common::compute_co_opening_proof(
                self.net,
                self.state,
                prover_opening_claim,
                transcript,
                crs,
            )
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
