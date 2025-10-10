use super::{
    co_sumcheck::{SumcheckOutput, zk_data::SharedZKSumcheckData},
    small_subgroup_ipa::SharedSmallSubgroupIPAProver,
    types::ProverMemory,
};
use crate::{CONST_PROOF_SIZE_LOG_N, mpc_prover_flavour::MPCProverFlavour};
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
    types::ZeroKnowledge,
    utils::Utils,
};
use co_noir_common::{
    transcript::{Transcript, TranscriptHasher},
    transcript_mpc::TranscriptRef,
};
use mpc_net::Network;
use noir_types::HonkProof;
use std::marker::PhantomData;
pub struct CoDecider<
    'a,
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, P>,
    N: Network,
    L: MPCProverFlavour,
> {
    pub net: &'a N,
    pub state: &'a mut T::State,
    pub memory: ProverMemory<T, P, L>,
    pub has_zk: ZeroKnowledge,
    phantom_data: PhantomData<(P, H)>,
}

impl<
    'a,
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, P>,
    N: Network,
    L: MPCProverFlavour,
> CoDecider<'a, T, P, H, N, L>
{
    pub fn new(
        net: &'a N,
        state: &'a mut T::State,
        memory: ProverMemory<T, P, L>,
        has_zk: ZeroKnowledge,
    ) -> Self {
        Self {
            net,
            state,
            memory,
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
        transcript: &mut TranscriptRef<TranscriptFieldType, T, P, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<(SumcheckOutput<T, P>, Option<SharedZKSumcheckData<T, P>>)> {
        if self.has_zk == ZeroKnowledge::Yes {
            let log_subgroup_size = Utils::get_msb64(P::SUBGROUP_SIZE as u64);
            let commitment_key = &crs.monomials[..1 << (log_subgroup_size + 1)];
            match transcript {
                TranscriptRef::Plain(transcript) => {
                    let mut zk_sumcheck_data: SharedZKSumcheckData<T, P> =
                        SharedZKSumcheckData::<T, P>::new(
                            Utils::get_msb64(circuit_size as u64) as usize,
                            transcript,
                            commitment_key,
                            self.net,
                            self.state,
                        )?;
                    Ok((
                        self.sumcheck_prove_zk::<CONST_PROOF_SIZE_LOG_N>(
                            transcript,
                            circuit_size,
                            &mut zk_sumcheck_data,
                            crs,
                        )?,
                        Some(zk_sumcheck_data),
                    ))
                }
                TranscriptRef::Rep3(_) => {
                    panic!("ZK Flavours are not supposed to be called with REP3 transcripts")
                }
            }
        } else {
            // This is just Sumcheck.prove without ZK
            Ok((self.sumcheck_prove(transcript, circuit_size)?, None))
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
        transcript: &mut TranscriptRef<TranscriptFieldType, T, P, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<T, P>,
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
            let mut small_subgroup_ipa_prover = SharedSmallSubgroupIPAProver::<T, P>::new(
                zk_sumcheck_data.expect("We have ZK"),
                sumcheck_output
                    .claimed_libra_evaluation
                    .expect("We have ZK"),
                "Libra:".to_string(),
                &sumcheck_output.challenges,
            )?;

            match transcript {
                TranscriptRef::Plain(transcript) => {
                    small_subgroup_ipa_prover
                        .prove::<H, N>(self.net, self.state, transcript, crs)?;
                }
                TranscriptRef::Rep3(_) => {
                    panic!("ZK Flavours are not supposed to be called with REP3 transcripts")
                }
            }
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

    #[expect(clippy::type_complexity)]
    pub(crate) fn prove_inner(
        mut self,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        mut transcript: TranscriptRef<TranscriptFieldType, T, P, H>,
    ) -> HonkProofResult<(
        Option<HonkProof<TranscriptFieldType>>,
        Option<Vec<T::ArithmeticShare>>,
    )> {
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

    pub(crate) fn prove(
        self,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        mut transcript: Transcript<TranscriptFieldType, H, T, P>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("Decider prove");

        let transcript_ref = TranscriptRef::Plain(&mut transcript);
        let res = self.prove_inner(circuit_size, crs, transcript_ref);
        match res {
            Ok((Some(proof), None)) => Ok(proof),
            _ => panic!("Unexpected transcript result"),
        }
    }
}
