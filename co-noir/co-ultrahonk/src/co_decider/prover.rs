use super::{co_sumcheck::SumcheckOutput, types::ProverMemory};
use mpc_core::traits::{MSMProvider, PrimeFieldMpcProtocol};
use std::marker::PhantomData;
use ultrahonk::prelude::{
    HonkCurve, HonkProof, HonkProofResult, ProverCrs, TranscriptFieldType, TranscriptType,
};

pub(crate) struct CoDecider<T, P: HonkCurve<TranscriptFieldType>>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    pub(crate) driver: T,
    pub(super) memory: ProverMemory<T, P>,
    phantom_data: PhantomData<P>,
}

impl<T, P: HonkCurve<TranscriptFieldType>> CoDecider<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    pub fn new(driver: T, memory: ProverMemory<T, P>) -> Self {
        Self {
            driver,
            memory,
            phantom_data: PhantomData,
        }
    }

    /**
     * @brief Run Sumcheck to establish that ∑_i pow(\vec{β*})f_i(ω) = e*. This results in u = (u_1,...,u_d) sumcheck round
     * challenges and all evaluations at u being calculated.
     *
     */
    fn execute_relation_check_rounds(
        &mut self,
        transcript: &mut TranscriptType,
        circuit_size: u32,
    ) -> HonkProofResult<SumcheckOutput<P::ScalarField>> {
        // This is just Sumcheck.prove
        self.sumcheck_prove(transcript, circuit_size)
    }

    /**
     * @brief Execute the ZeroMorph protocol to produce an opening claim for the multilinear evaluations produced by
     * Sumcheck and then produce an opening proof with a univariate PCS.
     * @details See https://hackmd.io/dlf9xEwhTQyE3hiGbq4FsA?view for a complete description of the unrolled protocol.
     *
     * */
    fn execute_pcs_rounds(
        &mut self,
        transcript: &mut TranscriptType,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<()> {
        todo!("decider execute_pcs_rounds");
        // let prover_opening_claim =
        //     self.zeromorph_prove(transcript, circuit_size, crs, sumcheck_output)?;
        // Self::compute_opening_proof(prover_opening_claim, transcript, crs)
    }

    pub(crate) fn prove(
        mut self,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        mut transcript: TranscriptType,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("Decider prove");

        // Run sumcheck subprotocol.
        let sumcheck_output = self.execute_relation_check_rounds(&mut transcript, circuit_size)?;

        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds(&mut transcript, circuit_size, crs, sumcheck_output)?;

        Ok(transcript.get_proof())
    }
}
