use crate::co_decider::{co_sumcheck::SumcheckOutput, prover::CoDecider};
use mpc_core::traits::{MSMProvider, PrimeFieldMpcProtocol};
use ultrahonk::{
    prelude::{HonkCurve, HonkProofResult, ProverCrs, TranscriptFieldType, TranscriptType},
    Utils,
};

impl<T, P: HonkCurve<TranscriptFieldType>> CoDecider<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    /**
     * @brief  * @brief Returns a univariate opening claim equivalent to a set of multilinear evaluation claims for
     * unshifted polynomials f_i and to-be-shifted polynomials g_i to be subsequently proved with a univariate PCS
     *
     * @param f_polynomials Unshifted polynomials
     * @param g_polynomials To-be-shifted polynomials (of which the shifts h_i were evaluated by sumcheck)
     * @param evaluations Set of evaluations v_i = f_i(u), w_i = h_i(u) = g_i_shifted(u)
     * @param multilinear_challenge Multilinear challenge point u
     * @param commitment_key
     * @param transcript
     *
     * @todo https://github.com/AztecProtocol/barretenberg/issues/1030: document concatenation trick
     */
    pub(crate) fn zeromorph_prove(
        &self,
        transcript: &mut TranscriptType,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
        // ) -> HonkProofResult<ZeroMorphOpeningClaim<P::ScalarField>> {
    ) -> HonkProofResult<()> {
        tracing::trace!("Zeromorph prove");

        let f_polynomials = self.get_f_polyomials(&self.memory.polys);
        let g_polynomials = self.get_g_polyomials(&self.memory.polys);
        let f_evaluations = Self::get_f_evaluations(&sumcheck_output.claimed_evaluations);
        let g_shift_evaluations =
            Self::get_g_shift_evaluations(&sumcheck_output.claimed_evaluations);
        let multilinear_challenge = &sumcheck_output.challenges;
        let commitment_key = crs;

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge::<P>("rho".to_string());

        // Extract multilinear challenge u and claimed multilinear evaluations from Sumcheck output
        let u_challenge = multilinear_challenge;
        let log_n = Utils::get_msb32(circuit_size);
        let n = 1 << log_n;

        todo!("ZeroMorph prove")
    }
}
