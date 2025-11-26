use crate::honk_verifier::shplemini::BatchOpeningClaim;
use crate::{
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptHasherCT},
    types::{big_group::BigGroup, types::PairingPoints},
};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

#[expect(clippy::upper_case_acronyms)]
pub(crate) struct KZG;

impl KZG {
    /**
     * @brief Computes the input points for the pairing check needed to verify a KZG opening claim obtained from a
     * Shplemini accumulator.
     *
     * @details This function is used in a recursive setting where we want to "aggregate" proofs. In the Shplemini case,
     * the commitment \f$ C \f$ is encoded into the vectors `commitments` and `scalars` contained in the
     * `batch_opening_claim`. More explicitly, \f$ C = \sum \text{commitments}_i \cdot \text{scalars}_i \f$. To avoid
     * performing an extra `batch_mul`, we simply add the commitment \f$ [W]_1 \f$ to the vector of commitments and
     * the Shplonk evaluation challenge to the vector of scalars and perform a single batch_mul that computes \f$C +
     * W\cdot z \f$.
     *
     * @param batch_opening_claim \f$(\text{commitments}, \text{scalars}, \text{shplonk_evaluation_challenge})\f$
     *        A struct containing the commitments, scalars, and the Shplonk evaluation challenge.
     * @return \f$ \{P_0, P_1\}\f$ where:
     *         - \f$ P_0 = C + [W(x)]_1 \cdot z \f$
     *         - \f$ P_1 = - [W(x)]_1 \f$
     */
    pub(crate) fn reduce_verify_batch_opening_claim<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        batch_opening_claim: &mut BatchOpeningClaim<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<PairingPoints<C, T>> {
        let mut quotient_commitment =
            transcript.receive_point_from_prover("KZG:W".to_owned(), builder, driver)?;

        // This challenge is used to compute offset generators in the batch_mul call below
        let masking_challenge =
            transcript.get_challenge("KZG:masking_challenge".to_owned(), builder, driver)?;

        // The pairing check can be expressed as
        // e(C + [W]₁ ⋅ z, [1]₂) * e(−[W]₁, [X]₂) = 1, where C = ∑ commitmentsᵢ ⋅ scalarsᵢ.

        // Place the commitment to W to 'commitments'
        batch_opening_claim
            .commitments
            .push(quotient_commitment.clone());
        // Update the scalars by adding the Shplonk evaluation challenge z
        batch_opening_claim
            .scalars
            .push(batch_opening_claim.evaluation_point.clone());
        // Compute C + [W]₁ ⋅ z
        let p0 = BigGroup::batch_mul(
            &batch_opening_claim.commitments,
            &batch_opening_claim.scalars,
            0,
            true,
            &masking_challenge,
            builder,
            driver,
        )?;

        let p1 = quotient_commitment.neg(builder, driver)?;

        Ok(PairingPoints::new(p0, p1))
    }
}
