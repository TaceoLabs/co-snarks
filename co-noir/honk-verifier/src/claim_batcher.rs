use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::types::goblin_types::GoblinElement;
use co_builder::{
    mega_builder::MegaCircuitBuilder,
    types::field_ct::FieldCT,
};
use common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use itertools::izip;

pub struct Batch<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) commitments: Vec<GoblinElement<C, T>>,
    pub(crate) evaluations: Vec<FieldCT<C::ScalarField>>,
    pub(crate) scalar: FieldCT<C::ScalarField>,
}

pub struct ClaimBatcher<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) unshifted: Batch<C, T>,
    pub(crate) shifted: Batch<C, T>,
}

impl<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> ClaimBatcher<C, T>
{
    /**
     * @brief Compute scalars used to batch each set of claims, excluding contribution from batching challenge \rho
     * @details Computes scalars s_0, s_1, s_2 given by
     * \f[
     * - s_0 = \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right) \f],
     * - s_1 = \frac{1}{r} \times \left(\frac{1}{z-r} - \nu \times \frac{1}{z+r}\right)
     * - s_2 = r^{k} \times \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right)
     * \f]
     * where the scalars used to batch the claims are given by
     * \f[
     * \left(
     * - s_0,
     * \ldots,
     * - \rho^{i+k-1} \times s_0,
     * - \rho^{i+k} \times s_1,
     * \ldots,
     * - \rho^{k+m-1} \times s_1
     * \right)
     * \f]
     *
     * @param inverse_vanishing_eval_pos 1/(z-r)
     * @param inverse_vanishing_eval_neg 1/(z+r)
     * @param nu_challenge ν (shplonk batching challenge)
     * @param r_challenge r (gemini evaluation challenge)
     */
    pub(crate) fn compute_scalars_for_each_batch(
        &mut self,
        inverted_vanishing_evals: &Vec<FieldCT<C::ScalarField>>,
        nu_challenge: &FieldCT<C::ScalarField>,
        r_challenge: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let inverse_vanishing_eval_pos = &inverted_vanishing_evals[0];
        let inverse_vanishing_eval_neg = &inverted_vanishing_evals[1];

        // TACEO TODO: Do we need the other optional fields?
        let mul_expr = inverse_vanishing_eval_neg.multiply(nu_challenge, builder, driver)?;

        // (1/(z−r) + ν/(z+r))
        self.unshifted.scalar = mul_expr.add(inverse_vanishing_eval_pos, builder, driver);

        // r⁻¹ ⋅ (1/(z−r) − ν/(z+r))
        let inverse_r = one.divide(r_challenge, builder, driver)?;
        self.shifted.scalar = inverse_vanishing_eval_pos
            .sub(&mul_expr, builder, driver)
            .multiply(&inverse_r, builder, driver)?;

        Ok(())
    }

    /**
     * @brief Append the commitments and scalars from each batch of claims to the Shplemini, vectors which subsequently
     * will be inputs to the batch mul;
     * update the batched evaluation and the running batching challenge (power of rho) in place.
     *
     * @param commitments commitment inputs to the single Shplemini batch mul
     * @param scalars scalar inputs to the single Shplemini batch mul
     * @param batched_evaluation running batched evaluation of the committed multilinear polynomials
     * @param rho multivariate batching challenge \rho
     * @param rho_power current power of \rho used in the batching scalar
     * @param shplonk_batching_pos and @param shplonk_batching_neg consecutive powers of the Shplonk batching
     * challenge ν for the interleaved contributions
     */
    pub(crate) fn update_batch_mul_inputs_and_batched_evaluation(
        &mut self,
        commitments: &mut Vec<GoblinElement<C, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        batched_evaluation: &mut FieldCT<C::ScalarField>,
        rho: &FieldCT<C::ScalarField>,
        rho_power: &mut FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // Append the commitments/scalars from a given batch to the corresponding containers; update the batched
        // evaluation and the running batching challenge in place
        let mut aggregate_claim_data_and_update_batched_evaluation =
            |batch: &mut Batch<C, T>, rho_power: &mut FieldCT<C::ScalarField>| {
                for (commitment, evaluation) in
                    izip!(batch.commitments.iter_mut(), batch.evaluations.iter_mut())
                {
                    commitments.push(commitment.clone());
                    scalars.push(batch.scalar.neg().multiply(rho_power, builder, driver)?);

                    *batched_evaluation = batched_evaluation.add(
                        &evaluation.multiply(rho_power, builder, driver)?,
                        builder,
                        driver,
                    );
                    *rho_power = rho.multiply(rho_power, builder, driver)?;
                }
                HonkProofResult::Ok(())
            };

        // Incorporate the claim data from each batch of claims that is present in the vectors of commitments and
        // scalars for the batch mul

        // i-th Unshifted commitment will be multiplied by ρ^i and (1/(z−r) + ν/(z+r))
        aggregate_claim_data_and_update_batched_evaluation(&mut self.unshifted, rho_power)?;

        // i-th shifted commitments will be multiplied by p^{k+i} and r⁻¹ ⋅ (1/(z−r) − ν/(z+r))
        aggregate_claim_data_and_update_batched_evaluation(&mut self.shifted, rho_power)?;

        // TACEO TODO: Do we need the other optional fields?
        Ok(())
    }
}
