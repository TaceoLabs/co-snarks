use crate::{
    types::{big_group::BigGroup, field_ct::FieldCT},
    ultra_builder::GenericUltraCircuitBuilder,
};
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use itertools::{interleave, izip};

pub struct Batch<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
{
    pub(crate) commitments: Vec<BigGroup<C::ScalarField, T>>,
    pub(crate) evaluations: Vec<FieldCT<C::ScalarField>>,
    pub(crate) scalar: FieldCT<C::ScalarField>,
}

pub struct ClaimBatcher<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) unshifted: Batch<C, T>,
    pub(crate) shifted: Batch<C, T>,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    ClaimBatcher<C, T>
{
    /*
     * @brief Compute scalars used to batch each set of claims, excluding contribution from batching challenge \rho
     * @details Computes scalars s_0, s_1, s_2 given by
     * \f[
     *  - s_0 = \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right) \f],
     *  - s_1 = \frac{1}{r} \times \left(\frac{1}{z-r} - \nu \times \frac{1}{z+r}\right)
     *  - s_2 = r^{k} \times \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right)
     * \f]
     * where the scalars used to batch the claims are given by
     * \f[
     *  \left(
     *  - s_0,
     *  \ldots,
     *  - \rho^{i+k-1} \times s_0,
     *  - \rho^{i+k} \times s_1,
     *  \ldots,
     *  - \rho^{k+m-1} \times s_1
     *  \right)
     *    \f]
     *
     * @param inverse_vanishing_eval_pos 1/(z-r)
     * @param inverse_vanishing_eval_neg 1/(z+r)
     * @param nu_challenge ν (shplonk batching challenge)
     * @param r_challenge r (gemini evaluation challenge)
     */
    pub(crate) fn compute_scalars_for_each_batch(
        &mut self,
        inverted_vanishing_evals: &[FieldCT<C::ScalarField>],
        nu_challenge: &FieldCT<C::ScalarField>,
        r_challenge: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let inverse_vanishing_eval_pos = &inverted_vanishing_evals[0];
        let inverse_vanishing_eval_neg = &inverted_vanishing_evals[1];

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
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn update_batch_mul_inputs_and_batched_evaluation(
        &mut self,
        commitments: &mut Vec<BigGroup<C::ScalarField, T>>,
        scalars: &mut Vec<FieldCT<C::ScalarField>>,
        batched_evaluation: &mut FieldCT<C::ScalarField>,
        rho: &FieldCT<C::ScalarField>,
        rho_power: &mut FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // Append the commitments/scalars from a given batch to the corresponding containers; update the batched
        // evaluation and the running batching challenge in place
        let rho_powers = std::iter::successors(Some(rho_power.clone()), |acc| {
            Some(
                rho.multiply(acc, builder, driver)
                    .expect("failed to compute rho powers"),
            )
        })
        .take(self.unshifted.commitments.len() + self.shifted.commitments.len())
        .collect::<Vec<_>>();

        let (unshifted_len, shifted_len) = (
            self.unshifted.commitments.len(),
            self.shifted.commitments.len(),
        );

        let unshifted_scalars_neg =
            std::iter::repeat_n(self.unshifted.scalar.neg(), unshifted_len).collect::<Vec<_>>();
        let shifted_scalars_neg =
            std::iter::repeat_n(self.shifted.scalar.neg(), shifted_len).collect::<Vec<_>>();

        let unshifted_data = interleave(unshifted_scalars_neg, self.unshifted.evaluations.clone())
            .collect::<Vec<_>>();
        let shifted_data =
            interleave(shifted_scalars_neg, self.shifted.evaluations.clone()).collect::<Vec<_>>();

        let lhs = [unshifted_data, shifted_data].concat();
        let rhs = interleave(rho_powers.clone(), rho_powers).collect::<Vec<_>>();
        let tmp = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;
        let (unshifted_data, shifted_data) = tmp.split_at(unshifted_len * 2);

        let mut aggregate_claim_data_and_update_batched_evaluation =
            |batch: &mut Batch<C, T>,
             batch_data: &[FieldCT<C::ScalarField>]|
             -> HonkProofResult<()> {
                for (commitment, data) in izip!(batch.commitments.iter_mut(), batch_data.chunks(2))
                {
                    commitments.push(commitment.clone());
                    scalars.push(data[0].clone());

                    *batched_evaluation = batched_evaluation.add(&data[1], builder, driver);
                }
                HonkProofResult::Ok(())
            };

        // Incorporate the claim data from each batch of claims that is present in the vectors of commitments and
        // scalars for the batch mul

        // i-th Unshifted commitment will be multiplied by ρ^i and (1/(z−r) + ν/(z+r))
        aggregate_claim_data_and_update_batched_evaluation(&mut self.unshifted, unshifted_data)?;

        // i-th shifted commitments will be multiplied by p^{k+i} and r⁻¹ ⋅ (1/(z−r) − ν/(z+r))
        aggregate_claim_data_and_update_batched_evaluation(&mut self.shifted, shifted_data)?;

        Ok(())
    }
}
