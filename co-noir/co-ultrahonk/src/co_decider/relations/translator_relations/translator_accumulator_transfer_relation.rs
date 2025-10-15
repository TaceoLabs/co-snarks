use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorAccumulatorTransferRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup>
{
    pub(crate) r0: SharedUnivariate<T, P, 3>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
    pub(crate) r2: SharedUnivariate<T, P, 3>,
    pub(crate) r3: SharedUnivariate<T, P, 3>,
    pub(crate) r4: SharedUnivariate<T, P, 3>,
    pub(crate) r5: SharedUnivariate<T, P, 3>,
    pub(crate) r6: SharedUnivariate<T, P, 3>,
    pub(crate) r7: SharedUnivariate<T, P, 3>,
    pub(crate) r8: SharedUnivariate<T, P, 3>,
    pub(crate) r9: SharedUnivariate<T, P, 3>,
    pub(crate) r10: SharedUnivariate<T, P, 3>,
    pub(crate) r11: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default
    for TranslatorAccumulatorTransferRelationAcc<T, P>
{
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
            r2: SharedUnivariate::default(),
            r3: SharedUnivariate::default(),
            r4: SharedUnivariate::default(),
            r5: SharedUnivariate::default(),
            r6: SharedUnivariate::default(),
            r7: SharedUnivariate::default(),
            r8: SharedUnivariate::default(),
            r9: SharedUnivariate::default(),
            r10: SharedUnivariate::default(),
            r11: SharedUnivariate::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorAccumulatorTransferRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r1.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r2.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r3.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r4.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r5.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r6.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r7.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r8.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r9.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r10.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r11.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut SharedUnivariate<T, P, SIZE>,
        extended_random_poly: &Univariate<P::ScalarField, SIZE>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r1.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r2.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r3.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r4.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r5.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r6.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r7.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r8.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r9.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r10.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r11.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

pub(crate) struct TranslatorAccumulatorTransferRelation {}

impl TranslatorAccumulatorTransferRelation {
    pub(crate) const NUM_RELATIONS: usize = 12;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorAccumulatorTransferRelation
{
    type Acc = TranslatorAccumulatorTransferRelationAcc<T, P>;
    type VerifyAcc = ();

    fn can_skip(
        _entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
    ) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, TranslatorFlavour>,
    ) {
        batch.add_lagrange_odd_in_minicircuit(entity);
        batch.add_lagrange_result_row(entity);
        batch.add_lagrange_last_in_minicircuit(entity);
        batch.add_accumulators_binary_limbs_0_shift(entity);
        batch.add_accumulators_binary_limbs_1_shift(entity);
        batch.add_accumulators_binary_limbs_2_shift(entity);
        batch.add_accumulators_binary_limbs_3_shift(entity);
        batch.add_accumulators_binary_limbs_0(entity);
        batch.add_accumulators_binary_limbs_1(entity);
        batch.add_accumulators_binary_limbs_2(entity);
        batch.add_accumulators_binary_limbs_3(entity);
    }

    /**
     * @brief Expression for enforcing the value of the Opcode to be {0,3,4,8} (nop, eq and reset, mul or add)
     * @details This relation enforces the opcode to be one of described values. Since we don't care about even
     * values in the opcode wire and usually just set them to zero, we don't use a lagrange polynomial to specify
     * the relation to be enforced just at odd indices, which brings the degree down by 1.
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate TranslatorAccumulatorTransferRelation");
        let lagrange_odd_in_minicircuit = input.precomputed.lagrange_odd_in_minicircuit();

        // Lagrange ensuring the accumulator result is validated at the correct row
        let lagrange_result_row = input.precomputed.lagrange_result_row();

        // Lagrange at index (size of minicircuit - 1) is used to enforce that the accumulator is initialized to zero in the
        // circuit
        let lagrange_last_in_minicircuit = input.precomputed.lagrange_last_in_minicircuit();

        let accumulators_binary_limbs_0 = input.witness.accumulators_binary_limbs_0();
        let accumulators_binary_limbs_1 = input.witness.accumulators_binary_limbs_1();
        let accumulators_binary_limbs_2 = input.witness.accumulators_binary_limbs_2();
        let accumulators_binary_limbs_3 = input.witness.accumulators_binary_limbs_3();
        let accumulators_binary_limbs_0_shift =
            input.shifted_witness.accumulators_binary_limbs_0_shift();
        let accumulators_binary_limbs_1_shift =
            input.shifted_witness.accumulators_binary_limbs_1_shift();
        let accumulators_binary_limbs_2_shift =
            input.shifted_witness.accumulators_binary_limbs_2_shift();
        let accumulators_binary_limbs_3_shift =
            input.shifted_witness.accumulators_binary_limbs_3_shift();

        // Contribution (1) (1-4 ensure transfer of accumulator limbs at odd indices of the minicircuit)
        let mut tmp_1 = T::sub_many(
            accumulators_binary_limbs_0,
            accumulators_binary_limbs_0_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_1, lagrange_odd_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_1, scaling_factors);
        fold_accumulator!(univariate_accumulator.r0, tmp_1, SIZE);

        // Contribution (2)
        let mut tmp_2 = T::sub_many(
            accumulators_binary_limbs_1,
            accumulators_binary_limbs_1_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_2, lagrange_odd_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_2, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp_2, SIZE);

        // Contribution (3)
        let mut tmp_3 = T::sub_many(
            accumulators_binary_limbs_2,
            accumulators_binary_limbs_2_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_3, lagrange_odd_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_3, scaling_factors);
        fold_accumulator!(univariate_accumulator.r2, tmp_3, SIZE);

        // Contribution (4)
        let mut tmp_4 = T::sub_many(
            accumulators_binary_limbs_3,
            accumulators_binary_limbs_3_shift,
        );
        T::mul_assign_with_public_many(&mut tmp_4, lagrange_odd_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_4, scaling_factors);
        fold_accumulator!(univariate_accumulator.r3, tmp_4, SIZE);

        // Contribution (5) (5-9 ensure that accumulator starts with zeroed-out limbs)
        let mut tmp_5 = accumulators_binary_limbs_0.to_owned();
        T::mul_assign_with_public_many(&mut tmp_5, lagrange_last_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_5, scaling_factors);
        fold_accumulator!(univariate_accumulator.r4, tmp_5, SIZE);

        // Contribution (6)
        let mut tmp_6 = accumulators_binary_limbs_1.to_owned();
        T::mul_assign_with_public_many(&mut tmp_6, lagrange_last_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_6, scaling_factors);
        fold_accumulator!(univariate_accumulator.r5, tmp_6, SIZE);

        // Contribution (7)
        let mut tmp_7 = accumulators_binary_limbs_2.to_owned();
        T::mul_assign_with_public_many(&mut tmp_7, lagrange_last_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_7, scaling_factors);
        fold_accumulator!(univariate_accumulator.r6, tmp_7, SIZE);

        // Contribution (8)
        let mut tmp_8 = accumulators_binary_limbs_3.to_owned();
        T::mul_assign_with_public_many(&mut tmp_8, lagrange_last_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp_8, scaling_factors);
        fold_accumulator!(univariate_accumulator.r7, tmp_8, SIZE);

        // Contribution (9) (9-12 ensure the output is as stated, we basically use this to get the result out of the
        //  proof)
        let mut tmp_9 = T::mul_with_public_many(
            lagrange_result_row,
            &T::add_scalar(
                accumulators_binary_limbs_0,
                -relation_parameters.accumulated_result[0],
                state.id(),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_9, scaling_factors);
        fold_accumulator!(univariate_accumulator.r8, tmp_9, SIZE);

        // Contribution (10)
        let mut tmp_10 = T::mul_with_public_many(
            lagrange_result_row,
            &T::add_scalar(
                accumulators_binary_limbs_1,
                -relation_parameters.accumulated_result[1],
                state.id(),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_10, scaling_factors);
        fold_accumulator!(univariate_accumulator.r9, tmp_10, SIZE);

        // Contribution (11)
        let mut tmp_11 = T::mul_with_public_many(
            lagrange_result_row,
            &T::add_scalar(
                accumulators_binary_limbs_2,
                -relation_parameters.accumulated_result[2],
                state.id(),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_11, scaling_factors);
        fold_accumulator!(univariate_accumulator.r10, tmp_11, SIZE);

        // Contribution (12)
        let mut tmp_12 = T::mul_with_public_many(
            lagrange_result_row,
            &T::add_scalar(
                accumulators_binary_limbs_3,
                -relation_parameters.accumulated_result[3],
                state.id(),
            ),
        );
        T::mul_assign_with_public_many(&mut tmp_12, scaling_factors);
        fold_accumulator!(univariate_accumulator.r11, tmp_12, SIZE);
        Ok(())
    }
}
