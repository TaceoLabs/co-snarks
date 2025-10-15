use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorDeltaRangeConstraintRelationAcc<
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 7>,
    pub(crate) r2: SharedUnivariate<T, P, 7>,
    pub(crate) r3: SharedUnivariate<T, P, 7>,
    pub(crate) r4: SharedUnivariate<T, P, 7>,
    pub(crate) r5: SharedUnivariate<T, P, 3>,
    pub(crate) r6: SharedUnivariate<T, P, 3>,
    pub(crate) r7: SharedUnivariate<T, P, 3>,
    pub(crate) r8: SharedUnivariate<T, P, 3>,
    pub(crate) r9: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default
    for TranslatorDeltaRangeConstraintRelationAcc<T, P>
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
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorDeltaRangeConstraintRelationAcc<T, P> {
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
    }
}

pub(crate) struct TranslatorDeltaRangeConstraintRelation {}

impl TranslatorDeltaRangeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 10;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorDeltaRangeConstraintRelation
{
    type Acc = TranslatorDeltaRangeConstraintRelationAcc<T, P>;
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
        batch.add_ordered_range_constraints_0(entity);
        batch.add_ordered_range_constraints_1(entity);
        batch.add_ordered_range_constraints_2(entity);
        batch.add_ordered_range_constraints_3(entity);
        batch.add_ordered_range_constraints_4(entity);

        batch.add_ordered_range_constraints_0_shift(entity);
        batch.add_ordered_range_constraints_1_shift(entity);
        batch.add_ordered_range_constraints_2_shift(entity);
        batch.add_ordered_range_constraints_3_shift(entity);
        batch.add_ordered_range_constraints_4_shift(entity);

        batch.add_lagrange_real_last(entity);
        batch.add_lagrange_masking(entity);
    }

    /**
     * @brief Expression for the generalized permutation sort relation
     *
     * @details The relation enforces 2 constraints on each of the ordered_range_constraints wires:
     * 1) 2 sequential values are non-descending and have a difference of at most 3, except for the value at last index
     * 2) The value at last index is  2¹⁴ - 1
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate TranslatorDeltaRangeConstraintRelation");

        let minus_one = P::ScalarField::from(-1);
        let minus_two = P::ScalarField::from(-2);
        let minus_three = P::ScalarField::from(-3);
        let micro_limb_bits = 14;
        let maximum_sort_value = -P::ScalarField::from((1 << micro_limb_bits) - 1);

        let ordered_range_constraints_0 = input.witness.ordered_range_constraints_0();
        let ordered_range_constraints_1 = input.witness.ordered_range_constraints_1();
        let ordered_range_constraints_2 = input.witness.ordered_range_constraints_2();
        let ordered_range_constraints_3 = input.witness.ordered_range_constraints_3();
        let ordered_range_constraints_4 = input.witness.ordered_range_constraints_4();
        let ordered_range_constraints_0_shift =
            input.shifted_witness.ordered_range_constraints_0_shift();
        let ordered_range_constraints_1_shift =
            input.shifted_witness.ordered_range_constraints_1_shift();
        let ordered_range_constraints_2_shift =
            input.shifted_witness.ordered_range_constraints_2_shift();
        let ordered_range_constraints_3_shift =
            input.shifted_witness.ordered_range_constraints_3_shift();
        let ordered_range_constraints_4_shift =
            input.shifted_witness.ordered_range_constraints_4_shift();
        // Represents the positon of the final non masked witness index
        let lagrange_real_last = input.precomputed.lagrange_real_last();
        let lagrange_masking = input.precomputed.lagrange_masking();

        let is_last_witness_or_masking = lagrange_real_last
            .iter()
            .zip_eq(lagrange_masking.iter())
            .map(|(a, b)| (*a - P::ScalarField::one()) * (*b - P::ScalarField::one()))
            .collect::<Vec<_>>();

        // Compute wire differences
        let delta_1 = T::sub_many(
            ordered_range_constraints_0_shift,
            ordered_range_constraints_0,
        );
        let delta_2 = T::sub_many(
            ordered_range_constraints_1_shift,
            ordered_range_constraints_1,
        );
        let delta_3 = T::sub_many(
            ordered_range_constraints_2_shift,
            ordered_range_constraints_2,
        );
        let delta_4 = T::sub_many(
            ordered_range_constraints_3_shift,
            ordered_range_constraints_3,
        );
        let delta_5 = T::sub_many(
            ordered_range_constraints_4_shift,
            ordered_range_constraints_4,
        );

        // Contribution (1) (contributions 1-5 ensure that the sequential values have a difference of {0,1,2,3})
        let delta_1_minus_one = T::add_scalar(&delta_1, minus_one, state.id());
        let delta_1_minus_two = T::add_scalar(&delta_1, minus_two, state.id());
        let delta_1_minus_three = T::add_scalar(&delta_1, minus_three, state.id());

        // Contribution (2)
        let delta_2_minus_one = T::add_scalar(&delta_2, minus_one, state.id());
        let delta_2_minus_two = T::add_scalar(&delta_2, minus_two, state.id());
        let delta_2_minus_three = T::add_scalar(&delta_2, minus_three, state.id());

        // Contribution (3)
        let delta_3_minus_one = T::add_scalar(&delta_3, minus_one, state.id());
        let delta_3_minus_two = T::add_scalar(&delta_3, minus_two, state.id());
        let delta_3_minus_three = T::add_scalar(&delta_3, minus_three, state.id());

        // Contribution (4)
        let delta_4_minus_one = T::add_scalar(&delta_4, minus_one, state.id());
        let delta_4_minus_two = T::add_scalar(&delta_4, minus_two, state.id());
        let delta_4_minus_three = T::add_scalar(&delta_4, minus_three, state.id());

        // Contribution (5)
        let delta_5_minus_one = T::add_scalar(&delta_5, minus_one, state.id());
        let delta_5_minus_two = T::add_scalar(&delta_5, minus_two, state.id());
        let delta_5_minus_three = T::add_scalar(&delta_5, minus_three, state.id());

        let capacity = delta_1.len() * 10;
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(delta_1);
        rhs.extend(delta_1_minus_one);
        lhs.extend(delta_1_minus_two);
        rhs.extend(delta_1_minus_three);
        lhs.extend(delta_2);
        rhs.extend(delta_2_minus_one);
        lhs.extend(delta_2_minus_two);
        rhs.extend(delta_2_minus_three);
        lhs.extend(delta_3);
        rhs.extend(delta_3_minus_one);
        lhs.extend(delta_3_minus_two);
        rhs.extend(delta_3_minus_three);
        lhs.extend(delta_4);
        rhs.extend(delta_4_minus_one);
        lhs.extend(delta_4_minus_two);
        rhs.extend(delta_4_minus_three);
        lhs.extend(delta_5);
        rhs.extend(delta_5_minus_one);
        lhs.extend(delta_5_minus_two);
        rhs.extend(delta_5_minus_three);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 10).collect_vec();
        debug_assert_eq!(mul.len(), 10);
        let mut lhs = Vec::with_capacity(capacity / 2);
        let mut rhs = Vec::with_capacity(capacity / 2);
        lhs.extend(mul[0]);
        rhs.extend(mul[1]);
        lhs.extend(mul[2]);
        rhs.extend(mul[3]);
        lhs.extend(mul[4]);
        rhs.extend(mul[5]);
        lhs.extend(mul[6]);
        rhs.extend(mul[7]);
        lhs.extend(mul[8]);
        rhs.extend(mul[9]);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 5).collect_vec();
        debug_assert_eq!(mul.len(), 5);

        let mut delta_1_result = mul[0].to_owned();
        T::mul_assign_with_public_many(&mut delta_1_result, &is_last_witness_or_masking);
        T::mul_assign_with_public_many(&mut delta_1_result, scaling_factors);
        let mut delta_2_result = mul[1].to_owned();
        T::mul_assign_with_public_many(&mut delta_2_result, &is_last_witness_or_masking);
        T::mul_assign_with_public_many(&mut delta_2_result, scaling_factors);
        let mut delta_3_result = mul[2].to_owned();
        T::mul_assign_with_public_many(&mut delta_3_result, &is_last_witness_or_masking);
        T::mul_assign_with_public_many(&mut delta_3_result, scaling_factors);
        let mut delta_4_result = mul[3].to_owned();
        T::mul_assign_with_public_many(&mut delta_4_result, &is_last_witness_or_masking);
        T::mul_assign_with_public_many(&mut delta_4_result, scaling_factors);
        let mut delta_5_result = mul[4].to_owned();
        T::mul_assign_with_public_many(&mut delta_5_result, &is_last_witness_or_masking);
        T::mul_assign_with_public_many(&mut delta_5_result, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, delta_1_result, SIZE);
        fold_accumulator!(univariate_accumulator.r1, delta_2_result, SIZE);
        fold_accumulator!(univariate_accumulator.r2, delta_3_result, SIZE);
        fold_accumulator!(univariate_accumulator.r3, delta_4_result, SIZE);
        fold_accumulator!(univariate_accumulator.r4, delta_5_result, SIZE);

        // Contribution (6) (Contributions 6-10 ensure that the last value is the designated maximum value. We don't
        // need to constrain the first value to be 0, because the shift mechanic does this for us)
        let mut tmp_6 = T::add_scalar(ordered_range_constraints_0, maximum_sort_value, state.id());
        T::mul_assign_with_public_many(&mut tmp_6, lagrange_real_last);
        T::mul_assign_with_public_many(&mut tmp_6, scaling_factors);
        fold_accumulator!(univariate_accumulator.r5, tmp_6, SIZE);

        // Contribution (7)
        let mut tmp_7 = T::add_scalar(ordered_range_constraints_1, maximum_sort_value, state.id());
        T::mul_assign_with_public_many(&mut tmp_7, lagrange_real_last);
        T::mul_assign_with_public_many(&mut tmp_7, scaling_factors);
        fold_accumulator!(univariate_accumulator.r6, tmp_7, SIZE);

        // Contribution (8)
        let mut tmp_8 = T::add_scalar(ordered_range_constraints_2, maximum_sort_value, state.id());
        T::mul_assign_with_public_many(&mut tmp_8, lagrange_real_last);
        T::mul_assign_with_public_many(&mut tmp_8, scaling_factors);
        fold_accumulator!(univariate_accumulator.r7, tmp_8, SIZE);

        // Contribution (9)
        let mut tmp_9 = T::add_scalar(ordered_range_constraints_3, maximum_sort_value, state.id());
        T::mul_assign_with_public_many(&mut tmp_9, lagrange_real_last);
        T::mul_assign_with_public_many(&mut tmp_9, scaling_factors);
        fold_accumulator!(univariate_accumulator.r8, tmp_9, SIZE);

        // Contribution (10)
        let mut tmp_10 = T::add_scalar(ordered_range_constraints_4, maximum_sort_value, state.id());
        T::mul_assign_with_public_many(&mut tmp_10, lagrange_real_last);
        T::mul_assign_with_public_many(&mut tmp_10, scaling_factors);
        fold_accumulator!(univariate_accumulator.r9, tmp_10, SIZE);

        Ok(())
    }
}
