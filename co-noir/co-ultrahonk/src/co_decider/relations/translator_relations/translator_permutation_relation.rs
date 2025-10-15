use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{
    flavours::translator_flavour::TranslatorFlavour,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour,
};
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorPermutationRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for TranslatorPermutationRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorPermutationRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r1.scale_inplace(*current_scalar);
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
    }
}

pub(crate) struct TranslatorPermutationRelation {}

impl TranslatorPermutationRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    fn compute_grand_product_numerator_and_denominator_batch<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
        let interleaved_range_constraints_0 = input.witness.interleaved_range_constraints_0();
        let interleaved_range_constraints_1 = input.witness.interleaved_range_constraints_1();
        let interleaved_range_constraints_2 = input.witness.interleaved_range_constraints_2();
        let interleaved_range_constraints_3 = input.witness.interleaved_range_constraints_3();
        let ordered_range_constraints_0 = input.witness.ordered_range_constraints_0();
        let ordered_range_constraints_1 = input.witness.ordered_range_constraints_1();
        let ordered_range_constraints_2 = input.witness.ordered_range_constraints_2();
        let ordered_range_constraints_3 = input.witness.ordered_range_constraints_3();
        let ordered_range_constraints_4 = input.witness.ordered_range_constraints_4();
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm_shift();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();
        let ordered_extra_range_constraints_numerator = input
            .precomputed
            .ordered_extra_range_constraints_numerator();

        let lagrange_masking = input.precomputed.lagrange_masking();
        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let lagrange_masking_beta = lagrange_masking.iter().map(|x| *x * beta).collect_vec();
        let lagrange_first_z_perm = T::add_with_public_many(lagrange_first, z_perm, state.id());
        let lagrange_last_z_perm_shift =
            T::add_with_public_many(lagrange_last, z_perm_shift, state.id());
        let mut factor1_1 = T::add_with_public_many(
            &lagrange_masking_beta,
            interleaved_range_constraints_0,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor1_1, gamma, state.id());
        let mut factor1_2 = T::add_with_public_many(
            &lagrange_masking_beta,
            interleaved_range_constraints_1,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor1_2, gamma, state.id());
        let mut factor1_3 = T::add_with_public_many(
            &lagrange_masking_beta,
            interleaved_range_constraints_2,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor1_3, gamma, state.id());
        let mut factor1_4 = T::add_with_public_many(
            &lagrange_masking_beta,
            interleaved_range_constraints_3,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor1_4, gamma, state.id());

        // This one is public
        let factor1_5 = lagrange_masking_beta
            .iter()
            .zip(ordered_extra_range_constraints_numerator.iter())
            .map(|(a, b)| *a + b + gamma)
            .collect_vec();

        let mut factor2_1 = T::add_with_public_many(
            &lagrange_masking_beta,
            ordered_range_constraints_0,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor2_1, gamma, state.id());
        let mut factor2_2 = T::add_with_public_many(
            &lagrange_masking_beta,
            ordered_range_constraints_1,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor2_2, gamma, state.id());
        let mut factor2_3 = T::add_with_public_many(
            &lagrange_masking_beta,
            ordered_range_constraints_2,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor2_3, gamma, state.id());
        let mut factor2_4 = T::add_with_public_many(
            &lagrange_masking_beta,
            ordered_range_constraints_3,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor2_4, gamma, state.id());
        let mut factor2_5 = T::add_with_public_many(
            &lagrange_masking_beta,
            ordered_range_constraints_4,
            state.id(),
        );
        T::add_scalar_in_place(&mut factor2_5, gamma, state.id());

        let capacity =
            factor1_1.len() + factor1_3.len() + factor2_1.len() + factor2_3.len() + factor2_5.len();
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(factor1_1);
        rhs.extend(factor1_2);
        lhs.extend(factor1_3);
        rhs.extend(factor1_4);

        lhs.extend(factor2_1);
        rhs.extend(factor2_2);
        lhs.extend(factor2_3);
        rhs.extend(factor2_4);
        lhs.extend(factor2_5);
        rhs.extend(lagrange_last_z_perm_shift);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 5).collect_vec();
        debug_assert_eq!(mul.len(), 5);

        let capacity = mul[0].len() + mul[2].len();
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        let factor1_5 = T::mul_with_public_many(&factor1_5, &lagrange_first_z_perm);
        let last_factor_denominator = mul[4];
        lhs.extend(mul[0].to_owned());
        rhs.extend(mul[1].to_owned());
        lhs.extend(mul[2].to_owned());
        rhs.extend(mul[3].to_owned());
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let capacity = mul[0].len() + mul[1].len();
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(mul[0].to_owned());
        rhs.extend(factor1_5);
        lhs.extend(mul[1].to_owned());
        rhs.extend(last_factor_denominator);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let mut result = mul[0].to_owned();
        T::sub_assign_many(&mut result, mul[1]);
        T::mul_assign_with_public_many(&mut result, scaling_factors);

        Ok(result)
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorPermutationRelation
{
    type Acc = TranslatorPermutationRelationAcc<T, P>;
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
        batch.add_interleaved_range_constraints_0(entity);
        batch.add_interleaved_range_constraints_1(entity);
        batch.add_interleaved_range_constraints_2(entity);
        batch.add_interleaved_range_constraints_3(entity);
        batch.add_ordered_range_constraints_0(entity);
        batch.add_ordered_range_constraints_1(entity);
        batch.add_ordered_range_constraints_2(entity);
        batch.add_ordered_range_constraints_3(entity);
        batch.add_ordered_range_constraints_4(entity);
        batch.add_z_perm(entity);
        batch.z_perm_shift(entity);
        batch.add_lagrange_first(entity);
        batch.add_lagrange_last(entity);
        batch.add_lagrange_masking(entity);
        batch.add_ordered_extra_range_constraints_numerator(entity);
    }

    /**
     * @brief Expression for the generalized permutation sort gate.
     * @details The relation is defined as C(in(X)...) =
     *    q_delta_range * \sum{ i = [0, 3]} \alpha^i D_i(D_i - 1)(D_i - 2)(D_i - 3)
     *      where
     *      D_0 = w_2 - w_1
     *      D_1 = w_3 - w_2
     *      D_2 = w_4 - w_3
     *      D_3 = w_1_shift - w_4
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
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate TranslatorPermutationRelation");

        let z_perm_shift = input.shifted_witness.z_perm_shift();
        let lagrange_last = input.precomputed.lagrange_last();
        let result =
            TranslatorPermutationRelation::compute_grand_product_numerator_and_denominator_batch(
                net,
                state,
                input,
                relation_parameters,
                scaling_factors,
            )?;

        fold_accumulator!(univariate_accumulator.r0, result, SIZE);
        let mut tmp = T::mul_with_public_many(lagrange_last, z_perm_shift);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);
        Ok(())
    }
}
