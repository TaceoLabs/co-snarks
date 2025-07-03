use super::{Relation, fold_accumulator};
use crate::{
    co_decider::{
        types::{MAX_PARTIAL_RELATION_LENGTH, RelationParameters},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::Zero;
use co_builder::HonkProofResult;
use co_builder::prelude::HonkCurve;
use itertools::Itertools as _;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct DeltaRangeConstraintRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 6>,
    pub(crate) r2: SharedUnivariate<T, P, 6>,
    pub(crate) r3: SharedUnivariate<T, P, 6>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for DeltaRangeConstraintRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> DeltaRangeConstraintRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == DeltaRangeConstraintRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
        self.r2.scale_inplace(elements[2]);
        self.r3.scale_inplace(elements[3]);
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
    }
}

pub(crate) struct DeltaRangeConstraintRelation {}

impl DeltaRangeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 12;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for DeltaRangeConstraintRelation
{
    type Acc = DeltaRangeConstraintRelationAcc<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P>) -> bool {
        entity.precomputed.q_delta_range().is_zero()
    }

    fn add_entites(
        entity: &super::ProverUnivariates<T, P>,
        batch: &mut super::ProverUnivariatesBatch<T, P>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_shifted_w_l(entity);
        batch.add_q_delta_range(entity);
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
    fn accumulate<N: Network>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &super::ProverUnivariatesBatch<T, P>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        let id = state.id();

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let q_delta_range = input.precomputed.q_delta_range();
        let minus_one = -P::ScalarField::one();
        let minus_two = -P::ScalarField::from(2u64);

        // Compute wire differences
        let delta_1 = T::sub_many(w_2, w_1);
        let delta_2 = T::sub_many(w_3, w_2);
        let delta_3 = T::sub_many(w_4, w_3);
        let delta_4 = T::sub_many(w_1_shift, w_4);

        let tmp_1 = T::add_scalar(&delta_1, minus_one, id);
        let tmp_2 = T::add_scalar(&delta_2, minus_one, id);
        let tmp_3 = T::add_scalar(&delta_3, minus_one, id);
        let tmp_4 = T::add_scalar(&delta_4, minus_one, id);
        let tmp_1_2 = T::add_scalar(&delta_1, minus_two, id);
        let tmp_2_2 = T::add_scalar(&delta_2, minus_two, id);
        let tmp_3_2 = T::add_scalar(&delta_3, minus_two, id);
        let tmp_4_2 = T::add_scalar(&delta_4, minus_two, id);

        let mut lhs = Vec::with_capacity(
            tmp_1.len()
                + tmp_2.len()
                + tmp_3.len()
                + tmp_4.len()
                + tmp_1_2.len()
                + tmp_2_2.len()
                + tmp_3_2.len()
                + tmp_4_2.len(),
        );
        lhs.extend(tmp_1);
        lhs.extend(tmp_2);
        lhs.extend(tmp_3);
        lhs.extend(tmp_4);
        lhs.extend(tmp_1_2);
        lhs.extend(tmp_2_2);
        lhs.extend(tmp_3_2);
        lhs.extend(tmp_4_2);

        let mut sqr = T::mul_many(&lhs, &lhs, net, state)?;

        for el in sqr.iter_mut() {
            T::add_assign_public(el, minus_one, id);
        }

        let (lhs, rhs) = sqr.split_at(sqr.len() >> 1);
        let mut mul = T::mul_many(lhs, rhs, net, state)?;
        let q_delta_range = q_delta_range
            .iter()
            .cloned()
            .cycle()
            .take(mul.len())
            .collect_vec();

        let scaling_factors = scaling_factors
            .iter()
            .cloned()
            .cycle()
            .take(mul.len())
            .collect_vec();

        T::mul_assign_with_public_many(&mut mul, &q_delta_range);
        T::mul_assign_with_public_many(&mut mul, &scaling_factors);

        // Contribution (1)
        //let mut tmp = T::mul_with_public(*q_delta_range, mul[0]);
        //tmp.scale_inplace(*scaling_factor);
        let (lhs, rhs) = mul.split_at(mul.len() >> 1);
        let (contribution0, contribution1) = lhs.split_at(lhs.len() >> 1);
        let (contribution2, contribution3) = rhs.split_at(rhs.len() >> 1);

        fold_accumulator!(univariate_accumulator.r0, contribution0);
        fold_accumulator!(univariate_accumulator.r1, contribution1);
        fold_accumulator!(univariate_accumulator.r2, contribution2);
        fold_accumulator!(univariate_accumulator.r3, contribution3);

        Ok(())
    }
}
