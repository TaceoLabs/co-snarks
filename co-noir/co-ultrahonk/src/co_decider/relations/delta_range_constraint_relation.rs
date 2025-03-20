use itertools::{izip, Itertools as _};
use std::time::Instant;

use super::Relation;
use crate::{
    co_decider::{
        relations::{relation_utils, MIN_RAYON_ITER},
        types::{RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_ff::{One, PrimeField};
use co_builder::prelude::HonkCurve;
use co_builder::HonkProofResult;
use rayon::prelude::*;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct DeltaRangeConstraintRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 6>,
    pub(crate) r2: SharedUnivariate<T, P, 6>,
    pub(crate) r3: SharedUnivariate<T, P, 6>,
}

#[derive(Clone, Debug)]
pub(crate) struct DeltaRangeConstraintRelationAccHalfShared<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 6>,
    pub(crate) r3: Univariate<F, 6>,
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

impl<F: PrimeField> Default for DeltaRangeConstraintRelationAccHalfShared<F> {
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

    fn fold_contribution_multithreaded<P: Pairing>(
        contribution: &[P::ScalarField],
        q_delta_range: &[P::ScalarField],
        scaling_factors: &[P::ScalarField],
        acc: &mut Univariate<P::ScalarField, 6>,
    ) {
        let iter = (contribution, q_delta_range, scaling_factors)
            .into_par_iter()
            .with_min_len(MIN_RAYON_ITER)
            .map(|(contribution, q_delta_range, scaling_factor)| {
                *contribution * *q_delta_range * scaling_factor
            });
        relation_utils::accumulate_half_share!(iter, acc)
    }

    fn fold_contribution<P: Pairing>(
        contribution: &[P::ScalarField],
        acc: &mut Univariate<P::ScalarField, 6>,
    ) {
        let evaluations_len = acc.evaluations.len();
        let mut tmp = [P::ScalarField::default(); MAX_PARTIAL_RELATION_LENGTH];
        tmp[..evaluations_len].clone_from_slice(&acc.evaluations);

        for (idx, b) in contribution.iter().enumerate() {
            let a = &mut tmp[idx % MAX_PARTIAL_RELATION_LENGTH];
            *a += b;
        }
        acc.evaluations.clone_from_slice(&tmp[..evaluations_len]);
    }

    fn accumulate_multithreaded<T, P>(
        driver: &mut T,
        univariate_accumulator: &mut DeltaRangeConstraintRelationAccHalfShared<P::ScalarField>,
        input: &super::ProverUnivariatesBatch<T, P>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()>
    where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    {
        let party_id = driver.get_party_id();

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let minus_one = -P::ScalarField::one();
        let minus_two = -P::ScalarField::from(2u64);
        let q_delta_range = input.precomputed.q_delta_range();

        macro_rules! minus_scalar {
            ($lhs: expr, $rhs: expr, $scalar: expr) => {
                ($lhs, $rhs).into_par_iter().map(|(lhs, rhs)| {
                    let tmp = T::sub(*lhs, *rhs);
                    T::add_with_public($scalar, tmp, party_id)
                })
            };
        }

        let (minus_one_iters, minus_two_iters) = rayon::join(
            || {
                relation_utils::rayon_multi_join!(
                    minus_scalar!(w_2, w_1, minus_one),
                    minus_scalar!(w_3, w_2, minus_one),
                    minus_scalar!(w_4, w_3, minus_one),
                    minus_scalar!(w_1_shift, w_4, minus_one)
                )
            },
            || {
                relation_utils::rayon_multi_join!(
                    minus_scalar!(w_2, w_1, minus_two),
                    minus_scalar!(w_3, w_2, minus_two),
                    minus_scalar!(w_4, w_3, minus_two),
                    minus_scalar!(w_1_shift, w_4, minus_two)
                )
            },
        );

        let lhs = minus_one_iters
            .0
            .chain(minus_one_iters.1)
            .chain(minus_one_iters.2)
            .chain(minus_one_iters.3)
            .chain(minus_two_iters.0)
            .chain(minus_two_iters.1)
            .chain(minus_two_iters.2)
            .chain(minus_two_iters.3)
            .collect::<Vec<_>>();

        let mut sqr = driver.mul_many(&lhs, &lhs)?;

        sqr.par_iter_mut().for_each(|el| {
            T::add_assign_public(el, minus_one, party_id);
        });

        let (lhs, rhs) = sqr.split_at(sqr.len() >> 1);
        let mul = driver.local_mul_vec(lhs, rhs);

        let (lhs, rhs) = mul.split_at(mul.len() >> 1);
        let (contribution0, contribution1) = lhs.split_at(lhs.len() >> 1);
        let (contribution2, contribution3) = rhs.split_at(rhs.len() >> 1);

        relation_utils::rayon_multi_join!(
            Self::fold_contribution_multithreaded::<P>(
                contribution0,
                q_delta_range,
                scaling_factors,
                &mut univariate_accumulator.r0,
            ),
            Self::fold_contribution_multithreaded::<P>(
                contribution1,
                q_delta_range,
                scaling_factors,
                &mut univariate_accumulator.r1,
            ),
            Self::fold_contribution_multithreaded::<P>(
                contribution2,
                q_delta_range,
                scaling_factors,
                &mut univariate_accumulator.r2,
            ),
            Self::fold_contribution_multithreaded::<P>(
                contribution3,
                q_delta_range,
                scaling_factors,
                &mut univariate_accumulator.r3,
            )
        );
        Ok(())
    }

    fn accumulate_small<T, P>(
        driver: &mut T,
        univariate_accumulator: &mut DeltaRangeConstraintRelationAccHalfShared<P::ScalarField>,
        input: &super::ProverUnivariatesBatch<T, P>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()>
    where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    {
        let party_id = driver.get_party_id();

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

        let tmp_1 = T::add_scalar(&delta_1, minus_one, party_id);
        let tmp_2 = T::add_scalar(&delta_2, minus_one, party_id);
        let tmp_3 = T::add_scalar(&delta_3, minus_one, party_id);
        let tmp_4 = T::add_scalar(&delta_4, minus_one, party_id);
        let tmp_1_2 = T::add_scalar(&delta_1, minus_two, party_id);
        let tmp_2_2 = T::add_scalar(&delta_2, minus_two, party_id);
        let tmp_3_2 = T::add_scalar(&delta_3, minus_two, party_id);
        let tmp_4_2 = T::add_scalar(&delta_4, minus_two, party_id);

        let mut lhs = Vec::with_capacity(tmp_1.len() * 8);
        lhs.extend(tmp_1);
        lhs.extend(tmp_2);
        lhs.extend(tmp_3);
        lhs.extend(tmp_4);
        lhs.extend(tmp_1_2);
        lhs.extend(tmp_2_2);
        lhs.extend(tmp_3_2);
        lhs.extend(tmp_4_2);

        let mut sqr = driver.mul_many(&lhs, &lhs)?;
        T::add_scalar_in_place(&mut sqr, minus_one, party_id);

        let (lhs, rhs) = sqr.split_at(sqr.len() >> 1);
        let mut mul = driver.local_mul_vec(lhs, rhs);

        let q_delta_range = q_delta_range.iter().cycle();
        let scaling_factors = scaling_factors.iter().cycle();

        izip!(mul.iter_mut(), q_delta_range, scaling_factors).for_each(
            |(mul, q_delta_range, scaling_factor)| *mul *= *q_delta_range * scaling_factor,
        );

        let (lhs, rhs) = mul.split_at(mul.len() >> 1);
        let (contribution0, contribution1) = lhs.split_at(lhs.len() >> 1);
        let (contribution2, contribution3) = rhs.split_at(rhs.len() >> 1);

        Self::fold_contribution::<P>(contribution0, &mut univariate_accumulator.r0);
        Self::fold_contribution::<P>(contribution1, &mut univariate_accumulator.r1);
        Self::fold_contribution::<P>(contribution2, &mut univariate_accumulator.r2);
        Self::fold_contribution::<P>(contribution3, &mut univariate_accumulator.r3);

        Ok(())
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for DeltaRangeConstraintRelation
{
    type Acc = DeltaRangeConstraintRelationAccHalfShared<P::ScalarField>;

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
    fn accumulate(
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &super::ProverUnivariatesBatch<T, P>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        // because this is rather smallish a lot of the times we make a check whether we
        // want to do multithreading
        if scaling_factors.len() > (1 << 14) {
            Self::accumulate_multithreaded(driver, univariate_accumulator, input, scaling_factors)?;
        } else {
            Self::accumulate_small(driver, univariate_accumulator, input, scaling_factors)?;
        }

        Ok(())
    }
}
