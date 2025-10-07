use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::{
    HonkProofResult, flavours::eccvm_flavour::ECCVMFlavour,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour, prelude::HonkCurve,
};
use common::{mpc::NoirUltraHonkProver, transcript::TranscriptFieldType};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EccPointTableRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 6>,
    pub(crate) r2: SharedUnivariate<T, P, 6>,
    pub(crate) r3: SharedUnivariate<T, P, 6>,
    pub(crate) r4: SharedUnivariate<T, P, 6>,
    pub(crate) r5: SharedUnivariate<T, P, 6>,
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccPointTableRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
            r2: SharedUnivariate::default(),
            r3: SharedUnivariate::default(),
            r4: SharedUnivariate::default(),
            r5: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct EccPointTableRelation {}
impl EccPointTableRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 20;
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccPointTableRelationAcc<T, P> {
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
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccPointTableRelation
{
    type Acc = EccPointTableRelationAcc<T, P>;
    type VerifyAcc = (); // Not need for ECCVM

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_precompute_tx(entity);
        batch.add_precompute_tx_shift(entity);
        batch.add_precompute_ty(entity);
        batch.add_precompute_ty_shift(entity);
        batch.add_precompute_dx(entity);
        batch.add_precompute_dx_shift(entity);
        batch.add_precompute_dy(entity);
        batch.add_precompute_dy_shift(entity);
        batch.add_precompute_point_transition(entity);
        batch.add_lagrange_first(entity);
    }

    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let id = state.id();

        let tx = input.witness.precompute_tx();
        let tx_shift = input.shifted_witness.precompute_tx_shift();
        let ty = input.witness.precompute_ty();
        let ty_shift = input.shifted_witness.precompute_ty_shift();
        let dx = input.witness.precompute_dx();
        let dx_shift = input.shifted_witness.precompute_dx_shift();
        let dy = input.witness.precompute_dy();
        let dy_shift = input.shifted_witness.precompute_dy_shift();
        let precompute_point_transition = input.witness.precompute_point_transition();
        let mut lagrange_first_modified = input.precomputed.lagrange_first().to_owned();
        let minus_one = P::ScalarField::from(-1);
        lagrange_first_modified
            .iter_mut()
            .zip_eq(scaling_factors)
            .for_each(|(x, y)| {
                *x = *x * minus_one + P::ScalarField::one();
                *x *= *y;
            });

        /*
         * @brief Row structure
         *
         * Consider the set of (128-bit scalar multiplier, point, pc) tuples in the transcript columns.
         * The point table columns process one tuple every 8 rows. The tuple with the largest pc value is first.
         * When transitioning between tuple elements, pc decrements by 1.
         *
         * The following table gives an example for two points.
         * In the table, the point associated with `pc = 1` is labelled P.
         *               the point associated with `pc = 0` is labelled Q.
         *
         * | precompute_pc | precompute_point_transition  | precompute_round | Tx    | Ty    | Dx   | Dy   |
         * | -------- | ----------------------- | ----------- | ----- | ----- | ---- | ---- |
         * | 1        | 0                       |           0 |15P.x | 15P.y | 2P.x | 2P.y |
         * | 1        | 0                       |           1 |13P.x | 13P.y | 2P.x | 2P.y |
         * | 1        | 0                       |           2 |11P.x | 11P.y | 2P.x | 2P.y |
         * | 1        | 0                       |           3 | 9P.x |  9P.y | 2P.x | 2P.y |
         * | 1        | 0                       |           4 | 7P.x |  7P.y | 2P.x | 2P.y |
         * | 1        | 0                       |           5 | 5P.x |  5P.y | 2P.x | 2P.y |
         * | 1        | 0                       |           6 | 3P.x |  3P.y | 2P.x | 2P.y |
         * | 1        | 1                       |           7 |  P.x |   P.y | 2P.x | 2P.y |
         * | 0        | 0                       |           0 |15Q.x | 15Q.y | 2Q.x | 2Q.y |
         * | 0        | 0                       |           1 |13Q.x | 13Q.y | 2Q.x | 2Q.y |
         * | 0        | 0                       |           2 |11Q.x | 11Q.y | 2Q.x | 2Q.y |
         * | 0        | 0                       |           3 | 9Q.x |  9Q.y | 2Q.x | 2Q.y |
         * | 0        | 0                       |           4 | 7Q.x |  7Q.y | 2Q.x | 2Q.y |
         * | 0        | 0                       |           5 | 5Q.x |  5Q.y | 2Q.x | 2Q.y |
         * | 0        | 0                       |           6 | 3Q.x |  3Q.y | 2Q.x | 2Q.y |
         * | 0        | 1                       |           7 |  Q.x |   Q.y | 2Q.x | 2Q.y |
         *
         * We apply the following relations to constrain the above table:
         *
         * 1. If precompute_point_transition = 0, (Dx, Dy) = (Dx_shift, Dy_shift)
         * 2. If precompute_point_transition = 1, (Dx, Dy) = 2 (Px, Py)
         * 3. If precompute_point_transition = 0, (Tx, Ty) = (Tx_shift, Ty_shift) + (Dx, Dy)
         *
         * The relations that constrain `precompute_point_transition` and `precompute_pc` are in `ecc_wnaf_relation.hpp`
         *
         * When precompute_point_transition = 1, we use a strict lookup protocol in `ecc_set_relation.hpp` to validate (pc,
         * Tx, Ty) belong to the set of points present in our transcript columns.
         * ("strict" lookup protocol = every item in the table must be read from once, and only once)
         *
         * For every row, we use a lookup protocol in `ecc_lookup_relation.hpp` to write the following tuples into a lookup
         * table:
         * 1. (pc, 15 - precompute_round, Tx, Ty)
         * 2. (pc, precompute_round, Tx, -Ty)
         *
         * The value `15 - precompute_round` describes the multiplier applied to P at the current row.
         * (this can be expanded into a wnaf value by taking `2x - 15` where `x = 15 - precompute_round`) .
         * The value `precompute_round` describes the *negative multiplier* applied to P at the current row.
         * This is also expanded into a wnaf value by taking `2x - 15` where `x = precompute_round`.
         *
         * The following table describes how taking (15 - precompute_round) for positive values and (precompute_round) for
         * negative values produces the WNAF slice values that correspond to the multipliers for (Tx, Ty) and (Tx, -Ty):
         *
         * | Tx    | Ty    | x = 15 - precompute_round | 2x - 15 | y = precompute_round | 2y - 15 |
         * | ----- | ----- | -------------------- | ------- | --------------- | ------- |
         * | 15P.x | 15P.y | 15                   |      15 |               0 |     -15 |
         * | 13P.x | 13P.y | 14                   |      13 |               1 |     -13 |
         * | 11P.x | 11P.y | 13                   |      11 |               2 |     -11 |
         * |  9P.x |  9P.y | 12                   |       9 |               3 |      -9 |
         * |  7P.x |  7P.y | 11                   |       7 |               4 |      -7 |
         * |  5P.x |  5P.y | 10                   |       5 |               5 |      -5 |
         * |  3P.x |  3P.y |  9                   |       3 |               6 |      -3 |
         * |   P.x |   P.y |  8                   |       1 |               7 |      -1 |
         */
        /*
         * @brief Validate Dx, Dy correctness relation
         *
         * When computing a point table for point [P] = (Px, Py), we require [D] (Dx, Dy) = 2.[P]
         * If all other relations are satisfied, we know that (Tx, Ty) = (Px, Py)
         * i.e. (Dx, Dy) = 2(Px, Py) when precompute_round_transition = 1.
         *
         * Double formula:
         * x_3 = 9x^4 / 4y^2 - 2x
         * y_3 = (3x^2 / 2y) * (x - x_3) - y
         *
         * Expanding into relations:
         * (x_3 + 2x) * 4y^2 - 9x^4 = 0
         * (y3 + y) * 2y - 3x^2 * (x - x_3) = 0
         */
        let mut two_x = tx.to_owned();
        T::scale_many_in_place(&mut two_x, P::ScalarField::from(2u64));
        let three_x = T::add_many(&two_x, tx);
        let mut two_y = ty.to_owned();
        T::scale_many_in_place(&mut two_y, P::ScalarField::from(2u64));
        let mut lhs = Vec::with_capacity(three_x.len() + two_y.len());
        let mut rhs = Vec::with_capacity(three_x.len() + two_y.len());
        lhs.extend(three_x);
        lhs.extend(two_y.clone());
        rhs.extend(tx);
        rhs.extend(two_y.clone());
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let three_xx = mul[0];
        let four_yy = mul[1];
        let mut lhs = Vec::with_capacity(
            three_xx.len() + ty.len() + three_xx.len() + three_xx.len() + dx.len(),
        );
        let mut rhs = Vec::with_capacity(
            three_xx.len() + ty.len() + three_xx.len() + three_xx.len() + dx.len(),
        );
        lhs.extend(three_xx);
        lhs.extend(T::add_many(ty, dy));
        lhs.extend(three_xx);
        lhs.extend(three_xx);
        lhs.extend(T::add_many(dx, &two_x));

        rhs.extend(three_xx);
        rhs.extend(two_y);
        rhs.extend(dx);
        rhs.extend(tx);
        rhs.extend(four_yy);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 5).collect_vec();
        debug_assert_eq!(mul.len(), 5);

        let nine_xxxx = mul[0];
        let y_double_check = T::add_many(mul[1], &T::sub_many(mul[2], mul[3]));
        let x_double_check = T::sub_many(mul[4], nine_xxxx);
        let x_double_check = x_double_check
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        let y_double_check = y_double_check
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();

        /*
         * @brief If precompute_round_transition = 0, (Dx_shift, Dy_shift) = (Dx, Dy)
         *
         * 1st row is empty => don't apply if lagrange_first == 1
         */

        /*
         * @brief Valdiate (Tx, Ty) is correctly computed from (Tx_shift, Ty_shift), (Dx, Dy).
         *        If precompute_round_transition = 0, [T] = [T_shift] + [D].
         *
         * Add formula:
         * x_3 = (y_2 - y_1)^2 / (x_2 - x_1)^2 - x_2 - x_1
         * y_3 = ((y_2 - y_1) / (x_2 - x_1)) * (x_1 - x_3) - y_1
         *
         * Expanding into relations:
         * (x_3 + x_2 + x_1) * (x_2 - x_1)^2 - (y_2 - y_1)^2 = 0
         * (y_3 + y_1) * (x_2 - x_1) + (x_3 - x_1) * (y_2 - y_1) = 0
         *
         * We don't need to check for incomplete point addition edge case (x_1 == x_2)
         * AZTEC TODO explain why (computing simple point multiples cannot trigger the edge cases, but need to serve a proof of
         * this...)
         */
        let x1 = tx_shift;
        let y1 = ty_shift;
        let x2 = dx;
        let y2 = dy;
        let x3 = tx;
        let y3 = ty;
        let mut lambda_numerator = y1.to_owned();
        T::scale_many_in_place(&mut lambda_numerator, minus_one);
        T::add_assign_many(&mut lambda_numerator, y2);
        let mut lambda_denominator = x1.to_owned();
        T::scale_many_in_place(&mut lambda_denominator, minus_one);
        T::add_assign_many(&mut lambda_denominator, x2);

        let mut precompute_point_transition_modified = precompute_point_transition.to_owned();
        T::scale_many_in_place(&mut precompute_point_transition_modified, minus_one);
        T::add_scalar_in_place(
            &mut precompute_point_transition_modified,
            P::ScalarField::one(),
            id,
        );
        T::mul_assign_with_public_many(
            &mut precompute_point_transition_modified,
            &lagrange_first_modified,
        );

        let mut dx_shift_neg = dx_shift.to_owned();
        T::scale_many_in_place(&mut dx_shift_neg, minus_one);
        let mut dy_shift_neg = dy_shift.to_owned();
        T::scale_many_in_place(&mut dy_shift_neg, minus_one);

        let mut lhs = Vec::with_capacity(
            x_double_check.len()
                + y_double_check.len()
                + 2 * precompute_point_transition_modified.len()
                + 3 * lambda_denominator.len()
                + 3 * lambda_numerator.len(),
        );
        let mut rhs = Vec::with_capacity(
            x_double_check.len()
                + y_double_check.len()
                + 2 * precompute_point_transition_modified.len()
                + 3 * lambda_denominator.len()
                + 3 * lambda_numerator.len(),
        );
        lhs.extend(x_double_check);
        lhs.extend(y_double_check);
        lhs.extend(precompute_point_transition_modified.clone());
        lhs.extend(precompute_point_transition_modified.clone());
        lhs.extend(lambda_denominator.clone());
        lhs.extend(lambda_numerator.clone());
        lhs.extend(lambda_denominator.clone());
        lhs.extend(lambda_denominator.clone());
        lhs.extend(lambda_numerator.clone());
        lhs.extend(lambda_numerator.clone());

        rhs.extend(precompute_point_transition.clone());
        rhs.extend(precompute_point_transition);
        rhs.extend(T::add_many(&dx_shift_neg, dx));
        rhs.extend(T::add_many(&dy_shift_neg, dy));
        rhs.extend(lambda_denominator);
        rhs.extend(lambda_numerator);
        rhs.extend(y3);
        rhs.extend(y1);
        rhs.extend(x3);
        rhs.extend(x1);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 10).collect_vec();
        debug_assert_eq!(mul.len(), 10);

        let tmp0 = mul[0].to_owned();
        fold_accumulator!(univariate_accumulator.r0, tmp0, SIZE);
        let tmp1 = mul[1].to_owned();
        fold_accumulator!(univariate_accumulator.r1, tmp1, SIZE);
        let tmp2 = mul[2].to_owned();
        fold_accumulator!(univariate_accumulator.r2, tmp2, SIZE);
        let tmp3 = mul[3].to_owned();
        fold_accumulator!(univariate_accumulator.r3, tmp3, SIZE);

        let mul_2 = T::mul_many(&T::add_many(x3, &T::add_many(x2, x1)), mul[4], net, state)?;

        let x_add_check = T::sub_many(&mul_2, mul[5]);

        let y_add_check = T::add_many(&T::add_many(mul[6], mul[7]), &T::sub_many(mul[8], mul[9]));
        let mut lhs = Vec::with_capacity(2 * precompute_point_transition_modified.len());
        let mut rhs = Vec::with_capacity(2 * precompute_point_transition_modified.len());
        lhs.extend(precompute_point_transition_modified.clone());
        lhs.extend(precompute_point_transition_modified);
        rhs.extend(x_add_check);
        rhs.extend(y_add_check);
        let tmp = T::mul_many(&lhs, &rhs, net, state)?;
        let tmp = tmp.chunks_exact(tmp.len() / 2).collect_vec();
        debug_assert_eq!(tmp.len(), 2);
        fold_accumulator!(univariate_accumulator.r4, tmp[0], SIZE);
        fold_accumulator!(univariate_accumulator.r5, tmp[1], SIZE);
        Ok(())
    }
}
