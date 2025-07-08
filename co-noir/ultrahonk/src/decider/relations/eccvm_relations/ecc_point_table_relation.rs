use crate::{
    decider::relations::Relation, plain_prover_flavour::UnivariateTrait, prelude::Univariate,
};
use ark_ff::PrimeField;
use co_builder::{
    flavours::eccvm_flavour::ECCVMFlavour,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct EccPointTableRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 6>,
    pub(crate) r3: Univariate<F, 6>,
    pub(crate) r4: Univariate<F, 6>,
    pub(crate) r5: Univariate<F, 6>,
}
#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct EccPointTableRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
    pub(crate) r4: F,
    pub(crate) r5: F,
}

pub(crate) struct EccPointTableRelation {}
impl EccPointTableRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
}

impl<F: PrimeField> EccPointTableRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
        *current_scalar *= challenge;
        self.r2 *= *current_scalar;
        *current_scalar *= challenge;
        self.r3 *= *current_scalar;
        *current_scalar *= challenge;
        self.r4 *= *current_scalar;
        *current_scalar *= challenge;
        self.r5 *= *current_scalar;
        *current_scalar *= challenge;
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
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

impl<F: PrimeField> Relation<F, ECCVMFlavour> for EccPointTableRelation {
    type Acc = EccPointTableRelationAcc<F>;

    type VerifyAcc = EccPointTableRelationEvals<F>;

    const SKIPPABLE: bool = false;

    fn skip<const SIZE: usize>(
        _input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> bool {
        false
    }

    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        _relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        scaling_factor: &F,
    ) {
        let tx = input.witness.precompute_tx();
        let tx_shift = input.shifted_witness.precompute_tx_shift();
        let ty = input.witness.precompute_ty();
        let ty_shift = input.shifted_witness.precompute_ty_shift();
        let dx = input.witness.precompute_dx();
        let dx_shift = input.shifted_witness.precompute_dx_shift();
        let dy = input.witness.precompute_dy();
        let dy_shift = input.shifted_witness.precompute_dy_shift();
        let precompute_point_transition = input.witness.precompute_point_transition();
        let lagrange_first = input.precomputed.lagrange_first();

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
        let two_x = tx.to_owned() * F::from(2u64);
        let three_x = two_x.clone() + tx;
        let three_xx = three_x * tx;
        let nine_xxxx = three_xx.clone().sqr();
        let two_y = ty.to_owned() * F::from(2u64);
        let four_yy = two_y.clone().sqr();
        let x_double_check = (dx.to_owned() + two_x) * four_yy - nine_xxxx;
        let y_double_check = (ty.to_owned() + dy) * two_y + three_xx.clone() * dx - three_xx * tx;
        let tmp = x_double_check * precompute_point_transition * scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = y_double_check * precompute_point_transition * scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        /*
         * @brief If precompute_round_transition = 0, (Dx_shift, Dy_shift) = (Dx, Dy)
         *
         * 1st row is empty => don't apply if lagrange_first == 1
         */
        let minus_one = F::from(-1);

        let tmp = (lagrange_first.to_owned() * minus_one + &F::one())
            * (precompute_point_transition.to_owned() * minus_one + &F::one())
            * (dx_shift.to_owned() * minus_one + dx)
            * scaling_factor;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }
        let tmp = (lagrange_first.to_owned() * minus_one + &F::one())
            * (precompute_point_transition.to_owned() * minus_one + &F::one())
            * (dy_shift.to_owned() * minus_one + dy)
            * scaling_factor;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }
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
         * TODO explain why (computing simple point multiples cannot trigger the edge cases, but need to serve a proof of
         * this...)
         */
        let x1 = tx_shift;
        let y1 = ty_shift;
        let x2 = dx;
        let y2 = dy;
        let x3 = tx;
        let y3 = ty;
        let lambda_numerator = y1.to_owned() * minus_one + y2;
        let lambda_denominator = x1.to_owned() * minus_one + x2;
        let x_add_check = (x3.to_owned() + x2 + x1) * lambda_denominator.clone().sqr()
            - lambda_numerator.clone().sqr();
        let y_add_check = (lambda_denominator.clone() * y3 + lambda_denominator * y1)
            + (lambda_numerator.clone() * x3 + lambda_numerator * minus_one * x1);
        let tmp = (lagrange_first.to_owned() * minus_one + &F::one())
            * (precompute_point_transition.to_owned() * minus_one + &F::one())
            * x_add_check
            * scaling_factor;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }

        let tmp = (lagrange_first.to_owned() * minus_one + &F::one())
            * (precompute_point_transition.to_owned() * minus_one + &F::one())
            * y_add_check
            * scaling_factor;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &crate::prelude::ClaimedEvaluations<F, ECCVMFlavour>,
        _relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        _scaling_factor: &F,
    ) {
        todo!()
    }
}
