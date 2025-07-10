use crate::decider::types::{ClaimedEvaluations, ProverUnivariatesSized, RelationParameters};
use crate::decider::univariate::Univariate;
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::plain_prover_flavour::UnivariateTrait;
use crate::transcript::TranscriptFieldType;
use ark_ff::AdditiveGroup;
use ark_ff::{Field, PrimeField, Zero};
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::prelude::HonkCurve;
#[derive(Clone, Debug, Default)]
pub(crate) struct EllipticRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 6>,
}

impl<F: PrimeField> EllipticRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == EllipticRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
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
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EllipticRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

impl<F: PrimeField> EllipticRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == EllipticRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
    }
}

pub(crate) struct EllipticRelation {}

impl EllipticRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const SKIPPABLE: bool = true;

    pub(crate) fn skip<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> bool {
        // This is the relation implemented manually
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
        input.precomputed.q_elliptic().is_zero()
    }

    /**
     * @brief Expression for the Ultra Arithmetic gate.
     * @details The relation is defined as C(in(X)...) =
     *   AZTEC TODO(#429): steal description from elliptic_widget.hpp
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    pub(crate) fn accumulate<
        P: HonkCurve<TranscriptFieldType>,
        L: PlainProverFlavour,
        const UNIVARIATE_SIZE: usize,
    >(
        univariate_accumulator: &mut EllipticRelationAcc<P::ScalarField>,
        input: &ProverUnivariatesSized<P::ScalarField, L, UNIVARIATE_SIZE>,
        _relation_parameters: &RelationParameters<P::ScalarField, L>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Accumulate EllipticRelation");

        // AZTEC TODO(@zac - williamson #2608 when Pedersen refactor is completed,
        // replace old addition relations with these ones and
        // remove endomorphism coefficient in ecc add gate(not used))

        let x_1 = input.witness.w_r();
        let y_1 = input.witness.w_o();

        let x_2 = input.shifted_witness.w_l();
        let y_2 = input.shifted_witness.w_4();
        let y_3 = input.shifted_witness.w_o();
        let x_3 = input.shifted_witness.w_r();

        let q_sign = input.precomputed.q_l();
        let q_elliptic = input.precomputed.q_elliptic();
        let q_is_double = input.precomputed.q_m();

        // Contribution (1) point addition, x-coordinate check
        // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
        let x_diff = x_2.to_owned() - x_1;
        let y2_sqr = y_2.to_owned().sqr();
        let y1_sqr = y_1.to_owned().sqr();
        let y1y2 = y_1.to_owned() * y_2 * q_sign;
        let x_add_identity =
            (x_3.to_owned() + x_2 + x_1) * x_diff.to_owned().sqr() - y2_sqr - &y1_sqr
                + &y1y2
                + y1y2;

        let q_elliptic_by_scaling = q_elliptic.to_owned() * scaling_factor;
        let q_elliptic_q_double_scaling = q_elliptic_by_scaling.to_owned() * q_is_double;
        let q_elliptic_not_double_scaling = q_elliptic_by_scaling - &q_elliptic_q_double_scaling;
        let mut tmp_1 = x_add_identity * &q_elliptic_not_double_scaling;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2) point addition, x-coordinate check
        // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
        let y1_plus_y3 = y_1.to_owned() + y_3;
        let y_diff = y_2.to_owned() * q_sign - y_1;
        let y_add_identity = y1_plus_y3.to_owned() * x_diff + (x_3.to_owned() - x_1) * y_diff;
        let mut tmp_2 = y_add_identity * &q_elliptic_not_double_scaling;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3) point doubling, x-coordinate check
        // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
        // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1

        let curve_b = P::get_curve_b(); // here we need the extra constraint on the Curve
        let x1_mul_3 = x_1.to_owned() + x_1 + x_1;
        let x_pow_4_mul_3 = (y1_sqr.to_owned() - &curve_b) * &x1_mul_3;
        let mut y1_sqr_mul_4 = y1_sqr.double();
        y1_sqr_mul_4.double_in_place();
        let x1_pow_4_mul_9 = x_pow_4_mul_3.to_owned().double() + &x_pow_4_mul_3;
        let x_double_identity = (x_3.to_owned() + x_1 + x_1) * y1_sqr_mul_4 - x1_pow_4_mul_9;

        tmp_1 += x_double_identity * &q_elliptic_q_double_scaling;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4) point doubling, y-coordinate check
        // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
        let x1_sqr_mul_3 = x1_mul_3 * x_1;
        let y_double_identity =
            x1_sqr_mul_3 * (x_1.to_owned() - x_3) - (y_1.to_owned() + y_1) * y1_plus_y3;
        tmp_2 += y_double_identity * q_elliptic_q_double_scaling;

        ///////////////////////////////////////////////////////////////////////

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp_1.evaluations[i];
        }

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp_2.evaluations[i];
        }
    }

    pub(crate) fn verify_accumulate<P: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour>(
        univariate_accumulator: &mut EllipticRelationEvals<P::ScalarField>,
        input: &ClaimedEvaluations<P::ScalarField, L>,
        _relation_parameters: &RelationParameters<P::ScalarField, L>,
        scaling_factor: &P::ScalarField,
    ) where
        P::ScalarField: PrimeField,
    {
        tracing::trace!("Accumulate EllipticRelation");

        // AZTEC TODO(@zac - williamson #2608 when Pedersen refactor is completed,
        // replace old addition relations with these ones and
        // remove endomorphism coefficient in ecc add gate(not used))

        let x_1 = input.witness.w_r();
        let y_1 = input.witness.w_o();

        let x_2 = input.shifted_witness.w_l();
        let y_2 = input.shifted_witness.w_4();
        let y_3 = input.shifted_witness.w_o();
        let x_3 = input.shifted_witness.w_r();

        let q_sign = input.precomputed.q_l();
        let q_elliptic = input.precomputed.q_elliptic();
        let q_is_double = input.precomputed.q_m();

        // Contribution (1) point addition, x-coordinate check
        // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
        let x_diff = x_2.to_owned() - x_1;
        let y2_sqr = y_2.to_owned().square();
        let y1_sqr = y_1.to_owned().square();
        let y1y2 = y_1.to_owned() * y_2 * q_sign;
        let x_add_identity =
            (x_3.to_owned() + x_2 + x_1) * x_diff.to_owned().square() - y2_sqr - y1_sqr
                + y1y2
                + y1y2;

        let q_elliptic_by_scaling = q_elliptic.to_owned() * scaling_factor;
        let q_elliptic_q_double_scaling = q_elliptic_by_scaling.to_owned() * q_is_double;
        let q_elliptic_not_double_scaling = q_elliptic_by_scaling - q_elliptic_q_double_scaling;
        let mut tmp_1 = x_add_identity * q_elliptic_not_double_scaling;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2) point addition, x-coordinate check
        // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
        let y1_plus_y3 = y_1.to_owned() + y_3;
        let y_diff = y_2.to_owned() * q_sign - y_1;
        let y_add_identity = y1_plus_y3.to_owned() * x_diff + (x_3.to_owned() - x_1) * y_diff;
        let mut tmp_2 = y_add_identity * q_elliptic_not_double_scaling;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3) point doubling, x-coordinate check
        // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
        // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1

        let curve_b = P::get_curve_b(); // here we need the extra constraint on the Curve
        let x1_mul_3 = x_1.to_owned() + x_1 + x_1;
        let x_pow_4_mul_3 = (y1_sqr.to_owned() - curve_b) * x1_mul_3;
        let mut y1_sqr_mul_4 = y1_sqr.double();
        y1_sqr_mul_4.double_in_place();
        let x1_pow_4_mul_9 = x_pow_4_mul_3.to_owned().double() + x_pow_4_mul_3;
        let x_double_identity = (x_3.to_owned() + x_1 + x_1) * y1_sqr_mul_4 - x1_pow_4_mul_9;

        tmp_1 += x_double_identity * q_elliptic_q_double_scaling;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4) point doubling, y-coordinate check
        // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
        let x1_sqr_mul_3 = x1_mul_3 * x_1;
        let y_double_identity =
            x1_sqr_mul_3 * (x_1.to_owned() - x_3) - (y_1.to_owned() + y_1) * y1_plus_y3;
        tmp_2 += y_double_identity * q_elliptic_q_double_scaling;

        ///////////////////////////////////////////////////////////////////////

        univariate_accumulator.r0 += tmp_1;
        univariate_accumulator.r1 += tmp_2;
    }
}
