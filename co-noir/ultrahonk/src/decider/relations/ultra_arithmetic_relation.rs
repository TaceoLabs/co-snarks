use super::Relation;
use crate::decider::{
    sumcheck::sumcheck_round::SumcheckRoundOutput,
    types::{ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ff::{PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct UltraArithmeticRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 5>,
}

impl<F: PrimeField> UltraArithmeticRelationAcc<F> {
    pub fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == UltraArithmeticRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
    }

    pub fn extend_and_batch_univariates(
        &self,
        result: &mut SumcheckRoundOutput<F>,
        extended_random_poly: &SumcheckRoundOutput<F>,
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

pub(crate) struct UltraArithmeticRelation {}

impl UltraArithmeticRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
}

impl<F: PrimeField> Relation<F> for UltraArithmeticRelation {
    type Acc = UltraArithmeticRelationAcc<F>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        <Self as Relation<F>>::check_skippable();
        input.precomputed.q_arith().is_zero()
    }

    /**
     * @brief Expression for the Ultra Arithmetic gate.
     * @details This relation encapsulates several idenitities, toggled by the value of q_arith in [0, 1, 2, 3, ...].
     * The following description is reproduced from the Plonk analog 'plookup_arithmetic_widget':
     * The whole formula is:
     *
     * q_arith * ( ( (-1/2) * (q_arith - 3) * q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c ) +
     * (q_arith - 1)*( α * (q_arith - 2) * (w_1 + w_4 - w_1_omega + q_m) + w_4_omega) ) = 0
     *
     * This formula results in several cases depending on q_arith:
     * 1. q_arith == 0: Arithmetic gate is completely disabled
     *
     * 2. q_arith == 1: Everything in the minigate on the right is disabled. The equation is just a standard plonk
     *    equation with extra wires: q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c = 0
     *
     * 3. q_arith == 2: The (w_1 + w_4 - ...) term is disabled. THe equation is:
     *    (1/2) * q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + w_4_omega = 0
     *    It allows defining w_4 at next index (w_4_omega) in terms of current wire values
     *
     * 4. q_arith == 3: The product of w_1 and w_2 is disabled, but a mini addition gate is enabled. α² allows us to
     *    split the equation into two:
     *
     * q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + 2 * w_4_omega = 0
     *
     * w_1 + w_4 - w_1_omega + q_m = 0  (we are reusing q_m here)
     *
     * 5. q_arith > 3: The product of w_1 and w_2 is scaled by (q_arith - 3), while the w_4_omega term is scaled by
     *    (q_arith
     * - 1). The equation can be split into two:
     *
     * (q_arith - 3)* q_m * w_1 * w_ 2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + (q_arith - 1) * w_4_omega
     * = 0
     *
     * w_1 + w_4 - w_1_omega + q_m = 0
     *
     * The problem that q_m is used both in both equations can be dealt with by appropriately changing selector values
     * at the next gate. Then we can treat (q_arith - 1) as a simulated q_6 selector and scale q_m to handle (q_arith -
     * 3) at product.
     *
     * The relation is
     * defined as C(in(X)...) = q_arith * [ -1/2(q_arith - 3)(q_m * w_r * w_l) + (q_l * w_l) + (q_r * w_r) +
     * (q_o * w_o) + (q_4 * w_4) + q_c + (q_arith - 1)w_4_shift ]
     *
     *    q_arith *
     *      (q_arith - 2) * (q_arith - 1) * (w_l + w_4 - w_l_shift + q_m)
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate UltraArithmeticRelation");

        let w_l = input.witness.w_l();
        let w_r = input.witness.w_r();
        let w_o = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_4_shift = input.shifted_witness.w_4();
        let q_m = input.precomputed.q_m();
        let q_l = input.precomputed.q_l();
        let q_r = input.precomputed.q_r();
        let q_o = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_c = input.precomputed.q_c();
        let q_arith = input.precomputed.q_arith();
        let w_l_shift = input.shifted_witness.w_l();

        let neg_half = -F::from(2u64).inverse().unwrap();

        let mut tmp = (q_arith.to_owned() - 3) * (q_m.to_owned() * w_r * w_l) * neg_half;
        tmp += (q_l.to_owned() * w_l)
            + (q_r.to_owned() * w_r)
            + (q_o.to_owned() * w_o)
            + (q_4.to_owned() * w_4)
            + q_c;
        tmp += (q_arith.to_owned() - 1) * w_4_shift;
        tmp *= q_arith;
        tmp *= scaling_factor;

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let mut tmp = w_l.to_owned() + w_4 - w_l_shift + q_m;
        tmp *= q_arith.to_owned() - 2;
        tmp *= q_arith.to_owned() - 1;
        tmp *= q_arith;
        tmp *= scaling_factor;

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }
}
