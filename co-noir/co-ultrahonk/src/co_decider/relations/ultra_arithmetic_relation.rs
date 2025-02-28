use super::{ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{
        relations::fold_accumulator,
        types::{RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use co_builder::HonkProofResult;
use co_builder::{prelude::HonkCurve, TranscriptFieldType};
use ultrahonk::prelude::Univariate;
#[derive(Clone, Debug)]
pub(crate) struct UltraArithmeticRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 5>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for UltraArithmeticRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> UltraArithmeticRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == UltraArithmeticRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
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

pub(crate) struct UltraArithmeticRelation {}

impl UltraArithmeticRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 1;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for UltraArithmeticRelation
{
    type Acc = UltraArithmeticRelationAcc<T, P>;

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
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
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

        let neg_half = -P::ScalarField::from(2u64).inverse().unwrap();

        let mul = driver.mul_many(w_l, w_r)?;
        //   let mul = SharedUnivariate::from_vec(&mul);
        let mut tmp = T::mul_with_public_many(q_m, &mul);
        let q_arith_neg_3 = q_arith
            .iter()
            .map(|q| *q - P::ScalarField::from(3_u64))
            .collect::<Vec<_>>();
        T::mul_assign_with_public_many(&mut tmp, &q_arith_neg_3);
        T::scale_many_in_place(&mut tmp, neg_half);
        let party_id = driver.get_party_id();
        let tmp_l = T::mul_with_public_many(q_l, w_l);
        let tmp_r = T::mul_with_public_many(q_r, w_r);
        let tmp_o = T::mul_with_public_many(q_o, w_o);
        let tmp_4 = T::mul_with_public_many(q_4, w_4);

        T::add_assign_many(&mut tmp, &tmp_l);
        T::add_assign_many(&mut tmp, &tmp_r);
        T::add_assign_many(&mut tmp, &tmp_o);
        T::add_assign_many(&mut tmp, &tmp_4);
        T::add_assign_public_many(&mut tmp, q_c, party_id);

        let q_arith_neg_1 = q_arith
            .iter()
            .map(|q| *q - P::ScalarField::from(1_u64))
            .collect::<Vec<_>>();

        let q_arith_neg_2 = q_arith
            .iter()
            .map(|q| *q - P::ScalarField::from(2_u64))
            .collect::<Vec<_>>();

        let tmp_arith = T::mul_with_public_many(&q_arith_neg_1, w_4_shift);
        T::add_assign_many(&mut tmp, &tmp_arith);
        T::mul_assign_with_public_many(&mut tmp, q_arith);

        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, tmp);

        let mut tmp = T::add_many(w_l, w_4);
        T::sub_assign_many(&mut tmp, w_l_shift);
        T::add_assign_public_many(&mut tmp, q_m, party_id);
        T::mul_assign_with_public_many(&mut tmp, &q_arith_neg_2);
        T::mul_assign_with_public_many(&mut tmp, &q_arith_neg_1);
        T::mul_assign_with_public_many(&mut tmp, q_arith);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r1, tmp);

        Ok(())
    }
}
