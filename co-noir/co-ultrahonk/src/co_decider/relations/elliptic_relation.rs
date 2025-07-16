use super::Relation;
use crate::{
    co_decider::{
        relations::fold_accumulator, types::RelationParameters, univariates::SharedUnivariate,
    },
    mpc_prover_flavour::MPCProverFlavour,
};
use common::mpc::NoirUltraHonkProver;

use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::{HonkProofResult, polynomials::polynomial_flavours::PrecomputedEntitiesFlavour};
use co_builder::{
    TranscriptFieldType, polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour,
};
use itertools::Itertools as _;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EllipticRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 6>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for EllipticRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> EllipticRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == EllipticRelation::NUM_RELATIONS);
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

pub(crate) struct EllipticRelation {}

impl EllipticRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 12;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for EllipticRelation
{
    type Acc = EllipticRelationAcc<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P, L>) -> bool {
        entity.precomputed.q_elliptic().is_zero()
    }

    fn add_entities(
        entity: &super::ProverUnivariates<T, P, L>,
        batch: &mut super::ProverUnivariatesBatch<T, P, L>,
    ) {
        batch.add_w_r(entity);
        batch.add_w_o(entity);

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_q_l(entity);
        batch.add_q_m(entity);
        batch.add_q_elliptic(entity);
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
    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &super::ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<<P>::ScalarField, L>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate EllipticRelation");

        // AZTEC TODO(@zac - williamson #2608 when Pedersen refactor is completed,
        // replace old addition relations with these ones and
        // remove endomorphism coefficient in ecc add gate(not used))

        let id = state.id();
        let x_1 = input.witness.w_r();
        let y_1 = input.witness.w_o();

        let x_2 = input.shifted_witness.w_l();
        let y_2 = input.shifted_witness.w_4();
        let y_3 = input.shifted_witness.w_o();
        let x_3 = input.shifted_witness.w_r();

        let q_sign = input.precomputed.q_l();
        let q_elliptic = input.precomputed.q_elliptic();
        let q_is_double = input.precomputed.q_m();

        debug_assert_eq!(x_1.len(), y_1.len());
        debug_assert_eq!(x_2.len(), y_2.len());
        debug_assert_eq!(y_2.len(), y_3.len());
        debug_assert_eq!(x_1.len(), x_2.len());
        debug_assert_eq!(x_2.len(), x_3.len());

        // First round of multiplications
        let x_diff = T::sub_many(x_2, x_1);
        let y1_plus_y3 = T::add_many(y_1, y_3);
        let mut y_diff = T::mul_with_public_many(q_sign, y_2);
        T::sub_assign_many(&mut y_diff, y_1);

        let mut x1_mul_3 = T::add_many(x_1, x_1);
        T::add_assign_many(&mut x1_mul_3, x_1);
        let mut lhs = Vec::with_capacity(
            (2 * y_1.len())
                + y_2.len()
                + x_diff.len()
                + y1_plus_y3.len()
                + y_diff.len()
                + x1_mul_3.len(),
        );

        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(y_1);
        lhs.extend(y_2);
        lhs.extend(y_1);
        lhs.extend(x_diff.clone());
        lhs.extend(y1_plus_y3.clone());
        lhs.extend(y_diff.clone());
        lhs.extend(x1_mul_3.clone());

        rhs.extend(y_1);
        rhs.extend(y_2);
        rhs.extend(y_2);
        rhs.extend(x_diff.clone());
        rhs.extend(x_diff);
        rhs.extend(T::sub_many(x_3, x_1));
        rhs.extend(x_1);
        let mul1 = T::mul_many(&lhs, &rhs, net, state)?;
        // we need the different contributions again
        let chunks1 = mul1.chunks_exact(mul1.len() / 7).collect_vec();
        debug_assert_eq!(chunks1.len(), 7);

        // Second round of multiplications
        let curve_b = P::get_curve_b(); // here we need the extra constraint on the Curve
        let y1_sqr = chunks1[0];
        let y1_sqr_mul_4 = T::add_many(y1_sqr, y1_sqr);
        let y1_sqr_mul_4 = T::add_many(&y1_sqr_mul_4, &y1_sqr_mul_4);
        let x1_sqr_mul_3 = chunks1[6];

        let mut lhs =
            Vec::with_capacity(2 * x_3.len() + y1_sqr.len() + x1_sqr_mul_3.len() + y_1.len());
        lhs.extend(T::add_many(&T::add_many(x_3, x_2), x_1));
        lhs.extend(T::add_scalar(y1_sqr, -curve_b, id));
        lhs.extend(T::add_many(&T::add_many(x_3, x_1), x_1));
        lhs.extend(x1_sqr_mul_3);
        lhs.extend(T::add_many(y_1, y_1));

        let mut rhs = Vec::with_capacity(lhs.len());
        rhs.extend(chunks1[3]);
        rhs.extend(x1_mul_3);
        rhs.extend(y1_sqr_mul_4);
        rhs.extend(T::sub_many(x_1, x_3));
        rhs.extend(y1_plus_y3);

        let mul2 = T::mul_many(&lhs, &rhs, net, state)?;
        let chunks2 = mul2.chunks_exact(mul2.len() / 5).collect_vec();
        debug_assert_eq!(chunks2.len(), 5);

        // Contribution (1) point addition, x-coordinate check
        // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
        let y2_sqr = chunks1[1];
        let y1y2 = T::mul_with_public_many(q_sign, chunks1[2]);
        let mut x_add_identity = T::sub_many(chunks2[0], y2_sqr);
        T::sub_assign_many(&mut x_add_identity, y1_sqr);
        T::add_assign_many(&mut x_add_identity, &y1y2);
        T::add_assign_many(&mut x_add_identity, &y1y2);

        let q_elliptic_by_scaling = q_elliptic
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| *a * *b)
            .collect_vec();
        let q_elliptic_q_double_scaling = q_elliptic_by_scaling
            .iter()
            .zip_eq(q_is_double)
            .map(|(a, b)| *a * *b)
            .collect_vec();
        let q_elliptic_not_double_scaling = q_elliptic_by_scaling
            .iter()
            .zip_eq(q_elliptic_q_double_scaling.iter())
            .map(|(a, b)| *a - *b)
            .collect_vec();

        let mut tmp_1 = T::mul_with_public_many(&q_elliptic_not_double_scaling, &x_add_identity);

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2) point addition, x-coordinate check
        // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
        let y_add_identity = T::add_many(chunks1[4], chunks1[5]);
        let mut tmp_2 = T::mul_with_public_many(&q_elliptic_not_double_scaling, &y_add_identity);

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3) point doubling, x-coordinate check
        // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
        // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1
        let x_pow_4_mul_3 = chunks2[1];
        let mut x1_pow_4_mul_9 = T::add_many(x_pow_4_mul_3, x_pow_4_mul_3);
        T::add_assign_many(&mut x1_pow_4_mul_9, x_pow_4_mul_3);
        let x_double_identity = T::sub_many(chunks2[2], &x1_pow_4_mul_9);

        let tmp = T::mul_with_public_many(&q_elliptic_q_double_scaling, &x_double_identity);
        T::add_assign_many(&mut tmp_1, &tmp);

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4) point doubling, y-coordinate check
        // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
        let y_double_identity = T::sub_many(chunks2[3], chunks2[4]);
        let tmp = T::mul_with_public_many(&q_elliptic_q_double_scaling, &y_double_identity);
        T::add_assign_many(&mut tmp_2, &tmp);

        fold_accumulator!(univariate_accumulator.r0, tmp_1, SIZE);
        fold_accumulator!(univariate_accumulator.r1, tmp_2, SIZE);
        Ok(())
    }
}
