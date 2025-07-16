use super::{MIN_RAYON_ITER, ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{types::RelationParameters, univariates::SharedUnivariate},
    mpc_prover_flavour::MPCProverFlavour,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_ff::Zero;
use co_builder::HonkProofResult;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{TranscriptFieldType, prelude::HonkCurve};
use common::mpc::NoirUltraHonkProver;
use itertools::izip;
use mpc_core::MpcState;
use mpc_net::Network;
use rayon::prelude::*;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct UltraArithmeticRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 5>,
}

#[derive(Clone, Debug)]
pub(crate) struct UltraArithmeticRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: Univariate<P::ScalarField, 6>,
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

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for UltraArithmeticRelationAccHalfShared<T, P> {
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

impl UltraArithmeticRelation {
    fn compute_r0<T, P, L, const SIZE: usize>(
        state: &mut T::State,
        r0: &mut Univariate<P::ScalarField, 6>,
        input: &ProverUnivariatesBatch<T, P, L>,
        scaling_factors: &[P::ScalarField],
    ) where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    {
        let w_l = input.witness.w_l();
        let w_r = input.witness.w_r();
        let w_o = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let q_m = input.precomputed.q_m();
        let q_l = input.precomputed.q_l();
        let q_r = input.precomputed.q_r();
        let q_o = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_c = input.precomputed.q_c();
        let q_arith = input.precomputed.q_arith();
        let w_4_shift = input.shifted_witness.w_4();

        let one = P::ScalarField::from(1_u64);
        let neg_half = -P::ScalarField::from(2u64).inverse().unwrap();
        let three = P::ScalarField::from(3_u64);

        let mul = T::local_mul_vec(w_l, w_r, state);
        let id = state.id();
        let tmp_l = (w_l, q_l)
            .into_par_iter()
            .map(|(w_l, q_l)| T::mul_with_public_to_half_share(*q_l, *w_l));

        let tmp_r = (w_r, q_r)
            .into_par_iter()
            .map(|(w_l, q_l)| T::mul_with_public_to_half_share(*q_l, *w_l));
        let tmp_o = (w_o, q_o)
            .into_par_iter()
            .map(|(w_l, q_l)| T::mul_with_public_to_half_share(*q_l, *w_l));
        let tmp_4 = (w_4, q_4)
            .into_par_iter()
            .map(|(w_l, q_l)| T::mul_with_public_to_half_share(*q_l, *w_l));

        let acc = (
            &mul,
            tmp_l,
            tmp_r,
            tmp_o,
            tmp_4,
            q_c,
            q_m,
            q_arith,
            w_4_shift,
            scaling_factors,
        )
            .into_par_iter()
            .map(
                |(
                    mul,
                    tmp_l,
                    tmp_r,
                    tmp_o,
                    tmp_4,
                    q_c,
                    q_m,
                    q_arith,
                    w_4_shift,
                    scaling_factor,
                )| {
                    let mut tmp = *mul * q_m;
                    tmp *= *q_arith - three;
                    tmp *= neg_half;
                    tmp += tmp_l + tmp_r + tmp_o + tmp_4;
                    T::add_assign_public_half_share(&mut tmp, *q_c, id);

                    let tmp_arith = T::mul_with_public_to_half_share(*q_arith - one, *w_4_shift);
                    tmp += tmp_arith;
                    tmp *= q_arith;
                    tmp * scaling_factor
                },
            )
            .enumerate()
            .fold(
                || [P::ScalarField::default(); SIZE],
                |mut acc, (idx, tmp)| {
                    acc[idx % SIZE] += tmp;
                    acc
                },
            )
            .reduce(
                || [P::ScalarField::default(); SIZE],
                |mut acc, next| {
                    for (acc, next) in izip!(acc.iter_mut(), next) {
                        *acc += next;
                    }
                    acc
                },
            );

        for (evaluations, new) in izip!(r0.evaluations.iter_mut(), acc) {
            *evaluations += new;
        }
    }
    fn compute_r1<T, P, L, const SIZE: usize>(
        id: <T::State as MpcState>::PartyID,
        r1: &mut SharedUnivariate<T, P, 5>,
        input: &ProverUnivariatesBatch<T, P, L>,
        scaling_factors: &[P::ScalarField],
    ) where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    {
        let w_l = input.witness.w_l();
        let w_4 = input.witness.w_4();
        let q_m = input.precomputed.q_m();
        let q_arith = input.precomputed.q_arith();
        let w_l_shift = input.shifted_witness.w_l();

        let one = P::ScalarField::from(1_u64);
        let two = P::ScalarField::from(2_u64);
        let acc = (w_l, w_4, w_l_shift, q_m, q_arith, scaling_factors)
            .into_par_iter()
            .with_min_len(MIN_RAYON_ITER)
            .map(|(w_l, w_4, w_l_shift, q_m, q_arith, scaling_factor)| {
                let tmp = T::add(*w_l, *w_4);
                let tmp = T::sub(tmp, *w_l_shift);
                let tmp = T::add_with_public(*q_m, tmp, id);
                let tmp = T::mul_with_public(*q_arith - two, tmp);
                let tmp = T::mul_with_public(*q_arith - one, tmp);
                let tmp = T::mul_with_public(*q_arith, tmp);
                T::mul_with_public(*scaling_factor, tmp)
            })
            .enumerate()
            .fold(
                || [T::ArithmeticShare::default(); SIZE],
                |mut acc, (idx, tmp)| {
                    T::add_assign(&mut acc[idx % SIZE], tmp);
                    acc
                },
            )
            .reduce(
                || [T::ArithmeticShare::default(); SIZE],
                |mut acc, next| {
                    for (acc, next) in izip!(acc.iter_mut(), next) {
                        T::add_assign(acc, next);
                    }
                    acc
                },
            );
        for (evaluations, new) in izip!(r1.evaluations.iter_mut(), acc) {
            T::add_assign(evaluations, new);
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for UltraArithmeticRelation
{
    type Acc = UltraArithmeticRelationAccHalfShared<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P, L>) -> bool {
        entity.precomputed.q_arith().is_zero()
    }

    fn add_entities(
        entity: &super::ProverUnivariates<T, P, L>,
        batch: &mut ProverUnivariatesBatch<T, P, L>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_q_m(entity);
        batch.add_q_l(entity);
        batch.add_q_r(entity);
        batch.add_q_o(entity);
        batch.add_q_4(entity);
        batch.add_q_c(entity);
        batch.add_q_arith(entity);

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_4(entity);
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
    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<<P>::ScalarField, L>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate UltraArithmeticRelation");
        let id = state.id();
        rayon::join(
            || {
                Self::compute_r0::<T, P, L, SIZE>(
                    state,
                    &mut univariate_accumulator.r0,
                    input,
                    scaling_factors,
                )
            },
            || {
                Self::compute_r1::<T, P, L, SIZE>(
                    id,
                    &mut univariate_accumulator.r1,
                    input,
                    scaling_factors,
                )
            },
        );
        Ok(())
    }
}
