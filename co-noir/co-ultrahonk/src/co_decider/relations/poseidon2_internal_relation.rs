use super::{ProverUnivariatesBatch, Relation, fold_accumulator};
use crate::{
    co_decider::{types::RelationParameters, univariates::SharedUnivariate},
    mpc_prover_flavour::MPCProverFlavour,
    types::AllEntities,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::Zero;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::{
    HonkProofResult, TranscriptFieldType,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour,
};
use common::mpc::NoirUltraHonkProver;
use itertools::Itertools as _;
use mpc_core::{MpcState as _, gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS};
use mpc_net::Network;
use num_bigint::BigUint;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2InternalRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 7>,
    pub(crate) r2: SharedUnivariate<T, P, 7>,
    pub(crate) r3: SharedUnivariate<T, P, 7>,
}

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2InternalRelationEvals<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: T::ArithmeticShare,
    pub(crate) r1: T::ArithmeticShare,
    pub(crate) r2: T::ArithmeticShare,
    pub(crate) r3: T::ArithmeticShare,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for Poseidon2InternalRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for Poseidon2InternalRelationEvals<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Poseidon2InternalRelationEvals<T, P> {
    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut T::ArithmeticShare,
        running_challenge: &[P::ScalarField],
    ) {
        assert!(running_challenge.len() == Poseidon2InternalRelation::NUM_RELATIONS);

        let tmp = T::mul_with_public_many(running_challenge, &[self.r0, self.r1, self.r2, self.r3])
            .into_iter()
            .reduce(T::add)
            .expect("Failed to accumulate poseidon2 internal relation evaluations");

        T::add_assign(linearly_independent_contribution, tmp);
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Poseidon2InternalRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == Poseidon2InternalRelation::NUM_RELATIONS);
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

    pub(crate) fn extend_and_batch_univariates_with_distinct_challenges<const SIZE: usize>(
        &self,
        result: &mut SharedUnivariate<T, P, SIZE>,
        running_challenge: &[Univariate<P::ScalarField, SIZE>],
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            &running_challenge[0],
            &P::ScalarField::ONE,
            true,
        );

        self.r1.extend_and_batch_univariates(
            result,
            &running_challenge[1],
            &P::ScalarField::ONE,
            true,
        );

        self.r2.extend_and_batch_univariates(
            result,
            &running_challenge[2],
            &P::ScalarField::ONE,
            true,
        );

        self.r3.extend_and_batch_univariates(
            result,
            &running_challenge[3],
            &P::ScalarField::ONE,
            true,
        );
    }
}

pub(crate) struct Poseidon2InternalRelation {}

impl Poseidon2InternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 3;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for Poseidon2InternalRelation
{
    type Acc = Poseidon2InternalRelationAcc<T, P>;
    type VerifyAcc = Poseidon2InternalRelationEvals<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P, L>) -> bool {
        entity.precomputed.q_poseidon2_internal().is_zero()
    }

    fn add_entities(
        entity: &super::ProverUnivariates<T, P, L>,
        batch: &mut ProverUnivariatesBatch<T, P, L>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_q_l(entity);

        batch.add_q_poseidon2_internal(entity);
    }

    /**
     * @brief Expression for the poseidon2 internal round relation, based on I_i in Section 6 of
     * https://eprint.iacr.org/2023/323.pdf.
     * @details This relation is defined as C(in(X)...) :=
     * q_poseidon2_internal * ( (v1 - w_1_shift) + \alpha * (v2 - w_2_shift) +
     * \alpha^2 * (v3 - w_3_shift) + \alpha^3 * (v4 - w_4_shift) ) = 0 where:
     *      u1 := (w_1 + q_1)^5
     *      sum := u1 + w_2 + w_3 + w_4
     *      v1 := u1 * D1 + sum
     *      v2 := w_2 * D2 + sum
     *      v3 := w_3 * D3 + sum
     *      v4 := w_4 * D4 + sum
     *      Di is the ith internal diagonal value - 1 of the internal matrix M_I
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
        input: &ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let w_l = input.witness.w_l();
        let w_r = input.witness.w_r();
        let w_o = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_l_shift = input.shifted_witness.w_l();
        let w_r_shift = input.shifted_witness.w_r();
        let w_o_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();
        let q_l = input.precomputed.q_l();
        let q_poseidon2_internal = input.precomputed.q_poseidon2_internal();

        // add round constants
        let s1 = T::add_with_public_many(q_l, w_l, state.id());

        // apply s-box round
        // 0xThemis TODO again can we do something better for x^5?
        let u1 = T::mul_many(&s1, &s1, net, state)?;
        let u1 = T::mul_many(&u1, &u1, net, state)?;
        let mut u1 = T::mul_many(&u1, &s1, net, state)?;

        let mut u2 = w_r.to_owned();
        let mut u3 = w_o.to_owned();
        let mut u4 = w_4.to_owned();

        // matrix mul with v = M_I * u 4 muls and 7 additions
        let mut sum = T::add_many(&u1, &u2);
        T::add_assign_many(&mut sum, &u3);
        T::add_assign_many(&mut sum, &u4);

        let q_pos_by_scaling = q_poseidon2_internal
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| *a * *b)
            .collect_vec();

        // TACEO TODO this poseidon instance is very hardcoded to the bn254 curve
        let internal_matrix_diag_0 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[0],
        ));
        let internal_matrix_diag_1 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[1],
        ));
        let internal_matrix_diag_2 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[2],
        ));
        let internal_matrix_diag_3 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[3],
        ));

        T::scale_many_in_place(&mut u1, internal_matrix_diag_0);
        T::add_assign_many(&mut u1, &sum);
        T::sub_assign_many(&mut u1, w_l_shift);
        T::mul_assign_with_public_many(&mut u1, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r0, u1, SIZE);

        ///////////////////////////////////////////////////////////////////////
        T::scale_many_in_place(&mut u2, internal_matrix_diag_1);
        T::add_assign_many(&mut u2, &sum);
        T::sub_assign_many(&mut u2, w_r_shift);
        T::mul_assign_with_public_many(&mut u2, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r1, u2, SIZE);

        ///////////////////////////////////////////////////////////////////////

        T::scale_many_in_place(&mut u3, internal_matrix_diag_2);
        T::add_assign_many(&mut u3, &sum);
        T::sub_assign_many(&mut u3, w_o_shift);
        T::mul_assign_with_public_many(&mut u3, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r2, u3, SIZE);

        ///////////////////////////////////////////////////////////////////////

        T::scale_many_in_place(&mut u4, internal_matrix_diag_3);
        T::add_assign_many(&mut u4, &sum);
        T::sub_assign_many(&mut u4, w_4_shift);
        T::mul_assign_with_public_many(&mut u4, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r3, u4, SIZE);

        ///////////////////////////////////////////////////////////////////////
        Ok(())
    }

    fn accumulate_with_extended_parameters<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        // TODO TACEO: Reconcile skip check and `can_skip`
        if input
            .precomputed
            .q_poseidon2_internal()
            .iter()
            .all(|x| x.is_zero())
        {
            return Ok(());
        }
        Self::accumulate::<N, SIZE>(
            net,
            state,
            univariate_accumulator,
            input,
            &RelationParameters::default(),
            &vec![*scaling_factor; input.precomputed.q_poseidon2_internal().len()],
        )
    }

    fn accumulate_evaluations<N: Network>(
        net: &N,
        state: &mut T::State,
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<T::ArithmeticShare, P::ScalarField, L>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        let w_l = input.witness.w_l().to_owned();
        let w_r = input.witness.w_r().to_owned();
        let w_o = input.witness.w_o().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let w_l_shift = input.shifted_witness.w_l().to_owned();
        let w_r_shift = input.shifted_witness.w_r().to_owned();
        let w_o_shift = input.shifted_witness.w_o().to_owned();
        let w_4_shift = input.shifted_witness.w_4().to_owned();
        let q_l = input.precomputed.q_l().to_owned();
        let q_poseidon2_internal = input.precomputed.q_poseidon2_internal().to_owned();

        // add round constants
        let s1 = T::add_with_public(q_l, w_l, state.id());

        // apply s-box round
        // 0xThemis TODO again can we do something better for x^5?
        let u1 = T::mul(s1, s1, net, state)?;
        let u1 = T::mul(u1, u1, net, state)?;
        let mut u1 = T::mul(u1, s1, net, state)?;

        let mut u2 = w_r.to_owned();
        let mut u3 = w_o.to_owned();
        let mut u4 = w_4.to_owned();

        // matrix mul with v = M_I * u 4 muls and 7 additions
        let mut sum = T::add(u1, u2);
        T::add_assign(&mut sum, u3);
        T::add_assign(&mut sum, u4);

        let q_pos_by_scaling = q_poseidon2_internal * scaling_factor;

        // TACEO TODO this poseidon instance is very hardcoded to the bn254 curve
        let internal_matrix_diag_0 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[0],
        ));
        let internal_matrix_diag_1 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[1],
        ));
        let internal_matrix_diag_2 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[2],
        ));
        let internal_matrix_diag_3 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[3],
        ));

        T::mul_assign_with_public(&mut u1, internal_matrix_diag_0);
        T::add_assign(&mut u1, sum);
        T::sub_assign(&mut u1, w_l_shift);
        T::mul_assign_with_public(&mut u1, q_pos_by_scaling);

        T::add_assign(&mut accumulator.r0, u1);

        ///////////////////////////////////////////////////////////////////////
        T::mul_assign_with_public(&mut u2, internal_matrix_diag_1);
        T::add_assign(&mut u2, sum);
        T::sub_assign(&mut u2, w_r_shift);
        T::mul_assign_with_public(&mut u2, q_pos_by_scaling);

        T::add_assign(&mut accumulator.r1, u2);

        ///////////////////////////////////////////////////////////////////////

        T::mul_assign_with_public(&mut u3, internal_matrix_diag_2);
        T::add_assign(&mut u3, sum);
        T::sub_assign(&mut u3, w_o_shift);
        T::mul_assign_with_public(&mut u3, q_pos_by_scaling);

        T::add_assign(&mut accumulator.r2, u3);

        ///////////////////////////////////////////////////////////////////////

        T::mul_assign_with_public(&mut u4, internal_matrix_diag_3);
        T::add_assign(&mut u4, sum);
        T::sub_assign(&mut u4, w_4_shift);
        T::mul_assign_with_public(&mut u4, q_pos_by_scaling);

        T::add_assign(&mut accumulator.r3, u4);

        ///////////////////////////////////////////////////////////////////////
        Ok(())
    }
}
