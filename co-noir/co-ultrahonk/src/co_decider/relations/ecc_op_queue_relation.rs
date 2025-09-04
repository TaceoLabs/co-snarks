use crate::co_decider::relations::Relation;
use crate::co_decider::relations::fold_accumulator;
use crate::co_decider::types::ProverUnivariatesBatch;
use crate::co_decider::types::RelationParameters;
use crate::types::AllEntities;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::prelude::HonkCurve;
use itertools::Itertools;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

use crate::co_decider::univariates::SharedUnivariate;

use crate::mpc_prover_flavour::MPCProverFlavour;
use ark_ff::Field;
use common::mpc::NoirUltraHonkProver;

#[derive(Clone, Debug)]
pub(crate) struct EccOpQueueRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 3>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
    pub(crate) r2: SharedUnivariate<T, P, 3>,
    pub(crate) r3: SharedUnivariate<T, P, 3>,
    pub(crate) r4: SharedUnivariate<T, P, 3>,
    pub(crate) r5: SharedUnivariate<T, P, 3>,
    pub(crate) r6: SharedUnivariate<T, P, 3>,
    pub(crate) r7: SharedUnivariate<T, P, 3>,
}

#[derive(Clone, Debug)]
pub(crate) struct EccOpQueueRelationEvals<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: T::ArithmeticShare,
    pub(crate) r1: T::ArithmeticShare,
    pub(crate) r2: T::ArithmeticShare,
    pub(crate) r3: T::ArithmeticShare,
    pub(crate) r4: T::ArithmeticShare,
    pub(crate) r5: T::ArithmeticShare,
    pub(crate) r6: T::ArithmeticShare,
    pub(crate) r7: T::ArithmeticShare,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccOpQueueRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
            r2: SharedUnivariate::default(),
            r3: SharedUnivariate::default(),
            r4: SharedUnivariate::default(),
            r5: SharedUnivariate::default(),
            r6: SharedUnivariate::default(),
            r7: SharedUnivariate::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccOpQueueRelationEvals<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
            r4: Default::default(),
            r5: Default::default(),
            r6: Default::default(),
            r7: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccOpQueueRelationEvals<T, P> {
    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut T::ArithmeticShare,
        running_challenge: &[P::ScalarField],
    ) {
        assert!(running_challenge.len() == EccOpQueueRelation::NUM_RELATIONS);

        let tmp = T::mul_with_public_many(
            running_challenge,
            &[
                self.r0, self.r1, self.r2, self.r3, self.r4, self.r5, self.r6, self.r7,
            ],
        )
        .into_iter()
        .reduce(T::add)
        .expect("Failed to accumulate ecc_op_queue relation evaluations");

        T::add_assign(linearly_independent_contribution, tmp);
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccOpQueueRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == EccOpQueueRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
        self.r2.scale_inplace(elements[2]);
        self.r3.scale_inplace(elements[3]);
        self.r4.scale_inplace(elements[4]);
        self.r5.scale_inplace(elements[5]);
        self.r6.scale_inplace(elements[6]);
        self.r7.scale_inplace(elements[7]);
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
        self.r6.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r7.extend_and_batch_univariates(
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

        self.r4.extend_and_batch_univariates(
            result,
            &running_challenge[4],
            &P::ScalarField::ONE,
            true,
        );

        self.r5.extend_and_batch_univariates(
            result,
            &running_challenge[5],
            &P::ScalarField::ONE,
            true,
        );

        self.r6.extend_and_batch_univariates(
            result,
            &running_challenge[6],
            &P::ScalarField::ONE,
            true,
        );

        self.r7.extend_and_batch_univariates(
            result,
            &running_challenge[7],
            &P::ScalarField::ONE,
            true,
        );
    }
}

pub(crate) struct EccOpQueueRelation {}

impl EccOpQueueRelation {
    pub(crate) const NUM_RELATIONS: usize = 8;
    // pub(crate) const CRAND_PAIRS_FACTOR: usize = 0;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for EccOpQueueRelation
{
    type Acc = EccOpQueueRelationAcc<T, P>;
    type VerifyAcc = EccOpQueueRelationEvals<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P, L>) -> bool {
        // The prover can skip execution of this relation if the ecc op selector is identically zero

        entity.precomputed.lagrange_ecc_op().is_zero()
    }

    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        _state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate EccOpQueueRelation");
        // using Accumulator = std::tuple_element_t<0, ContainerOverSubrelations>;
        // using CoefficientAccumulator = typename Accumulator::CoefficientAccumulator;
        // We skip using the CoefficientAccumulator type in this relation, as the overall relation degree is low (deg
        // 3). To do a degree-1 multiplication in the coefficient basis requires 3 Fp muls and 4 Fp adds (karatsuba
        // multiplication). But a multiplication of a degree-3 Univariate only requires 3 Fp muls.
        // We still cast to CoefficientAccumulator so that the degree is extended to degree-3 from degree-1

        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let op_wire_1 = input.witness.ecc_op_wire_1();
        let op_wire_2 = input.witness.ecc_op_wire_2();
        let op_wire_3 = input.witness.ecc_op_wire_3();
        let op_wire_4 = input.witness.ecc_op_wire_4();
        let lagrange_ecc_op = input.precomputed.lagrange_ecc_op();

        // If lagrange_ecc_op is the indicator for ecc_op_gates, this is the indicator for the complement

        let lagrange_by_scaling = lagrange_ecc_op
            .iter()
            .zip_eq(scaling_factors.iter())
            .map(|(a, b)| *a * *b)
            .collect_vec();
        let complement_ecc_op_by_scaling = lagrange_by_scaling
            .iter()
            .zip_eq(scaling_factors.iter())
            .map(|(a, b)| *b - *a)
            .collect_vec();

        // Contribution (1)
        let mut tmp = T::sub_many(op_wire_1, w_1_shift);
        tmp = T::mul_with_public_many(&lagrange_by_scaling, &tmp);
        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        // Contribution (2)
        tmp = T::sub_many(op_wire_2, w_2_shift);
        tmp = T::mul_with_public_many(&lagrange_by_scaling, &tmp);
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        // Contribution (3)
        tmp = T::sub_many(op_wire_3, w_3_shift);
        tmp = T::mul_with_public_many(&lagrange_by_scaling, &tmp);
        fold_accumulator!(univariate_accumulator.r2, tmp, SIZE);
        // Contribution (4)
        tmp = T::sub_many(op_wire_4, w_4_shift);
        tmp = T::mul_with_public_many(&lagrange_by_scaling, &tmp);
        fold_accumulator!(univariate_accumulator.r3, tmp, SIZE);

        // Contribution (5)
        tmp = T::mul_with_public_many(&complement_ecc_op_by_scaling, op_wire_1);
        fold_accumulator!(univariate_accumulator.r4, tmp, SIZE);

        // Contribution (6)
        tmp = T::mul_with_public_many(&complement_ecc_op_by_scaling, op_wire_2);
        fold_accumulator!(univariate_accumulator.r5, tmp, SIZE);

        // Contribution (7)
        tmp = T::mul_with_public_many(&complement_ecc_op_by_scaling, op_wire_3);
        fold_accumulator!(univariate_accumulator.r6, tmp, SIZE);

        // Contribution (8)
        tmp = T::mul_with_public_many(&complement_ecc_op_by_scaling, op_wire_4);
        fold_accumulator!(univariate_accumulator.r7, tmp, SIZE);
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
            .lagrange_ecc_op()
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
            &vec![*scaling_factor; input.precomputed.lagrange_ecc_op().len()],
        )
    }

    fn accumulate_evaluations<N: Network>(
        _net: &N,
        _state: &mut T::State,
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<T::ArithmeticShare, P::ScalarField, L>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate EccOpQueueRelation");
        // using Accumulator = std::tuple_element_t<0, ContainerOverSubrelations>;
        // using CoefficientAccumulator = typename Accumulator::CoefficientAccumulator;
        // We skip using the CoefficientAccumulator type in this relation, as the overall relation degree is low (deg
        // 3). To do a degree-1 multiplication in the coefficient basis requires 3 Fp muls and 4 Fp adds (karatsuba
        // multiplication). But a multiplication of a degree-3 Univariate only requires 3 Fp muls.
        // We still cast to CoefficientAccumulator so that the degree is extended to degree-3 from degree-1

        let w_1_shift = input.shifted_witness.w_l().to_owned();
        let w_2_shift = input.shifted_witness.w_r().to_owned();
        let w_3_shift = input.shifted_witness.w_o().to_owned();
        let w_4_shift = input.shifted_witness.w_4().to_owned();

        let op_wire_1 = input.witness.ecc_op_wire_1().to_owned();
        let op_wire_2 = input.witness.ecc_op_wire_2().to_owned();
        let op_wire_3 = input.witness.ecc_op_wire_3().to_owned();
        let op_wire_4 = input.witness.ecc_op_wire_4().to_owned();
        let lagrange_ecc_op = input.precomputed.lagrange_ecc_op().to_owned();

        // If lagrange_ecc_op is the indicator for ecc_op_gates, this is the indicator for the complement

        let lagrange_by_scaling = lagrange_ecc_op * *scaling_factor;
        let complement_ecc_op_by_scaling = lagrange_by_scaling - *scaling_factor;

        // Contribution (1)
        let mut tmp = T::sub(op_wire_1, w_1_shift);
        tmp = T::mul_with_public(lagrange_by_scaling, tmp);
        T::add_assign(&mut accumulator.r0, tmp);

        // Contribution (2)
        tmp = T::sub(op_wire_2, w_2_shift);
        tmp = T::mul_with_public(lagrange_by_scaling, tmp);
        T::add_assign(&mut accumulator.r1, tmp);

        // Contribution (3)
        tmp = T::sub(op_wire_3, w_3_shift);
        tmp = T::mul_with_public(lagrange_by_scaling, tmp);
        T::add_assign(&mut accumulator.r2, tmp);

        // Contribution (4)
        tmp = T::sub(op_wire_4, w_4_shift);
        tmp = T::mul_with_public(lagrange_by_scaling, tmp);
        T::add_assign(&mut accumulator.r3, tmp);

        // Contribution (5)
        tmp = T::mul_with_public(complement_ecc_op_by_scaling, op_wire_1);
        T::add_assign(&mut accumulator.r4, tmp);

        // Contribution (6)
        tmp = T::mul_with_public(complement_ecc_op_by_scaling, op_wire_2);
        T::add_assign(&mut accumulator.r5, tmp);

        // Contribution (7)
        tmp = T::mul_with_public(complement_ecc_op_by_scaling, op_wire_3);
        T::add_assign(&mut accumulator.r6, tmp);

        // Contribution (8)
        tmp = T::mul_with_public(complement_ecc_op_by_scaling, op_wire_4);
        T::add_assign(&mut accumulator.r7, tmp);
        Ok(())
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, L>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, L>,
    ) {
        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_ecc_op_wire_1(entity);
        batch.add_ecc_op_wire_2(entity);
        batch.add_ecc_op_wire_3(entity);
        batch.add_ecc_op_wire_4(entity);
        batch.add_lagrange_ecc_op(entity);
    }
}
