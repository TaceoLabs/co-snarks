use crate::co_decider::relations::Relation;
use crate::co_decider::relations::fold_accumulator;
use crate::co_decider::types::RelationParameters;
use ark_ec::pairing::Pairing;
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
use crate::mpc::NoirUltraHonkProver;
use crate::mpc_prover_flavour::MPCProverFlavour;

#[derive(Clone, Debug)]
pub(crate) struct EccOpQueueRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 3>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
    pub(crate) r2: SharedUnivariate<T, P, 3>,
    pub(crate) r3: SharedUnivariate<T, P, 3>,
    pub(crate) r4: SharedUnivariate<T, P, 3>,
    pub(crate) r5: SharedUnivariate<T, P, 3>,
    pub(crate) r6: SharedUnivariate<T, P, 3>,
    pub(crate) r7: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for EccOpQueueRelationAcc<T, P> {
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

impl<T: NoirUltraHonkProver<P>, P: Pairing> EccOpQueueRelationAcc<T, P> {
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

    fn can_skip(entity: &super::ProverUnivariates<T, P, L>) -> bool {
        // The prover can skip execution of this relation if the ecc op selector is identically zero

        entity.precomputed.lagrange_ecc_op().is_zero()
    }

    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        _state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &super::ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<<P>::ScalarField, L>,
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
