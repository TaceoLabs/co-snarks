use crate::co_decider::relations::Relation;
use crate::co_decider::types::ProverUnivariatesBatch;
use crate::co_decider::types::RelationParameters;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::prelude::HonkCurve;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use ultrahonk::prelude::Univariate;

use crate::co_decider::univariates::SharedUnivariate;
use crate::mpc::NoirUltraHonkProver;
use crate::mpc_prover_flavour::MPCProverFlavour;

#[derive(Clone, Debug, Default)]
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

impl<T: NoirUltraHonkProver<P>, P: Pairing> EccOpQueueRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == EccOpQueueRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
        self.r4 *= elements[4];
        self.r5 *= elements[5];
        self.r6 *= elements[6];
        self.r7 *= elements[7];
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
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for EccOpQueueRelation
{
    type Acc = EccOpQueueRelationAcc<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P, L>) -> bool {
        // The prover can skip execution of this relation if the ecc op selector is identically zero

        entity.precomputed.lagrange_ecc_op().is_zero()
    }

    fn accumulate<const SIZE: usize>(
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
        relation_parameters: &RelationParameters<<P>::ScalarField, L>,
        scaling_factors: &[P::ScalarField],
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
        let lagrange_by_scaling = lagrange_ecc_op.to_owned() * scaling_factor;
        let complement_ecc_op_by_scaling = -lagrange_by_scaling.clone() + scaling_factor;

        // Contribution (1)
        let mut tmp = op_wire_1.to_owned() - w_1_shift.to_owned();
        tmp *= lagrange_by_scaling.clone();
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (2)
        tmp = op_wire_2.to_owned() - w_2_shift.to_owned();
        tmp *= lagrange_by_scaling.clone();
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (3)
        tmp = op_wire_3.to_owned() - w_3_shift.to_owned();
        tmp *= lagrange_by_scaling.clone();
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (4)
        tmp = op_wire_4.to_owned() - w_4_shift.to_owned();
        tmp *= lagrange_by_scaling;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (5)
        tmp = op_wire_1.to_owned() * complement_ecc_op_by_scaling.to_owned();
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (6)
        tmp = op_wire_2.to_owned() * complement_ecc_op_by_scaling.to_owned();
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (7)
        tmp = op_wire_3.to_owned() * complement_ecc_op_by_scaling.to_owned();
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (8)
        tmp = op_wire_4.to_owned() * complement_ecc_op_by_scaling.to_owned();
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn add_entites(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, L>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, L>,
    ) {
        todo!()
    }
}
