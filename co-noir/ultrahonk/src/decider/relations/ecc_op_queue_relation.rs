use crate::decider::types::ProverUnivariatesSized;
use crate::{
    decider::{
        relations::Relation,
        types::{ClaimedEvaluations, RelationParameters},
        univariate::Univariate,
    },
    plain_prover_flavour::PlainProverFlavour,
};
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct EccOpQueueRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 3>,
    pub(crate) r1: Univariate<F, 3>,
    pub(crate) r2: Univariate<F, 3>,
    pub(crate) r3: Univariate<F, 3>,
    pub(crate) r4: Univariate<F, 3>,
    pub(crate) r5: Univariate<F, 3>,
    pub(crate) r6: Univariate<F, 3>,
    pub(crate) r7: Univariate<F, 3>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EccOpQueueRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
    pub(crate) r4: F,
    pub(crate) r5: F,
    pub(crate) r6: F,
    pub(crate) r7: F,
}

impl<F: PrimeField> EccOpQueueRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == EccOpQueueRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
        *result += self.r4 * running_challenge[4];
        *result += self.r5 * running_challenge[5];
        *result += self.r6 * running_challenge[6];
        *result += self.r7 * running_challenge[7];
    }

    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut F,
        _linearly_dependent_contribution: &mut F,
        running_challenge: &[F],
    ) {
        assert!(running_challenge.len() == EccOpQueueRelation::NUM_RELATIONS);

        *linearly_independent_contribution += self.r0 * running_challenge[0]
            + self.r1 * running_challenge[1]
            + self.r2 * running_challenge[2]
            + self.r3 * running_challenge[3]
            + self.r4 * running_challenge[4]
            + self.r5 * running_challenge[5]
            + self.r6 * running_challenge[6]
            + self.r7 * running_challenge[7];
    }
}

impl<F: PrimeField> EccOpQueueRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
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
        result: &mut Univariate<F, SIZE>,
        running_challenge: &[Univariate<F, SIZE>],
    ) {
        self.r0
            .extend_and_batch_univariates(result, &running_challenge[0], &F::ONE, true);

        self.r1
            .extend_and_batch_univariates(result, &running_challenge[1], &F::ONE, true);

        self.r2
            .extend_and_batch_univariates(result, &running_challenge[2], &F::ONE, true);

        self.r3
            .extend_and_batch_univariates(result, &running_challenge[3], &F::ONE, true);

        self.r4
            .extend_and_batch_univariates(result, &running_challenge[4], &F::ONE, true);

        self.r5
            .extend_and_batch_univariates(result, &running_challenge[5], &F::ONE, true);

        self.r6
            .extend_and_batch_univariates(result, &running_challenge[6], &F::ONE, true);

        self.r7
            .extend_and_batch_univariates(result, &running_challenge[7], &F::ONE, true);
    }
}

pub(crate) struct EccOpQueueRelation {}

impl EccOpQueueRelation {
    pub(crate) const NUM_RELATIONS: usize = 8;
}

impl<F: PrimeField, L: PlainProverFlavour> Relation<F, L> for EccOpQueueRelation {
    type Acc = EccOpQueueRelationAcc<F>;

    type VerifyAcc = EccOpQueueRelationEvals<F>;

    const SKIPPABLE: bool = true;
    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool {
        // The prover can skip execution of this relation if the ecc op selector is identically zero
        <Self as Relation<F, L>>::check_skippable();
        input.precomputed.lagrange_ecc_op().is_zero()
    }

    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
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
        let mut tmp = op_wire_1.to_owned() - w_1_shift;
        tmp *= &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (2)
        tmp = op_wire_2.to_owned() - w_2_shift;
        tmp *= &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (3)
        tmp = op_wire_3.to_owned() - w_3_shift;
        tmp *= &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (4)
        tmp = op_wire_4.to_owned() - w_4_shift;
        tmp *= lagrange_by_scaling;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (5)
        tmp = op_wire_1.to_owned() * &complement_ecc_op_by_scaling;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (6)
        tmp = op_wire_2.to_owned() * &complement_ecc_op_by_scaling;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (7)
        tmp = op_wire_3.to_owned() * &complement_ecc_op_by_scaling;
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (8)
        tmp = op_wire_4.to_owned() * complement_ecc_op_by_scaling;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn accumulate_with_extended_parameters<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        Self::accumulate(
            univariate_accumulator,
            input,
            &RelationParameters::default(),
            scaling_factor,
        );
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
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
        let complement_ecc_op_by_scaling = -lagrange_by_scaling + scaling_factor;

        // Contribution (1)
        let mut tmp = op_wire_1.to_owned() - w_1_shift;
        tmp *= lagrange_by_scaling;
        univariate_accumulator.r0 += tmp;

        // Contribution (2)
        tmp = op_wire_2.to_owned() - w_2_shift;
        tmp *= lagrange_by_scaling;
        univariate_accumulator.r1 += tmp;

        // Contribution (3)
        tmp = op_wire_3.to_owned() - w_3_shift;
        tmp *= lagrange_by_scaling;
        univariate_accumulator.r2 += tmp;

        // Contribution (4)
        tmp = op_wire_4.to_owned() - w_4_shift;
        tmp *= lagrange_by_scaling;
        univariate_accumulator.r3 += tmp;

        // Contribution (5)
        tmp = op_wire_1.to_owned() * complement_ecc_op_by_scaling;
        univariate_accumulator.r4 += tmp;

        // Contribution (6)
        tmp = op_wire_2.to_owned() * complement_ecc_op_by_scaling;
        univariate_accumulator.r5 += tmp;

        // Contribution (7)
        tmp = op_wire_3.to_owned() * complement_ecc_op_by_scaling;
        univariate_accumulator.r6 += tmp;

        // Contribution (8)
        tmp = op_wire_4.to_owned() * complement_ecc_op_by_scaling;
        univariate_accumulator.r7 += tmp;
    }
}
