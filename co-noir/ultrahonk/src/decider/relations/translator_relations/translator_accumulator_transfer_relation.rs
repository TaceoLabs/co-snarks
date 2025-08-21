use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::plain_prover_flavour::UnivariateTrait;
use crate::{
    decider::{
        types::{ClaimedEvaluations, RelationParameters},
        univariate::Univariate,
    },
    plain_prover_flavour::PlainProverFlavour,
};
use ark_ff::{PrimeField, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorAccumulatorTransferRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 3>,
    pub(crate) r1: Univariate<F, 3>,
    pub(crate) r2: Univariate<F, 3>,
    pub(crate) r3: Univariate<F, 3>,
    pub(crate) r4: Univariate<F, 3>,
    pub(crate) r5: Univariate<F, 3>,
    pub(crate) r6: Univariate<F, 3>,
    pub(crate) r7: Univariate<F, 3>,
    pub(crate) r8: Univariate<F, 3>,
    pub(crate) r9: Univariate<F, 3>,
    pub(crate) r10: Univariate<F, 3>,
    pub(crate) r11: Univariate<F, 3>,
}

impl<F: PrimeField> TranslatorAccumulatorTransferRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
        *current_scalar *= challenge;
        self.r2 *= *current_scalar;
        *current_scalar *= challenge;
        self.r3 *= *current_scalar;
        *current_scalar *= challenge;
        self.r4 *= *current_scalar;
        *current_scalar *= challenge;
        self.r5 *= *current_scalar;
        *current_scalar *= challenge;
        self.r6 *= *current_scalar;
        *current_scalar *= challenge;
        self.r7 *= *current_scalar;
        *current_scalar *= challenge;
        self.r8 *= *current_scalar;
        *current_scalar *= challenge;
        self.r9 *= *current_scalar;
        *current_scalar *= challenge;
        self.r10 *= *current_scalar;
        *current_scalar *= challenge;
        self.r11 *= *current_scalar;
        *current_scalar *= challenge;
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
        self.r8.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r9.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r10.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r11.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }

    pub(crate) fn extend_and_batch_univariates_with_distinct_challenges<const SIZE: usize>(
        &self,
        _result: &mut Univariate<F, SIZE>,
        _running_challenge: &[Univariate<F, SIZE>],
    ) {
        panic!(
            "TranslatorFlavour should not need extend_and_batch_univariates_with_distinct_challenges"
        );
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorAccumulatorTransferRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
    pub(crate) r4: F,
    pub(crate) r5: F,
    pub(crate) r6: F,
    pub(crate) r7: F,
    pub(crate) r8: F,
    pub(crate) r9: F,
    pub(crate) r10: F,
    pub(crate) r11: F,
}

impl<F: PrimeField> TranslatorAccumulatorTransferRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }

    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut F,
        _linearly_dependent_contribution: &mut F,
        running_challenge: &[F],
    ) {
        todo!("Implement Sumcheck Verifier for TranslatorFlavour");
    }
}

pub(crate) struct TranslatorAccumulatorTransferRelation {}

impl TranslatorAccumulatorTransferRelation {
    pub(crate) const NUM_RELATIONS: usize = 12;
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorAccumulatorTransferRelation {
    type Acc = TranslatorAccumulatorTransferRelationAcc<F>;
    type VerifyAcc = TranslatorAccumulatorTransferRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>) -> bool {
        (input.precomputed.lagrange_odd_in_minicircuit().to_owned()
            + input.precomputed.lagrange_last_in_minicircuit()
            + input.precomputed.lagrange_result_row())
        .is_zero()
    }

    /**
     * @brief Expression for enforcing the value of the Opcode to be {0,3,4,8} (nop, eq and reset, mul or add)
     * @details This relation enforces the opcode to be one of described values. Since we don't care about even
     * values in the opcode wire and usually just set them to zero, we don't use a lagrange polynomial to specify
     * the relation to be enforced just at odd indices, which brings the degree down by 1.
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate TranslatorAccumulatorTransferRelation");
        let lagrange_odd_in_minicircuit = input.precomputed.lagrange_odd_in_minicircuit();

        // Lagrange ensuring the accumulator result is validated at the correct row
        let lagrange_result_row = input.precomputed.lagrange_result_row();

        // Lagrange at index (size of minicircuit - 1) is used to enforce that the accumulator is initialized to zero in the
        // circuit
        let lagrange_last_in_minicircuit = input.precomputed.lagrange_last_in_minicircuit();

        let accumulators_binary_limbs_0 = input.witness.accumulators_binary_limbs_0();
        let accumulators_binary_limbs_1 = input.witness.accumulators_binary_limbs_1();
        let accumulators_binary_limbs_2 = input.witness.accumulators_binary_limbs_2();
        let accumulators_binary_limbs_3 = input.witness.accumulators_binary_limbs_3();
        let accumulators_binary_limbs_0_shift =
            input.shifted_witness.accumulators_binary_limbs_0_shift();
        let accumulators_binary_limbs_1_shift =
            input.shifted_witness.accumulators_binary_limbs_1_shift();
        let accumulators_binary_limbs_2_shift =
            input.shifted_witness.accumulators_binary_limbs_2_shift();
        let accumulators_binary_limbs_3_shift =
            input.shifted_witness.accumulators_binary_limbs_3_shift();

        // Contribution (1) (1-4 ensure transfer of accumulator limbs at odd indices of the minicircuit)
        let mut tmp_1 = accumulators_binary_limbs_0.to_owned() - accumulators_binary_limbs_0_shift;
        tmp_1 *= lagrange_odd_in_minicircuit;
        tmp_1 *= scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp_1.evaluations[i];
        }

        // Contribution (2)
        let mut tmp_2 = accumulators_binary_limbs_1.to_owned() - accumulators_binary_limbs_1_shift;
        tmp_2 *= lagrange_odd_in_minicircuit;
        tmp_2 *= scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp_2.evaluations[i];
        }
        // Contribution (3)
        let mut tmp_3 = accumulators_binary_limbs_2.to_owned() - accumulators_binary_limbs_2_shift;
        tmp_3 *= lagrange_odd_in_minicircuit;
        tmp_3 *= scaling_factor;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp_3.evaluations[i];
        }
        // Contribution (4)
        let mut tmp_4 = accumulators_binary_limbs_3.to_owned() - accumulators_binary_limbs_3_shift;
        tmp_4 *= lagrange_odd_in_minicircuit;
        tmp_4 *= scaling_factor;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp_4.evaluations[i];
        }

        // Contribution (5) (5-9 ensure that accumulator starts with zeroed-out limbs)
        let mut tmp_5 = accumulators_binary_limbs_0.to_owned() * lagrange_last_in_minicircuit;
        tmp_5 *= scaling_factor;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp_5.evaluations[i];
        }

        // Contribution (6)
        let mut tmp_6 = accumulators_binary_limbs_1.to_owned() * lagrange_last_in_minicircuit;
        tmp_6 *= scaling_factor;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp_6.evaluations[i];
        }

        // Contribution (7)
        let mut tmp_7 = accumulators_binary_limbs_2.to_owned() * lagrange_last_in_minicircuit;
        tmp_7 *= scaling_factor;
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp_7.evaluations[i];
        }

        // Contribution (8)
        let mut tmp_8 = accumulators_binary_limbs_3.to_owned() * lagrange_last_in_minicircuit;
        tmp_8 *= scaling_factor;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp_8.evaluations[i];
        }

        // Contribution (9) (9-12 ensure the output is as stated, we basically use this to get the result out of the
        // // proof)
        let mut tmp_9 = (accumulators_binary_limbs_0.to_owned()
            - &relation_parameters.accumulated_result[0])
            * lagrange_result_row;
        tmp_9 *= scaling_factor;
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp_9.evaluations[i];
        }

        // Contribution (10)
        let mut tmp_10 = (accumulators_binary_limbs_1.to_owned()
            - &relation_parameters.accumulated_result[1])
            * lagrange_result_row;
        tmp_10 *= scaling_factor;
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp_10.evaluations[i];
        }

        // Contribution (11)
        let mut tmp_11 = (accumulators_binary_limbs_2.to_owned()
            - &relation_parameters.accumulated_result[2])
            * lagrange_result_row;
        tmp_11 *= scaling_factor;
        for i in 0..univariate_accumulator.r10.evaluations.len() {
            univariate_accumulator.r10.evaluations[i] += tmp_11.evaluations[i];
        }

        // Contribution (12)
        let mut tmp_12 = (accumulators_binary_limbs_3.to_owned()
            - &relation_parameters.accumulated_result[3])
            * lagrange_result_row;
        tmp_12 *= scaling_factor;
        for i in 0..univariate_accumulator.r11.evaluations.len() {
            univariate_accumulator.r11.evaluations[i] += tmp_12.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, TranslatorFlavour>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        todo!()
    }

    fn accumulate_with_extended_parameters<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        todo!()
    }
}
