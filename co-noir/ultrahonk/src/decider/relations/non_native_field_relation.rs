use super::Relation;
use crate::decider::{
    types::{ClaimedEvaluations, ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ff::{One, PrimeField, Zero};
use num_bigint::BigUint;

#[derive(Clone, Debug, Default)]
pub(crate) struct NonNativeFieldRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
}

impl<F: PrimeField> NonNativeFieldRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == NonNativeFieldRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
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
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NonNativeFieldRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
}

impl<F: PrimeField> NonNativeFieldRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == NonNativeFieldRelation::NUM_RELATIONS);
        *result += self.r0 * running_challenge[0];
    }
}

pub(crate) struct NonNativeFieldRelation {}

impl NonNativeFieldRelation {
    pub(crate) const NUM_RELATIONS: usize = 1;
}

impl<F: PrimeField> Relation<F> for NonNativeFieldRelation {
    type Acc = NonNativeFieldRelationAcc<F>;
    type VerifyAcc = NonNativeFieldRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        <Self as Relation<F>>::check_skippable();
        input.precomputed.q_nnf().is_zero()
    }

    /**
     * @brief Non-native field arithmetic relation
     * @details Adds contributions for identities associated with non-native field arithmetic:
     *  * Bigfield product evaluation (3 in total)
     *  * Bigfield limb accumulation (2 in total)
     *
     * Multiple selectors are used to 'switch' nnf gates on/off according to the following pattern:
     *
     * | gate type                    | q_nnf | q_2 | q_3 | q_4 | q_m |
     * | ---------------------------- | ----- | --- | --- | --- | --- |
     * | Bigfield Limb Accumulation 1 | 1     | 0   | 1   | 1   | 0   |
     * | Bigfield Limb Accumulation 2 | 1     | 0   | 1   | 0   | 1   |
     * | Bigfield Product 1           | 1     | 1   | 1   | 0   | 0   |
     * | Bigfield Product 2           | 1     | 1   | 0   | 1   | 0   |
     * | Bigfield Product 3           | 1     | 1   | 0   | 0   | 1   |
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the Totaly extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate NonNativeFieldRelation");

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let q_2 = input.precomputed.q_r();
        let q_3 = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_m = input.precomputed.q_m();
        let q_nnf = input.precomputed.q_nnf();

        let limb_size = F::from(BigUint::one() << 68);
        let sublimb_shift = F::from(1u64 << 14);

        /*
         * Non native field arithmetic gate 2
         * deg 4
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         */
        let mut limb_subproduct = w_1.to_owned() * w_2_shift + w_1_shift.to_owned() * w_2;
        let mut non_native_field_gate_2 = w_1.to_owned() * w_4 + w_2.to_owned() * w_3 - w_3_shift;
        non_native_field_gate_2 *= &limb_size;
        non_native_field_gate_2 -= w_4_shift;
        non_native_field_gate_2 += &limb_subproduct;
        non_native_field_gate_2 *= q_4;

        limb_subproduct *= &limb_size;
        limb_subproduct += w_1_shift.to_owned() * w_2_shift;
        let mut non_native_field_gate_1 = limb_subproduct.clone();
        non_native_field_gate_1 -= w_3.to_owned() + w_4;
        non_native_field_gate_1 *= q_3;

        let mut non_native_field_gate_3 = limb_subproduct;
        non_native_field_gate_3 += w_4;
        non_native_field_gate_3 -= w_3_shift.to_owned() + w_4_shift;
        non_native_field_gate_3 *= q_m;

        let mut non_native_field_identity =
            non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3;
        non_native_field_identity *= q_2;

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * q_4
        let mut limb_accumulator_1 = w_2_shift.to_owned() * sublimb_shift;
        limb_accumulator_1 += w_1_shift;
        limb_accumulator_1 *= &sublimb_shift;
        limb_accumulator_1 += w_3;
        limb_accumulator_1 *= &sublimb_shift;
        limb_accumulator_1 += w_2;
        limb_accumulator_1 *= &sublimb_shift;
        limb_accumulator_1 += w_1;
        limb_accumulator_1 -= w_4;
        limb_accumulator_1 *= q_4;

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * q_m
        let mut limb_accumulator_2 = w_3_shift.to_owned() * sublimb_shift;
        limb_accumulator_2 += w_2_shift;
        limb_accumulator_2 *= &sublimb_shift;
        limb_accumulator_2 += w_1_shift;
        limb_accumulator_2 *= &sublimb_shift;
        limb_accumulator_2 += w_4;
        limb_accumulator_2 *= &sublimb_shift;
        limb_accumulator_2 += w_3;
        limb_accumulator_2 -= w_4_shift;
        limb_accumulator_2 *= q_m;

        let mut limb_accumulator_identity = limb_accumulator_1 + limb_accumulator_2;
        limb_accumulator_identity *= q_3;

        let mut nnf_identity = non_native_field_identity + limb_accumulator_identity;
        nnf_identity *= q_nnf;
        nnf_identity *= scaling_factor;

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += nnf_identity.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate NonNativeFieldRelation");

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let q_2 = input.precomputed.q_r();
        let q_3 = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_m = input.precomputed.q_m();
        let q_nnf = input.precomputed.q_nnf();

        let limb_size = F::from(BigUint::one() << 68);
        let sublimb_shift = F::from(1u64 << 14);

        // Non native field arithmetic gate 2
        let mut limb_subproduct = w_1.to_owned() * w_2_shift + w_1_shift.to_owned() * w_2;
        let mut non_native_field_gate_2 = w_1.to_owned() * w_4 + w_2.to_owned() * w_3 - w_3_shift;
        non_native_field_gate_2 *= &limb_size;
        non_native_field_gate_2 -= w_4_shift;
        non_native_field_gate_2 += &limb_subproduct;
        non_native_field_gate_2 *= q_4;

        limb_subproduct *= &limb_size;
        limb_subproduct += w_1_shift.to_owned() * w_2_shift;
        let mut non_native_field_gate_1 = limb_subproduct;
        non_native_field_gate_1 -= w_3.to_owned() + w_4;
        non_native_field_gate_1 *= q_3;

        let mut non_native_field_gate_3 = limb_subproduct;
        non_native_field_gate_3 += w_4;
        non_native_field_gate_3 -= w_3_shift.to_owned() + w_4_shift;
        non_native_field_gate_3 *= q_m;

        let mut non_native_field_identity =
            non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3;
        non_native_field_identity *= q_2;

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * q_4
        let mut limb_accumulator_1 = w_2_shift.to_owned() * sublimb_shift;
        limb_accumulator_1 += w_1_shift;
        limb_accumulator_1 *= &sublimb_shift;
        limb_accumulator_1 += w_3;
        limb_accumulator_1 *= &sublimb_shift;
        limb_accumulator_1 += w_2;
        limb_accumulator_1 *= &sublimb_shift;
        limb_accumulator_1 += w_1;
        limb_accumulator_1 -= w_4;
        limb_accumulator_1 *= q_4;

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * q_m
        let mut limb_accumulator_2 = w_3_shift.to_owned() * sublimb_shift;
        limb_accumulator_2 += w_2_shift;
        limb_accumulator_2 *= &sublimb_shift;
        limb_accumulator_2 += w_1_shift;
        limb_accumulator_2 *= &sublimb_shift;
        limb_accumulator_2 += w_4;
        limb_accumulator_2 *= &sublimb_shift;
        limb_accumulator_2 += w_3;
        limb_accumulator_2 -= w_4_shift;
        limb_accumulator_2 *= q_m;

        let mut limb_accumulator_identity = limb_accumulator_1 + limb_accumulator_2;
        limb_accumulator_identity *= q_3;

        let mut nnf_identity = non_native_field_identity + limb_accumulator_identity;
        nnf_identity *= q_nnf;
        nnf_identity *= scaling_factor;

        univariate_accumulator.r0 += nnf_identity;
    }
}
