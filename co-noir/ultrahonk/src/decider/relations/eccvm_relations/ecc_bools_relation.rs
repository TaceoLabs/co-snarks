use crate::{decider::relations::Relation, prelude::Univariate};
use ark_ff::PrimeField;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;

#[derive(Clone, Debug, Default)]
pub(crate) struct EccBoolsRelationAcc<F: PrimeField> {
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
    pub(crate) r12: Univariate<F, 3>,
    pub(crate) r13: Univariate<F, 3>,
    pub(crate) r14: Univariate<F, 3>,
    pub(crate) r15: Univariate<F, 3>,
    pub(crate) r16: Univariate<F, 3>,
    pub(crate) r17: Univariate<F, 3>,
    pub(crate) r18: Univariate<F, 3>,
}
#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct EccBoolsRelationEvals<F: PrimeField> {
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
    pub(crate) r12: F,
    pub(crate) r13: F,
    pub(crate) r14: F,
    pub(crate) r15: F,
    pub(crate) r16: F,
    pub(crate) r17: F,
    pub(crate) r18: F,
}

pub(crate) struct EccBoolsRelation {}
impl EccBoolsRelation {
    pub(crate) const NUM_RELATIONS: usize = 19;
}

impl<F: PrimeField> EccBoolsRelationAcc<F> {
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
        self.r12 *= *current_scalar;
        *current_scalar *= challenge;
        self.r13 *= *current_scalar;
        *current_scalar *= challenge;
        self.r14 *= *current_scalar;
        *current_scalar *= challenge;
        self.r15 *= *current_scalar;
        *current_scalar *= challenge;
        self.r16 *= *current_scalar;
        *current_scalar *= challenge;
        self.r17 *= *current_scalar;
        *current_scalar *= challenge;
        self.r18 *= *current_scalar;
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
        self.r12.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r13.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r14.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r15.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r16.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r17.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r18.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

impl<F: PrimeField> Relation<F, ECCVMFlavour> for EccBoolsRelation {
    type Acc = EccBoolsRelationAcc<F>;

    type VerifyAcc = EccBoolsRelationEvals<F>;

    const SKIPPABLE: bool = false;

    fn skip<const SIZE: usize>(
        _input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> bool {
        false
    }

    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        _relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        scaling_factor: &F,
    ) {
        let z1_zero = input.witness.transcript_z1zero();
        let z2_zero = input.witness.transcript_z2zero();
        let msm_count_zero_at_transition = input.witness.transcript_msm_count_zero_at_transition();
        let q_add = input.witness.transcript_add();
        let q_mul = input.witness.transcript_mul();
        let q_eq = input.witness.transcript_eq();
        let transcript_msm_transition = input.witness.transcript_msm_transition();
        let is_accumulator_empty = input.witness.transcript_accumulator_empty();
        let q_reset_accumulator = input.witness.transcript_reset_accumulator();
        let transcript_pinfinity = input.witness.transcript_base_infinity();
        let transcript_msm_infinity = input.witness.transcript_msm_infinity();
        let transcript_add_x_equal = input.witness.transcript_add_x_equal();
        let transcript_add_y_equal = input.witness.transcript_add_y_equal();
        let precompute_point_transition = input.witness.precompute_point_transition();
        let msm_transition = input.witness.msm_transition();
        let msm_add = input.witness.msm_add();
        let msm_double = input.witness.msm_double();
        let msm_skew = input.witness.msm_skew();
        let precompute_select = input.witness.precompute_select();
        let minus_one = -F::one();

        let mut tmp = q_eq.to_owned() + &minus_one;
        tmp *= q_eq;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        tmp = q_add.to_owned() + &minus_one;
        tmp *= q_add;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        tmp = q_mul.to_owned() + &minus_one;
        tmp *= q_mul;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }
        tmp = q_reset_accumulator.to_owned() + &minus_one;
        tmp *= q_reset_accumulator;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }
        tmp = transcript_msm_transition.to_owned() + &minus_one;
        tmp *= transcript_msm_transition;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }
        tmp = is_accumulator_empty.to_owned() + &minus_one;
        tmp *= is_accumulator_empty;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }
        tmp = z1_zero.to_owned() + &minus_one;
        tmp *= z1_zero;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r6.evaluations.len() {
            univariate_accumulator.r6.evaluations[i] += tmp.evaluations[i];
        }
        tmp = z2_zero.to_owned() + &minus_one;
        tmp *= z2_zero;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r7.evaluations.len() {
            univariate_accumulator.r7.evaluations[i] += tmp.evaluations[i];
        }
        tmp = transcript_add_x_equal.to_owned() + &minus_one;
        tmp *= transcript_add_x_equal;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp.evaluations[i];
        }
        tmp = transcript_add_y_equal.to_owned() + &minus_one;
        tmp *= transcript_add_y_equal;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp.evaluations[i];
        }
        tmp = transcript_pinfinity.to_owned() + &minus_one;
        tmp *= transcript_pinfinity;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r10.evaluations.len() {
            univariate_accumulator.r10.evaluations[i] += tmp.evaluations[i];
        }
        tmp = transcript_msm_infinity.to_owned() + &minus_one;
        tmp *= transcript_msm_infinity;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r11.evaluations.len() {
            univariate_accumulator.r11.evaluations[i] += tmp.evaluations[i];
        }
        tmp = msm_count_zero_at_transition.to_owned() + &minus_one;
        tmp *= msm_count_zero_at_transition;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r12.evaluations.len() {
            univariate_accumulator.r12.evaluations[i] += tmp.evaluations[i];
        }
        tmp = msm_transition.to_owned() + &minus_one;
        tmp *= msm_transition;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r13.evaluations.len() {
            univariate_accumulator.r13.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_point_transition.to_owned() + &minus_one;
        tmp *= precompute_point_transition;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r14.evaluations.len() {
            univariate_accumulator.r14.evaluations[i] += tmp.evaluations[i];
        }
        tmp = msm_add.to_owned() + &minus_one;
        tmp *= msm_add;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r15.evaluations.len() {
            univariate_accumulator.r15.evaluations[i] += tmp.evaluations[i];
        }
        tmp = msm_double.to_owned() + &minus_one;
        tmp *= msm_double;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r16.evaluations.len() {
            univariate_accumulator.r16.evaluations[i] += tmp.evaluations[i];
        }
        tmp = msm_skew.to_owned() + &minus_one;
        tmp *= msm_skew;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r17.evaluations.len() {
            univariate_accumulator.r17.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_select.to_owned() + &minus_one;
        tmp *= precompute_select;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r18.evaluations.len() {
            univariate_accumulator.r18.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &crate::prelude::ClaimedEvaluations<F, ECCVMFlavour>,
        _relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        _scaling_factor: &F,
    ) {
        todo!()
    }
}
