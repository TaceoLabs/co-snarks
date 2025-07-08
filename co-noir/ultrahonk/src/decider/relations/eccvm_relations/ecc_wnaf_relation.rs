use crate::plain_prover_flavour::UnivariateTrait;
use crate::{decider::relations::Relation, prelude::Univariate};
use ark_ff::PrimeField;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;

#[derive(Clone, Debug, Default)]
pub(crate) struct EccWnafRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 5>,
    pub(crate) r1: Univariate<F, 5>,
    pub(crate) r2: Univariate<F, 5>,
    pub(crate) r3: Univariate<F, 5>,
    pub(crate) r4: Univariate<F, 5>,
    pub(crate) r5: Univariate<F, 5>,
    pub(crate) r6: Univariate<F, 5>,
    pub(crate) r7: Univariate<F, 5>,
    pub(crate) r8: Univariate<F, 5>,
    pub(crate) r9: Univariate<F, 5>,
    pub(crate) r10: Univariate<F, 5>,
    pub(crate) r11: Univariate<F, 5>,
    pub(crate) r12: Univariate<F, 5>,
    pub(crate) r13: Univariate<F, 5>,
    pub(crate) r14: Univariate<F, 5>,
    pub(crate) r15: Univariate<F, 5>,
    pub(crate) r16: Univariate<F, 5>,
    pub(crate) r17: Univariate<F, 5>,
    pub(crate) r18: Univariate<F, 5>,
    pub(crate) r19: Univariate<F, 5>,
    pub(crate) r20: Univariate<F, 5>,
    pub(crate) r21: Univariate<F, 5>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct EccWnafRelationEvals<F: PrimeField> {
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
    pub(crate) r19: F,
    pub(crate) r20: F,
    pub(crate) r21: F,
}

pub(crate) struct EccWnafRelation {}
impl EccWnafRelation {
    pub(crate) const NUM_RELATIONS: usize = 19;
}

impl<F: PrimeField> EccWnafRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == EccWnafRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
        self.r4 *= elements[4];
        self.r5 *= elements[5];
        self.r6 *= elements[6];
        self.r7 *= elements[7];
        self.r8 *= elements[8];
        self.r9 *= elements[9];
        self.r10 *= elements[10];
        self.r11 *= elements[11];
        self.r12 *= elements[12];
        self.r13 *= elements[13];
        self.r14 *= elements[14];
        self.r15 *= elements[15];
        self.r16 *= elements[16];
        self.r17 *= elements[17];
        self.r18 *= elements[18];
        self.r19 *= elements[19];
        self.r20 *= elements[20];
        self.r21 *= elements[21];
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
        self.r19.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r20.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r21.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

impl<F: PrimeField> Relation<F, ECCVMFlavour> for EccWnafRelation {
    type Acc = EccWnafRelationAcc<F>;

    type VerifyAcc = EccWnafRelationEvals<F>;

    const SKIPPABLE: bool = false; //TODO FLORIN: Where does this come from?

    fn skip<const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> bool {
        todo!() //TODO FLORIN: Where does this come from?
    }

    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        scaling_factor: &F,
    ) {
        let scalar_sum = input.witness.precompute_scalar_sum();
        let scalar_sum_new = input.shifted_witness.precompute_scalar_sum_shift();
        let q_transition = input.witness.precompute_point_transition();
        let round = input.witness.precompute_round();
        let round_shift = input.shifted_witness.precompute_round_shift();
        let pc = input.witness.precompute_pc();
        let pc_shift = input.shifted_witness.precompute_pc_shift();
        let precompute_select = input.witness.precompute_select();
        let precompute_select_shift = input.shifted_witness.precompute_select_shift();
        let minus_one = F::from(-1);
        let minus_three = F::from(-3);
        let minus_two = F::from(-2);
        let minus_seven = F::from(-7);
        let minus_15 = F::from(-15);
        let fifteen = F::from(15);
        let two = F::from(2);

        let precompute_skew = input.witness.precompute_skew();

        let slices = [
            input.witness.precompute_s1hi(),
            input.witness.precompute_s1lo(),
            input.witness.precompute_s2hi(),
            input.witness.precompute_s2lo(),
            input.witness.precompute_s3hi(),
            input.witness.precompute_s3lo(),
            input.witness.precompute_s4hi(),
            input.witness.precompute_s4lo(),
        ];

        let range_constraint_slice_to_2_bits =
            |s: &Univariate<F, SIZE>, acc: &mut Univariate<F, 5>| {
                let tmp = ((s.to_owned() + &minus_one).sqr() + &minus_one)
                    * ((s.to_owned() + &minus_two).sqr() + &minus_one)
                    * scaling_factor;
                for i in 0..acc.evaluations.len() {
                    acc.evaluations[i] = tmp.evaluations[i];
                }
            };

        let convert_to_wnaf =
            |s0: &Univariate<F, SIZE>, s1: &Univariate<F, SIZE>| -> Univariate<F, SIZE> {
                let mut t = s0.to_owned() + s0;
                t += t.clone();
                t += s1;
                t *= &two;
                t.to_owned() + &minus_15
            };

        let scaled_transition = q_transition.to_owned() * scaling_factor;
        let scaled_transition_is_zero = -scaled_transition.clone() + scaling_factor;

        for slice in slices.iter() {
            range_constraint_slice_to_2_bits(slice, &mut univariate_accumulator.r0);
        }

        let s1_shift = input.shifted_witness.precompute_s1hi_shift();
        let s1_shift_msb_set =
            (s1_shift.to_owned() + &minus_two) * (s1_shift.to_owned() + &minus_three);
        let mut tmp = scaled_transition.to_owned() * precompute_select_shift * s1_shift_msb_set;
        for i in 0..univariate_accumulator.r20.evaluations.len() {
            univariate_accumulator.r20.evaluations[i] += tmp.evaluations[i];
        }

        let w0 = convert_to_wnaf(slices[0], slices[1]);
        let w1 = convert_to_wnaf(slices[2], slices[3]);
        let w2 = convert_to_wnaf(slices[4], slices[5]);
        let w3 = convert_to_wnaf(slices[6], slices[7]);

        let mut row_slice = w0.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += w1.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += w2.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += w3.clone();
        let sum_delta = scalar_sum.to_owned() * F::from(1u64 << 16) + row_slice;
        let check_sum = scalar_sum_new.to_owned() - sum_delta;
        tmp = precompute_select.to_owned() * check_sum * scaled_transition_is_zero;
        for i in 0..univariate_accumulator.r8.evaluations.len() {
            univariate_accumulator.r8.evaluations[i] += tmp.evaluations[i];
        }

        let round_check = round.to_owned() * minus_one + round_shift + &minus_one;
        tmp = precompute_select.to_owned()
            * scaled_transition.clone()
            * ((round_check.to_owned() * minus_one + round + &minus_seven) + round_check);
        for i in 0..univariate_accumulator.r9.evaluations.len() {
            univariate_accumulator.r9.evaluations[i] += tmp.evaluations[i];
        }

        tmp = precompute_select.to_owned() * scaled_transition.clone() * round_shift;
        for i in 0..univariate_accumulator.r10.evaluations.len() {
            univariate_accumulator.r10.evaluations[i] += tmp.evaluations[i];
        }

        tmp = precompute_select.to_owned() * scalar_sum_new * scaled_transition.clone();
        for i in 0..univariate_accumulator.r11.evaluations.len() {
            univariate_accumulator.r11.evaluations[i] += tmp.evaluations[i];
        }

        let pc_delta = pc.to_owned() * minus_one + pc_shift;
        tmp = precompute_select.to_owned()
            * (scaled_transition * (pc_delta.to_owned() * minus_one + &minus_one)
                + pc_delta * scaling_factor);
        for i in 0..univariate_accumulator.r12.evaluations.len() {
            univariate_accumulator.r12.evaluations[i] += tmp.evaluations[i];
        }

        tmp = precompute_select.to_owned()
            * (precompute_skew.to_owned()
                * (precompute_skew.to_owned() + &minus_seven)
                * scaling_factor);
        for i in 0..univariate_accumulator.r13.evaluations.len() {
            univariate_accumulator.r13.evaluations[i] += tmp.evaluations[i];
        }

        let precompute_select_zero =
            (precompute_select.to_owned() * minus_one + &F::one()) * scaling_factor;
        tmp = precompute_select_zero.clone() * (w0 + &fifteen);
        for i in 0..univariate_accumulator.r14.evaluations.len() {
            univariate_accumulator.r14.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_select_zero.clone() * (w1 + &fifteen);

        for i in 0..univariate_accumulator.r15.evaluations.len() {
            univariate_accumulator.r15.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_select_zero.clone() * (w2 + &fifteen);

        for i in 0..univariate_accumulator.r16.evaluations.len() {
            univariate_accumulator.r16.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_select_zero.clone() * (w3 + &fifteen);

        for i in 0..univariate_accumulator.r17.evaluations.len() {
            univariate_accumulator.r17.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_select_zero.clone() * round;

        for i in 0..univariate_accumulator.r18.evaluations.len() {
            univariate_accumulator.r18.evaluations[i] += tmp.evaluations[i];
        }
        tmp = precompute_select_zero.clone() * pc;
        for i in 0..univariate_accumulator.r19.evaluations.len() {
            univariate_accumulator.r19.evaluations[i] += tmp.evaluations[i];
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
