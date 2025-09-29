use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::{HonkProofResult, flavours::eccvm_flavour::ECCVMFlavour, prelude::HonkCurve};
use common::{mpc::NoirUltraHonkProver, transcript::TranscriptFieldType};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EccWnafRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 5>,
    pub(crate) r1: SharedUnivariate<T, P, 5>,
    pub(crate) r2: SharedUnivariate<T, P, 5>,
    pub(crate) r3: SharedUnivariate<T, P, 5>,
    pub(crate) r4: SharedUnivariate<T, P, 5>,
    pub(crate) r5: SharedUnivariate<T, P, 5>,
    pub(crate) r6: SharedUnivariate<T, P, 5>,
    pub(crate) r7: SharedUnivariate<T, P, 5>,
    pub(crate) r8: SharedUnivariate<T, P, 5>,
    pub(crate) r9: SharedUnivariate<T, P, 5>,
    pub(crate) r10: SharedUnivariate<T, P, 5>,
    pub(crate) r11: SharedUnivariate<T, P, 5>,
    pub(crate) r12: SharedUnivariate<T, P, 5>,
    pub(crate) r13: SharedUnivariate<T, P, 5>,
    pub(crate) r14: SharedUnivariate<T, P, 5>,
    pub(crate) r15: SharedUnivariate<T, P, 5>,
    pub(crate) r16: SharedUnivariate<T, P, 5>,
    pub(crate) r17: SharedUnivariate<T, P, 5>,
    pub(crate) r18: SharedUnivariate<T, P, 5>,
    pub(crate) r19: SharedUnivariate<T, P, 5>,
    pub(crate) r20: SharedUnivariate<T, P, 5>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccWnafRelationAcc<T, P> {
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
            r8: SharedUnivariate::default(),
            r9: SharedUnivariate::default(),
            r10: SharedUnivariate::default(),
            r11: SharedUnivariate::default(),
            r12: SharedUnivariate::default(),
            r13: SharedUnivariate::default(),
            r14: SharedUnivariate::default(),
            r15: SharedUnivariate::default(),
            r16: SharedUnivariate::default(),
            r17: SharedUnivariate::default(),
            r18: SharedUnivariate::default(),
            r19: SharedUnivariate::default(),
            r20: SharedUnivariate::default(),
        }
    }
}
pub(crate) struct EccWnafRelation {}
impl EccWnafRelation {
    pub(crate) const NUM_RELATIONS: usize = 21;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 43;
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccWnafRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r1.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r2.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r3.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r4.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r5.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r6.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r7.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r8.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r9.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r10.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r11.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r12.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r13.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r14.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r15.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r16.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r17.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r18.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r19.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r20.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
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
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccWnafRelation
{
    type Acc = EccWnafRelationAcc<T, P>;

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_precompute_scalar_sum(entity);
        batch.add_precompute_scalar_sum_shift(entity);
        batch.add_precompute_point_transition(entity);
        batch.add_precompute_round(entity);
        batch.add_precompute_round_shift(entity);
        batch.add_precompute_pc(entity);
        batch.add_precompute_pc_shift(entity);
        batch.add_precompute_select(entity);
        batch.add_precompute_select_shift(entity);
        batch.add_precompute_s1hi_shift(entity);
        batch.add_precompute_skew(entity);
        batch.add_precompute_s1hi(entity);
        batch.add_precompute_s1lo(entity);
        batch.add_precompute_s2hi(entity);
        batch.add_precompute_s2lo(entity);
        batch.add_precompute_s3hi(entity);
        batch.add_precompute_s3lo(entity);
        batch.add_precompute_s4hi(entity);
        batch.add_precompute_s4lo(entity);
    }
    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        _relation_parameters: &RelationParameters<<P>::ScalarField, ECCVMFlavour>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let id = state.id();

        let scalar_sum = input.witness.precompute_scalar_sum();
        let scalar_sum_new = input.shifted_witness.precompute_scalar_sum_shift();
        let q_transition = input.witness.precompute_point_transition();
        let round = input.witness.precompute_round();
        let round_shift = input.shifted_witness.precompute_round_shift();
        let pc = input.witness.precompute_pc();
        let pc_shift = input.shifted_witness.precompute_pc_shift();
        let precompute_select = input.witness.precompute_select();
        let precompute_select_shift = input.shifted_witness.precompute_select_shift();
        let s1_shift = input.shifted_witness.precompute_s1hi_shift();
        let one = P::ScalarField::one();
        let minus_one = P::ScalarField::from(-1);
        let minus_three = P::ScalarField::from(-3);
        let minus_two = P::ScalarField::from(-2);
        let minus_seven = P::ScalarField::from(-7);
        let minus_15 = P::ScalarField::from(-15);
        let fifteen = P::ScalarField::from(15);
        let two = P::ScalarField::from(2);

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

        let mut scaled_transition = q_transition.to_owned();
        T::mul_assign_with_public_many(&mut scaled_transition, scaling_factors);
        let mut scaled_transition_is_zero = scaled_transition.clone();
        T::scale_many_in_place(&mut scaled_transition_is_zero, minus_one);
        T::add_assign_public_many(&mut scaled_transition_is_zero, scaling_factors, id);

        let mut lhs1 = Vec::with_capacity(
            2 * (slices[0].len()
                + slices[1].len()
                + slices[2].len()
                + slices[3].len()
                + slices[4].len()
                + slices[5].len()
                + slices[6].len()
                + slices[7].len())
                + 2 * precompute_select.len()
                + 6 * precompute_select.len(), //this is from precompute_select_zero which should have the same length as precompute_select
        );
        let mut rhs1 = Vec::with_capacity(lhs1.len());
        lhs1.extend(T::add_scalar(slices[0], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[1], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[2], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[3], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[4], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[5], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[6], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[7], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[0], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[1], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[2], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[3], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[4], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[5], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[6], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(slices[7], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        lhs1.extend(T::add_scalar(s1_shift, minus_two, id));

        rhs1.extend(T::add_scalar(slices[0], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[1], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[2], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[3], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[4], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[5], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[6], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[7], minus_one, id)); // first sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[0], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[1], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[2], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[3], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[4], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[5], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[6], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(slices[7], minus_two, id)); // second sqr() of the above range_constraint_slice_to_2_bits
        rhs1.extend(T::add_scalar(s1_shift, minus_three, id));

        let convert_to_wnaf = |s0: &Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>,
                               s1: &Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>|
         -> Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare> {
            let mut t = s0.to_owned();
            T::scale_many_in_place(&mut t, two * two);
            T::add_assign_many(&mut t, s1);
            T::scale_many_in_place(&mut t, two);
            T::add_scalar_in_place(&mut t, minus_15, id);
            t
        };

        let mut w0 = convert_to_wnaf(slices[0], slices[1]);
        let mut w1 = convert_to_wnaf(slices[2], slices[3]);
        let mut w2 = convert_to_wnaf(slices[4], slices[5]);
        let mut w3 = convert_to_wnaf(slices[6], slices[7]);

        let mut row_slice = w0.clone();
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w1);
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w2);
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w3);

        let mut sum_delta = scalar_sum.to_owned();
        T::scale_many_in_place(&mut sum_delta, P::ScalarField::from(1u64 << 16));
        T::add_assign_many(&mut sum_delta, &row_slice);
        let check_sum = T::sub_many(scalar_sum_new, &sum_delta);

        lhs1.extend(precompute_select.clone());
        rhs1.extend(check_sum.clone());

        let mut round_check = round.to_owned();
        T::scale_many_in_place(&mut round_check, minus_one);
        T::add_assign_many(&mut round_check, round_shift);
        T::add_scalar_in_place(&mut round_check, minus_one, id);
        let mut round_check_neg = round_check.to_owned();
        T::scale_many_in_place(&mut round_check_neg, minus_one);
        let tmp9_3 = T::add_many(
            &T::add_scalar(&T::add_many(&round_check_neg, round), minus_seven, id),
            &round_check,
        );

        lhs1.extend(precompute_select.clone());
        rhs1.extend(scaled_transition.clone());

        let pc_delta = T::sub_many(pc_shift, pc);
        let pc_delta_scaled = pc_delta
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, *a))
            .collect_vec();
        let pc_delta_minus_two = pc_delta
            .iter()
            .map(|a| T::add_with_public(minus_one, T::mul_with_public(minus_two, *a), id))
            .collect_vec();

        lhs1.extend(scaled_transition.clone());
        rhs1.extend(pc_delta_minus_two.clone());

        lhs1.extend(precompute_skew.clone());
        rhs1.extend(T::add_scalar(precompute_skew, minus_seven, id));

        let precompute_select_zero = precompute_select
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| {
                T::mul_with_public(
                    *b,
                    T::add_with_public(one, T::mul_with_public(minus_one, *a), id),
                )
            })
            .collect_vec();
        T::add_scalar_in_place(&mut w0, fifteen, id);
        T::add_scalar_in_place(&mut w1, fifteen, id);
        T::add_scalar_in_place(&mut w2, fifteen, id);
        T::add_scalar_in_place(&mut w3, fifteen, id);

        lhs1.extend(precompute_select_zero.clone());
        rhs1.extend(w0);
        lhs1.extend(precompute_select_zero.clone());
        rhs1.extend(w1);
        lhs1.extend(precompute_select_zero.clone());
        rhs1.extend(w2);
        lhs1.extend(precompute_select_zero.clone());
        rhs1.extend(w3);
        lhs1.extend(precompute_select_zero.clone());
        rhs1.extend(round);
        lhs1.extend(precompute_select_zero.clone());
        rhs1.extend(pc);

        let mul1 = T::mul_many(&lhs1, &rhs1, net, state)?;
        let mul1 = mul1.chunks_exact(mul1.len() / 27).collect_vec();
        debug_assert_eq!(mul1.len(), 27);

        let mut lhs2 = Vec::with_capacity(
            8 * mul1[0].len()
                + precompute_select_shift.len()
                + scaled_transition_is_zero.len()
                + tmp9_3.len()
                + round_shift.len()
                + scalar_sum_new.len()
                + precompute_select.len()
                + precompute_select.len(),
        );
        let mut rhs2 = Vec::with_capacity(lhs2.len());
        // these are for ((s - 1).sqr() - 1) * ((s - 2).sqr() - 1) in range_constraint_slice_to_2_bits;
        lhs2.extend(T::add_scalar(mul1[0], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[1], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[2], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[3], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[4], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[5], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[6], minus_one, id));
        lhs2.extend(T::add_scalar(mul1[7], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[8], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[9], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[10], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[11], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[12], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[13], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[14], minus_one, id));
        rhs2.extend(T::add_scalar(mul1[15], minus_one, id));

        // this is for precompute_select_shift * s1_shift_msb_set in acc 20
        lhs2.extend(mul1[16].to_owned());
        rhs2.extend(precompute_select_shift.clone()); // this is for precompute_select_shift * s1_shift_msb_set in acc 20

        // precompute_select * check_sum * scaled_transition_is_zero in acc 8
        lhs2.extend(mul1[17].to_owned());
        rhs2.extend(scaled_transition_is_zero.clone());

        // precompute_select * scaled_transition
        //     * ((round_check * minus_one + round + minus_seven) + round_check)
        // in acc 9
        lhs2.extend(mul1[18]);
        rhs2.extend(tmp9_3);

        // precompute_select * scaled_transition.clone() * round_shift in acc 10
        lhs2.extend(mul1[18]);
        rhs2.extend(round_shift);

        // precompute_select.to_owned() * scalar_sum_new * scaled_transition in acc 11
        lhs2.extend(mul1[18]);
        rhs2.extend(scalar_sum_new);

        // precompute_select * (scaled_transition * (pc_delta * minus_two + minus_one)
        //  + pc_delta * scaling_factor) in acc 12
        lhs2.extend(T::add_many(mul1[19], &pc_delta_scaled));
        rhs2.extend(precompute_select.clone());

        // precompute_select.to_owned() * (precompute_skew.to_owned()
        // * (precompute_skew.to_owned() + &minus_seven)
        // * scaling_factor) in acc 13
        lhs2.extend(mul1[20]);
        rhs2.extend(precompute_select.clone());

        // acc 14
        fold_accumulator!(univariate_accumulator.r14, mul1[21], SIZE);
        // acc 15
        fold_accumulator!(univariate_accumulator.r15, mul1[22], SIZE);
        // acc 16
        fold_accumulator!(univariate_accumulator.r16, mul1[23], SIZE);
        // acc 17
        fold_accumulator!(univariate_accumulator.r17, mul1[24], SIZE);
        // acc 18
        fold_accumulator!(univariate_accumulator.r18, mul1[25], SIZE);
        // acc 19
        fold_accumulator!(univariate_accumulator.r19, mul1[26], SIZE);

        let mul2 = T::mul_many(&lhs2, &rhs2, net, state)?;
        let mul2 = mul2.chunks_exact(mul2.len() / 15).collect_vec();
        debug_assert_eq!(mul2.len(), 15);

        // acc 0
        fold_accumulator!(
            univariate_accumulator.r0,
            mul2[0]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 1
        fold_accumulator!(
            univariate_accumulator.r1,
            mul2[1]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 2
        fold_accumulator!(
            univariate_accumulator.r2,
            mul2[2]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 3
        fold_accumulator!(
            univariate_accumulator.r3,
            mul2[3]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 4
        fold_accumulator!(
            univariate_accumulator.r4,
            mul2[4]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 5
        fold_accumulator!(
            univariate_accumulator.r5,
            mul2[5]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 6
        fold_accumulator!(
            univariate_accumulator.r6,
            mul2[6]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 7
        fold_accumulator!(
            univariate_accumulator.r7,
            mul2[7]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );
        // acc 20
        fold_accumulator!(
            univariate_accumulator.r20,
            T::mul_many(mul2[8], &scaled_transition, net, state)?,
            SIZE
        );

        // acc 8
        fold_accumulator!(univariate_accumulator.r8, mul2[9], SIZE);
        // acc 9
        fold_accumulator!(univariate_accumulator.r9, mul2[10], SIZE);
        // acc 10
        fold_accumulator!(univariate_accumulator.r10, mul2[11], SIZE);
        // acc 11
        fold_accumulator!(univariate_accumulator.r11, mul2[12], SIZE);
        // acc 12
        fold_accumulator!(univariate_accumulator.r12, mul2[13], SIZE);
        // acc 13
        fold_accumulator!(
            univariate_accumulator.r13,
            mul2[14]
                .iter()
                .zip_eq(scaling_factors)
                .map(|(a, b)| T::mul_with_public(*b, *a))
                .collect_vec(),
            SIZE
        );

        Ok(())
    }
}
