use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use co_builder::{
    HonkProofResult,
    flavours::eccvm_flavour::ECCVMFlavour,
    polynomials::polynomial_flavours::{PrecomputedEntitiesFlavour, WitnessEntitiesFlavour},
    prelude::HonkCurve,
};
use common::{mpc::NoirUltraHonkProver, transcript::TranscriptFieldType};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EccSetRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 22>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccSetRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct EccSetRelation {}
impl EccSetRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 29;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccSetRelation
{
    type Acc = EccSetRelationAcc<T, P>;

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        // We do not do this check
        // (input.witness.z_perm().to_owned() - input.shifted_witness.z_perm_shift().to_owned())
        //     .is_zero()
        false
    }
    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_z_perm(entity);
        batch.add_z_perm_shift(entity);
        batch.add_precompute_round(entity);
        batch.add_precompute_pc(entity);
        batch.add_precompute_select(entity);
        batch.add_msm_pc(entity);
        batch.add_msm_count(entity);
        batch.add_msm_round(entity);
        batch.add_precompute_s1hi(entity);
        batch.add_precompute_s1lo(entity);
        batch.add_precompute_s2hi(entity);
        batch.add_precompute_s2lo(entity);
        batch.add_precompute_s3hi(entity);
        batch.add_precompute_s3lo(entity);
        batch.add_precompute_s4hi(entity);
        batch.add_precompute_s4lo(entity);
        batch.add_precompute_skew(entity);
        batch.add_precompute_point_transition(entity);
        batch.add_precompute_tx(entity);
        batch.add_precompute_ty(entity);
        batch.add_precompute_scalar_sum(entity);
        batch.add_msm_transition_shift(entity);
        batch.add_msm_pc_shift(entity);
        batch.add_msm_accumulator_x_shift(entity);
        batch.add_msm_accumulator_y_shift(entity);
        batch.add_msm_size_of_msm(entity);
        batch.add_msm_add1(entity);
        batch.add_msm_slice1(entity);
        batch.add_msm_add2(entity);
        batch.add_msm_slice2(entity);
        batch.add_msm_add3(entity);
        batch.add_msm_slice3(entity);
        batch.add_msm_add4(entity);
        batch.add_msm_slice4(entity);
        batch.add_transcript_pc(entity);
        batch.add_transcript_px(entity);
        batch.add_transcript_py(entity);
        batch.add_transcript_z1(entity);
        batch.add_transcript_z2(entity);
        batch.add_transcript_z1zero(entity);
        batch.add_transcript_z2zero(entity);
        batch.add_transcript_pc_shift(entity);
        batch.add_transcript_msm_x(entity);
        batch.add_transcript_msm_y(entity);
        batch.add_transcript_msm_transition(entity);
        batch.add_transcript_msm_count(entity);
        batch.add_transcript_mul(entity);
        batch.add_transcript_base_infinity(entity);
        batch.add_lagrange_first(entity);
        batch.add_lagrange_last(entity);
    }

    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut EccSetRelationAcc<T, P>,
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        relation_parameters: &RelationParameters<<P>::ScalarField, ECCVMFlavour>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let id = state.id();

        // degree-11
        tracing::trace!("compute grand product numerator");

        let precompute_round = input.witness.precompute_round();
        let precompute_round2 = T::add_many(precompute_round, precompute_round);
        let precompute_round4 = T::add_many(&precompute_round2, &precompute_round2);

        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let beta_sqr = relation_parameters.beta_sqr;
        let beta_cube = relation_parameters.beta_cube;
        let precompute_pc = input.witness.precompute_pc();
        let precompute_select = input.witness.precompute_select();

        let msm_pc = input.witness.msm_pc();
        let msm_count = input.witness.msm_count();
        let msm_round = input.witness.msm_round();
        let one = P::ScalarField::one();
        let minus_one = P::ScalarField::from(-1);
        let minus_15 = P::ScalarField::from(-15);
        let two = P::ScalarField::from(2);
        let three = P::ScalarField::from(3);
        let four = P::ScalarField::from(4);

        // First term: tuple of (pc, round, wnaf_slice), computed when slicing scalar multipliers into slices,
        // as part of ECCVMWnafRelation.
        // If precompute_select = 1, tuple entry = (wnaf-slice + point-counter * beta + msm-round * beta_sqr).
        // There are 4 tuple entries per row.
        // let mut numerator = Univariate {
        //     evaluations: [P::ScalarField::one(); SIZE],
        // }; // degree-0

        let s0 = input.witness.precompute_s1hi();
        let s1 = input.witness.precompute_s1lo();

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input0 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&precompute_round4, beta_sqr),
            ),
        );
        let numerator = wnaf_slice_input0; // degree-1 

        let s0 = input.witness.precompute_s2hi();
        let s1 = input.witness.precompute_s2lo();

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input1 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&T::add_scalar(&precompute_round4, one, id), beta_sqr),
            ),
        );
        let mut lhs = Vec::with_capacity(15 * numerator.len());
        let mut rhs = Vec::with_capacity(lhs.len());

        lhs.extend(numerator);
        rhs.extend(wnaf_slice_input1);
        // numerator *= wnaf_slice_input1; // degree-2 DONE HERE

        let s0 = input.witness.precompute_s3hi();
        let s1 = input.witness.precompute_s3lo();

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input2 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&T::add_scalar(&precompute_round4, two, id), beta_sqr),
            ),
        );
        // numerator *= wnaf_slice_input2; // degree-3 TODO
        lhs.extend(wnaf_slice_input2);

        let s0 = input.witness.precompute_s4hi();
        let s1 = input.witness.precompute_s4lo();

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input3 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&T::add_scalar(&precompute_round4, three, id), beta_sqr),
            ),
        );
        // numerator *= wnaf_slice_input3; // degree-4 TODO
        rhs.extend(wnaf_slice_input3);

        // skew product if relevant
        let skew = input.witness.precompute_skew();
        let precompute_point_transition = input.witness.precompute_point_transition();
        let mut skew_input_factor = precompute_pc.to_owned();
        T::scale_many_in_place(&mut skew_input_factor, beta);
        T::add_assign_many(&mut skew_input_factor, skew);
        T::add_assign_many(
            &mut skew_input_factor,
            &T::scale_many(&T::add_scalar(&precompute_round4, four, id), beta_sqr),
        );
        T::add_scalar_in_place(&mut skew_input_factor, gamma, id);
        let mut skew_input_summand = precompute_point_transition.to_owned();
        T::scale_many_in_place(&mut skew_input_summand, minus_one);
        T::add_scalar_in_place(&mut skew_input_summand, one, id);

        // skew
        //     + &gamma
        //     + precompute_pc.to_owned() * beta
        //     + (precompute_round4 + &P::ScalarField::from(4)) * beta_sqr;
        lhs.extend(precompute_point_transition.clone());
        rhs.extend(&skew_input_factor);
        // let skew_input = precompute_point_transition.to_owned() * skew_input_factor
        //     + (T::add_scalar(
        //         &T::scale_many(precompute_point_transition, minus_one),
        //         one,
        //         id,
        //     )); TODO
        // numerator *= skew_input; // degree-5 TODO

        // let eccvm_set_permutation_delta = relation_parameters.eccvm_set_permutation_delta;
        let mut numerator_factor_7 = precompute_select.to_owned();
        T::scale_many_in_place(
            &mut numerator_factor_7,
            one - relation_parameters.eccvm_set_permutation_delta,
        );
        T::add_scalar_in_place(
            &mut numerator_factor_7,
            relation_parameters.eccvm_set_permutation_delta,
            id,
        );
        // numerator *= numerator_factor_7 TODO
        // ); // degree-7

        // Second term: tuple of (point-counter, P.x, P.y, scala r-multiplier), used in ECCVMWnafRelation and
        // ECCVMPointTableRelation. ECCVMWnafRelation validates the sum of the wnaf slices associated with point-counter
        // equals scalar-multiplier. ECCVMPointTableRelation computes a table of multiples of [P]: { -15[P], -13[P], ...,
        // 15[P] }. We need to validate that scalar-multiplier and [P] = (P.x, P.y) come from MUL opcodes in the transcript
        // columns.

        let convert_to_wnaf = |s0: &Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>,
                               s1: &Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>|
         -> Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare> {
            let mut t = s0.to_owned();
            T::scale_many_in_place(&mut t, four);
            T::add_assign_many(&mut t, s1);
            T::scale_many_in_place(&mut t, two);
            T::add_scalar_in_place(&mut t, minus_15, id);
            t
        };

        let table_x = input.witness.precompute_tx();
        let table_y = input.witness.precompute_ty();

        let precompute_skew = input.witness.precompute_skew();
        let negative_inverse_seven = P::ScalarField::from(-7)
            .inverse()
            .expect("-7 is hopefully non-zero");
        let mut adjusted_skew = precompute_skew.to_owned();
        T::scale_many_in_place(&mut adjusted_skew, negative_inverse_seven);

        let wnaf_scalar_sum = input.witness.precompute_scalar_sum();
        let w0 = convert_to_wnaf(
            input.witness.precompute_s1hi(),
            input.witness.precompute_s1lo(),
        );
        let w1 = convert_to_wnaf(
            input.witness.precompute_s2hi(),
            input.witness.precompute_s2lo(),
        );
        let w2 = convert_to_wnaf(
            input.witness.precompute_s3hi(),
            input.witness.precompute_s3lo(),
        );
        let w3 = convert_to_wnaf(
            input.witness.precompute_s4hi(),
            input.witness.precompute_s4lo(),
        );

        let mut row_slice = w0.clone();
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w1);
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w2);
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w3);

        let mut scalar_sum_full = wnaf_scalar_sum.to_owned();
        T::scale_many_in_place(&mut scalar_sum_full, P::ScalarField::from(65536));
        T::add_assign_many(
            &mut scalar_sum_full,
            &T::add_many(&row_slice, &adjusted_skew),
        );

        let precompute_point_transition = input.witness.precompute_point_transition();

        let mut point_table_init_read = table_x.to_owned(); // * beta
        //     + precompute_pc
        //     + table_y.to_owned() * beta_sqr
        //     + scalar_sum_full * beta_cube;
        T::scale_many_in_place(&mut point_table_init_read, beta);
        T::add_assign_many(&mut point_table_init_read, precompute_pc);
        T::add_assign_many(
            &mut point_table_init_read,
            &T::add_many(
                &T::scale_many(table_y, beta_sqr),
                &T::scale_many(&scalar_sum_full, beta_cube),
            ),
        );
        T::add_scalar_in_place(&mut point_table_init_read, gamma, id);
        // let mut point_table_init_read = precompute_point_transition.to_owned()
        //     * (point_table_init_read + &gamma)
        //     + (precompute_point_transition.to_owned() * minus_one + &P::ScalarField::one());
        let mut point_table_init_read_summand = precompute_point_transition.to_owned();
        T::scale_many_in_place(&mut point_table_init_read_summand, minus_one);
        T::add_scalar_in_place(&mut point_table_init_read_summand, one, id);
        lhs.extend(precompute_point_transition);
        rhs.extend(point_table_init_read);

        // numerator *= point_table_init_read; // degree-9 TODO

        // Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMMSMRelation.
        // (P.x, P.y) is the output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
        // We need to validate that the same values (P.x, P.y) are present in the Transcript columns and describe a
        // multi-scalar multiplication of size `msm-size`, starting at `point-counter`.

        let lagrange_first_modified = input
            .precomputed
            .lagrange_first()
            .iter()
            .map(|a| *a * minus_one + one)
            .collect_vec();

        let partial_msm_transition_shift = input.shifted_witness.msm_transition_shift();
        let msm_transition_shift =
            T::mul_with_public_many(&lagrange_first_modified, partial_msm_transition_shift);
        let msm_pc_shift = input.shifted_witness.msm_pc_shift();

        let msm_x_shift = input.shifted_witness.msm_accumulator_x_shift();
        let msm_y_shift = input.shifted_witness.msm_accumulator_y_shift();
        let msm_size = input.witness.msm_size_of_msm();

        let msm_result_write = T::add_many(
            &T::scale_many(msm_x_shift, beta),
            &T::add_many(
                &T::scale_many(msm_y_shift, beta_sqr),
                &T::add_many(&T::scale_many(msm_size, beta_cube), msm_pc_shift),
            ),
        );

        lhs.extend(&msm_transition_shift);
        rhs.extend(T::add_scalar(&msm_result_write, gamma, id));
        // msm_result_write = msm_transition_shift.to_owned() * (msm_result_write + &gamma)
        //     + (msm_transition_shift * minus_one + &P::ScalarField::one()); //TODO subtract this from the product
        // numerator *= msm_result_write; // degree-11 TODO

        // numerator
        tracing::trace!("compute grand product numinator finished");

        // degree-20
        tracing::trace!("compute grand product denominator");

        // AZTEC TODO(@zac-williamson). The degree of this contribution is 17! makes overall relation degree 19.
        // Can optimise by refining the algebra, once we have a stable base to iterate off of.

        /*
         * @brief First term: tuple of (pc, round, wnaf_slice), used to determine which points we extract from lookup tables
         * when evaluaing MSMs in ECCVMMsmRelation.
         * These values must be equivalent to the values computed in the 1st term of `compute_grand_product_numerator`
         */
        // let mut denominator = Univariate {
        //     evaluations: [P::ScalarField::one(); SIZE],
        // }; // degree-0

        let add1 = input.witness.msm_add1();
        let msm_slice1 = input.witness.msm_slice1();

        // let wnaf_slice_output1 = add1.to_owned()
        //     * (msm_slice1.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add1.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output1_factor = msm_slice1.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output1_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output1_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(msm_count, beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output1_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output1_summand = add1.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output1_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output1_summand, one, id);
        lhs.extend(add1);
        rhs.extend(wnaf_slice_output1_factor);
        // denominator *= wnaf_slice_output1; // degree-2 TODO

        let add2 = input.witness.msm_add2();
        let msm_slice2 = input.witness.msm_slice2();

        // let wnaf_slice_output2 = add2.to_owned()
        //     * (msm_slice2.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count + &minus_one) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add2.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output2_factor = msm_slice2.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output2_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output2_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(&T::add_scalar(msm_count, one, id), beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output2_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output2_summand = add2.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output2_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output2_summand, one, id);
        lhs.extend(add2);
        rhs.extend(wnaf_slice_output2_factor);
        // denominator *= wnaf_slice_output2; // degree-4 TODO

        let add3 = input.witness.msm_add3();
        let msm_slice3 = input.witness.msm_slice3();

        // let wnaf_slice_output3 = add3.to_owned()
        //     * (msm_slice3.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count + &P::ScalarField::from(-2)) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add3.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output3_factor = msm_slice3.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output3_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output3_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(&T::add_scalar(msm_count, two, id), beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output3_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output3_summand = add3.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output3_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output3_summand, one, id);
        lhs.extend(add3);
        rhs.extend(wnaf_slice_output3_factor);
        // denominator *= wnaf_slice_output3; // degree-6 TODO

        let add4 = input.witness.msm_add4();
        let msm_slice4 = input.witness.msm_slice4();

        // let wnaf_slice_output4 = add4.to_owned()
        //     * (msm_slice4.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count + &P::ScalarField::from(-3)) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add4.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output4_factor = msm_slice4.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output4_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output4_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(&T::add_scalar(msm_count, three, id), beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output4_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output4_summand = add4.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output4_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output4_summand, one, id);
        lhs.extend(add4);
        rhs.extend(wnaf_slice_output4_factor);
        // denominator *= wnaf_slice_output4; // degree-8 TODO

        /*
         * @brief Second term: tuple of (transcript_pc, transcript_Px, transcript_Py, z1) OR (transcript_pc, \lambda *
         * transcript_Px, -transcript_Py, z2) for each scalar multiplication in ECCVMTranscriptRelation columns. (the latter
         * term uses the curve endomorphism: \lambda = cube root of unity). These values must be equivalent to the second
         * term values in `compute_grand_product_numerator`
         */
        let transcript_pc = input.witness.transcript_pc();
        let transcript_px = input.witness.transcript_px();
        let transcript_py = input.witness.transcript_py();
        let z1 = input.witness.transcript_z1();
        let z2 = input.witness.transcript_z2();
        let z1_zero = input.witness.transcript_z1zero();
        let z2_zero = input.witness.transcript_z2zero();

        let mut lookup_first = z1_zero.to_owned(); //* minus_one + &P::ScalarField::one();
        T::scale_many_in_place(&mut lookup_first, minus_one);
        T::add_scalar_in_place(&mut lookup_first, one, id);
        let mut lookup_second = z2_zero.to_owned(); // * minus_one + &P::ScalarField::one();
        T::scale_many_in_place(&mut lookup_second, minus_one);
        T::add_scalar_in_place(&mut lookup_second, one, id);
        let endomorphism_base_field_shift = P::CycleGroup::get_cube_root_of_unity();

        let mut transcript_input1 = transcript_px.to_owned(); // * beta
        // + transcript_pc
        // + transcript_py.to_owned() * beta_sqr
        // + z1.to_owned() * beta_cube; // degree = 1
        T::scale_many_in_place(&mut transcript_input1, beta);
        T::add_assign_many(&mut transcript_input1, transcript_pc);
        T::add_assign_many(
            &mut transcript_input1,
            &T::scale_many(transcript_py, beta_sqr),
        );
        T::add_assign_many(&mut transcript_input1, &T::scale_many(z1, beta_cube));
        let mut transcript_input2 = transcript_px.to_owned(); // * endomorphism_base_field_shift * beta
        // + transcript_pc.to_owned()
        // + &minus_one
        // + transcript_py.to_owned() * beta_sqr * minus_one
        // + z2.to_owned() * beta_cube; // degree = 2
        T::scale_many_in_place(&mut transcript_input2, endomorphism_base_field_shift);
        T::scale_many_in_place(&mut transcript_input2, beta);
        T::add_assign_many(&mut transcript_input2, transcript_pc);
        T::add_scalar_in_place(&mut transcript_input2, minus_one, id);
        T::add_assign_many(
            &mut transcript_input2,
            &T::scale_many(transcript_py, beta_sqr * minus_one),
        );
        T::add_assign_many(&mut transcript_input2, &T::scale_many(z2, beta_cube));

        // transcript_input1 = (transcript_input1 + &gamma) * lookup_first.clone()
        //     + (lookup_first.to_owned() * minus_one + &P::ScalarField::one()); // degree 2 TODO ADD THIS
        T::add_scalar_in_place(&mut transcript_input1, gamma, id);
        lhs.extend(transcript_input1);
        rhs.extend(lookup_first.clone());
        // transcript_input2 = (transcript_input2 + &gamma) * lookup_second.clone()
        //     + (lookup_second.to_owned() * minus_one + &P::ScalarField::one()); // degree 3 TODO ADD THIS
        T::add_scalar_in_place(&mut transcript_input2, gamma, id);
        lhs.extend(transcript_input2);
        rhs.extend(lookup_second.clone());

        // let transcript_product = (transcript_input1 * transcript_input2)
        //     * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
        //     + base_infinity; // degree 6 TODO

        // let point_table_init_write = transcript_mul.to_owned() * transcript_product
        //     + (transcript_mul.to_owned() * minus_one + &P::ScalarField::one()); TODO
        // denominator *= point_table_init_write; // degree 17 TODO

        /*
         * @brief Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMTranscriptRelation.
         *        (P.x, P.y) is the *claimed* output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
         *        We need to validate that the msm output produced in ECCVMMSMRelation is equivalent to the output present
         * in `transcript_msm_output_x, transcript_msm_output_y`, for a given multi-scalar multiplication starting at
         * `transcript_pc` and has size `transcript_msm_count`
         */
        let transcript_pc_shift = input.shifted_witness.transcript_pc_shift();
        let transcript_msm_x = input.witness.transcript_msm_x();
        let transcript_msm_y = input.witness.transcript_msm_y();
        let transcript_msm_transition = input.witness.transcript_msm_transition();
        let transcript_msm_count = input.witness.transcript_msm_count();
        let z1_zero = input.witness.transcript_z1zero();
        let z2_zero = input.witness.transcript_z2zero();
        let transcript_mul = input.witness.transcript_mul();
        let base_infinity = input.witness.transcript_base_infinity();

        //  let full_msm_count = transcript_mul.to_owned()
        // * ((z1_zero.to_owned() * minus_one + &P::ScalarField::one())
        //     + (z2_zero.to_owned() * minus_one + &P::ScalarField::one()))
        // * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
        // + transcript_msm_count;
        let full_msm_count_factor_1 = transcript_mul;
        let mut full_msm_count_factor_2 = z1_zero.to_owned();
        T::scale_many_in_place(&mut full_msm_count_factor_2, minus_one);
        T::add_scalar_in_place(&mut full_msm_count_factor_2, two, id);
        T::sub_assign_many(&mut full_msm_count_factor_2, z2_zero);
        let mut full_msm_count_factor_3 = base_infinity.to_owned();
        T::scale_many_in_place(&mut full_msm_count_factor_3, minus_one);
        T::add_scalar_in_place(&mut full_msm_count_factor_3, one, id);
        let full_msm_count_summand = transcript_msm_count;
        lhs.extend(full_msm_count_factor_1);
        rhs.extend(full_msm_count_factor_2);

        let mut msm_result_read = transcript_msm_x.to_owned(); // * beta
        // + transcript_msm_y.to_owned() * beta_sqr
        // + full_msm_count.to_owned() * beta_cube
        // + transcript_pc_shift;
        T::scale_many_in_place(&mut msm_result_read, beta);
        T::add_assign_many(
            &mut msm_result_read,
            &T::scale_many(transcript_msm_y, beta_sqr),
        );
        // T::add_assign_many(
        //     &mut msm_result_read,
        //     &T::scale_many(transcript_msm_count, beta_cube), //TODO FLORIN: Removed this?
        // );
        T::add_assign_many(&mut msm_result_read, transcript_pc_shift);
        T::add_scalar_in_place(&mut msm_result_read, gamma, id);

        // msm_result_read = transcript_msm_transition.to_owned() * (msm_result_read + &gamma)<- DONE
        //     + (transcript_msm_transition.to_owned() * minus_one + &P::ScalarField::one()); TODO
        // denominator *= msm_result_read; // degree-20 TODO

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 12).collect_vec();
        debug_assert_eq!(mul.len(), 12);

        // Numerator stuff:
        let numerator_2 = mul[0].to_owned();
        let wnaf2wnaf3 = mul[1].to_owned(); //TODO multiply to numerator
        let mut skew_input = mul[2].to_owned(); //TODO multiply to numerator
        T::sub_assign_many(&mut skew_input, precompute_point_transition);
        T::add_scalar_in_place(&mut skew_input, one, id);
        let mut point_table_init_read = mul[3].to_owned(); //TODO multiply to numerator
        T::add_assign_many(&mut point_table_init_read, &point_table_init_read_summand);
        let mut msm_result_write = mul[4].to_owned(); //TODO multiply to numerator
        T::sub_assign_many(&mut msm_result_write, &msm_transition_shift);
        T::add_scalar_in_place(&mut msm_result_write, one, id);

        // Denominator stuff:
        let mut wnaf_slice_output1 = mul[5].to_owned();
        T::add_assign_many(&mut wnaf_slice_output1, &wnaf_slice_output1_summand);
        let mut wnaf_slice_output2 = mul[6].to_owned();
        T::add_assign_many(&mut wnaf_slice_output2, &wnaf_slice_output2_summand);
        let mut wnaf_slice_output3 = mul[7].to_owned();
        T::add_assign_many(&mut wnaf_slice_output3, &wnaf_slice_output3_summand);
        let mut wnaf_slice_output4 = mul[8].to_owned();
        T::add_assign_many(&mut wnaf_slice_output4, &wnaf_slice_output4_summand);
        let mut transcript_input1 = mul[9].to_owned();
        T::sub_assign_many(&mut transcript_input1, &lookup_first);
        T::add_scalar_in_place(&mut transcript_input1, one, id);
        let mut transcript_input2 = mul[10].to_owned();
        T::sub_assign_many(&mut transcript_input2, &lookup_second);
        T::add_scalar_in_place(&mut transcript_input2, one, id);
        let full_msm_count = mul[11].to_owned();
        // let mut msm_result_read = mul[12].to_owned(); // TODO multiply to denominator
        // T::sub_assign_many(&mut msm_result_read, &transcript_msm_transition);
        // T::add_scalar_in_place(&mut msm_result_read, one, id);

        let mut lhs2 = Vec::with_capacity(mul[0].len() * 4);
        let mut rhs2 = Vec::with_capacity(lhs2.len());
        lhs2.extend(wnaf2wnaf3);
        rhs2.extend(skew_input);
        lhs2.extend(point_table_init_read);
        rhs2.extend(msm_result_write);

        lhs2.extend(wnaf_slice_output1);
        rhs2.extend(wnaf_slice_output2);
        lhs2.extend(wnaf_slice_output3);
        rhs2.extend(wnaf_slice_output4);
        lhs2.extend(transcript_input1);
        rhs2.extend(transcript_input2);
        lhs2.extend(full_msm_count);
        rhs2.extend(full_msm_count_factor_3);

        let mul2 = T::mul_many(&lhs2, &rhs2, net, state)?;
        let mul2 = mul2.chunks_exact(mul2.len() / 6).collect_vec();
        debug_assert_eq!(mul2.len(), 6);

        let mut lhs3 = Vec::with_capacity(4 * mul2[0].len());
        let mut rhs3 = Vec::with_capacity(lhs3.len());
        lhs3.extend(mul2[0].to_owned()); // wnaf2wnaf3 * skew_input
        rhs3.extend(mul2[1].to_owned()); // point_table_init_read * msm_result_write

        lhs3.extend(mul2[2].to_owned()); // wnaf_slice_output1 * wnaf_slice_output2
        rhs3.extend(mul2[3].to_owned()); // wnaf_slice_output3 * wnaf_slice_output4
        lhs3.extend(mul2[4].to_owned()); // transcript_input1 * transcript_input2
        rhs3.extend(T::add_scalar(
            &T::scale_many(base_infinity, minus_one),
            one,
            id,
        )); // TODO: add base_infinity to this result
        let mut full_msm_count = T::add_many(mul2[5], full_msm_count_summand);
        T::scale_many_in_place(&mut full_msm_count, beta_cube);
        T::add_assign_many(&mut msm_result_read, &full_msm_count);
        lhs3.extend(transcript_msm_transition.to_owned());
        rhs3.extend(msm_result_read);

        let mul = T::mul_many(&lhs3, &rhs3, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 4).collect_vec();
        debug_assert_eq!(mul.len(), 4);

        let mut lhs4 = Vec::with_capacity(4 * mul[0].len());
        let mut rhs4 = Vec::with_capacity(lhs4.len());
        lhs4.extend(mul[0].to_owned()); // (wnaf2wnaf3 * skew_input) *  (point_table_init_read * msm_result_write)
        rhs4.extend(numerator_2); // 

        lhs4.extend(T::add_many(mul[2], base_infinity)); // (transcript_input1 * transcript_input2)   * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
        rhs4.extend(transcript_mul.to_owned());

        let mut msm_result_read = mul[3].to_owned(); //  (transcript_msm_transition.to_owned() * (msm_result_read + &gamma) 
        T::sub_assign_many(&mut msm_result_read, transcript_msm_transition);
        T::add_scalar_in_place(&mut msm_result_read, one, id);

        lhs4.extend(mul[1].to_owned()); // (wnaf_slice_output1 * wnaf_slice_output2) * (wnaf_slice_output3 * wnaf_slice_output4)
        rhs4.extend(msm_result_read);

        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();
        let mut z_perm_modified = input.witness.z_perm().to_owned();
        T::add_assign_public_many(&mut z_perm_modified, lagrange_first, id);
        let z_perm_shift = input.shifted_witness.z_perm_shift();

        lhs4.extend(z_perm_modified.to_owned());
        rhs4.extend(numerator_factor_7);

        let mul = T::mul_many(&lhs4, &rhs4, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 4).collect_vec();
        debug_assert_eq!(mul.len(), 4);

        let final_numerator_factor = mul[3]; // ((z_perm.to_owned() + lagrange_first) * numerator_factor_7

        let mut lhs5 = Vec::with_capacity(mul[0].len() * 2);
        let mut rhs5 = Vec::with_capacity(lhs5.len());
        lhs5.extend(mul[0].to_owned()); // final numerator
        rhs5.extend(final_numerator_factor.to_owned()); // z_perm + lagrange_first

        let mut point_table_init_write = mul[1].to_owned(); // transcript_mul.to_owned() * transcript_product
        T::sub_assign_many(&mut point_table_init_write, transcript_mul);
        T::add_scalar_in_place(&mut point_table_init_write, one, id);

        lhs5.extend(point_table_init_write);
        rhs5.extend(mul[2].to_owned()); // Returns the final denominator

        let mul = T::mul_many(&lhs5, &rhs5, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);

        let numerator_evaluation = mul[0].to_owned(); // this is already ((z_perm.to_owned() + lagrange_first) * numerator_evaluation
        let denominator_evaluation = mul[1]; // this is just denominator_evaluation and needs to be multiplied by (z_perm_shift.to_owned() + lagrange_last)
        let mut z_perm_shift_scaled = z_perm_shift.to_owned();
        T::add_assign_public_many(&mut z_perm_shift_scaled, lagrange_last, id);
        let final_mul = T::mul_many(denominator_evaluation, &z_perm_shift_scaled, net, state)?;

        let mut tmp = T::sub_many(&numerator_evaluation, &final_mul);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        // // degree-21
        // let mut tmp = ((z_perm.to_owned() + lagrange_first) * numerator_evaluation
        //     - (z_perm_shift.to_owned() + lagrange_last) * denominator_evaluation)
        //     * scaling_factors;
        // for i in 0..univariate_accumulator.r0.evaluations.len() {
        //     univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        // }

        // // Contribution (2)
        let mut tmp = z_perm_shift.to_owned(); // lagrange_last.to_owned() * * scaling_factors;
        T::mul_assign_with_public_many(&mut tmp, lagrange_last);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        Ok(())
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccSetRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r1.scale_inplace(*current_scalar);
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
    }
}
