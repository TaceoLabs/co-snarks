use crate::{decider::types::ProverUnivariatesSized, prelude::Univariate};
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::{
    TranscriptFieldType, polynomials::polynomial_flavours::WitnessEntitiesFlavour,
    prelude::HonkCurve,
};
use co_builder::{
    flavours::eccvm_flavour::ECCVMFlavour,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct EccSetRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 22>,
    pub(crate) r1: Univariate<F, 3>,
}
#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct EccSetRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

pub(crate) struct EccSetRelation {}
impl EccSetRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const SKIPPABLE: bool = true;

    fn compute_grand_product_numerator<F: PrimeField, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
    ) -> Univariate<F, SIZE> {
        tracing::trace!("compute grand product numerator");

        let precompute_round = input.witness.precompute_round();
        let precompute_round2 = precompute_round.to_owned() + precompute_round;
        let precompute_round4 = precompute_round2.to_owned() + precompute_round2;

        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let beta_sqr = relation_parameters.beta_sqr;
        let beta_cube = relation_parameters.beta_cube;
        let precompute_pc = input.witness.precompute_pc();
        let precompute_select = input.witness.precompute_select();
        let minus_one = F::from(-1);

        // First term: tuple of (pc, round, wnaf_slice), computed when slicing scalar multipliers into slices,
        // as part of ECCVMWnafRelation.
        // If precompute_select = 1, tuple entry = (wnaf-slice + point-counter * beta + msm-round * beta_sqr).
        // There are 4 tuple entries per row.
        let mut numerator = Univariate {
            evaluations: [F::one(); SIZE],
        }; // degree-0

        let s0 = input.witness.precompute_s1hi();
        let s1 = input.witness.precompute_s1lo();

        let mut wnaf_slice = s0.to_owned() + s0;
        wnaf_slice += wnaf_slice.clone();
        wnaf_slice += s1;

        let wnaf_slice_input0 = wnaf_slice
            + &gamma
            + precompute_pc.to_owned() * beta
            + precompute_round4.to_owned() * beta_sqr;
        numerator *= wnaf_slice_input0; // degree-1

        let s0 = input.witness.precompute_s2hi();
        let s1 = input.witness.precompute_s2lo();

        let mut wnaf_slice = s0.to_owned() + s0;
        wnaf_slice += wnaf_slice.clone();
        wnaf_slice += s1;

        let wnaf_slice_input1 = wnaf_slice
            + &gamma
            + precompute_pc.to_owned() * beta
            + (precompute_round4.to_owned() + &F::one()) * beta_sqr;
        numerator *= wnaf_slice_input1; // degree-2

        let s0 = input.witness.precompute_s3hi();
        let s1 = input.witness.precompute_s3lo();

        let mut wnaf_slice = s0.to_owned() + s0;
        wnaf_slice += wnaf_slice.clone();
        wnaf_slice += s1;

        let wnaf_slice_input2 = wnaf_slice
            + &gamma
            + precompute_pc.to_owned() * beta
            + (precompute_round4.to_owned() + &F::from(2)) * beta_sqr;
        numerator *= wnaf_slice_input2; // degree-3

        let s0 = input.witness.precompute_s4hi();
        let s1 = input.witness.precompute_s4lo();

        let mut wnaf_slice = s0.to_owned() + s0;
        wnaf_slice += wnaf_slice.clone();
        wnaf_slice += s1;

        let wnaf_slice_input3 = wnaf_slice
            + &gamma
            + precompute_pc.to_owned() * beta
            + (precompute_round4.to_owned() + &F::from(3)) * beta_sqr;
        numerator *= wnaf_slice_input3; // degree-4

        // skew product if relevant
        let skew = input.witness.precompute_skew();
        let precompute_point_transition = input.witness.precompute_point_transition();
        let skew_input = precompute_point_transition.to_owned()
            * (skew.to_owned()
                + &gamma
                + precompute_pc.to_owned() * beta
                + (precompute_round4 + &F::from(4)) * beta_sqr)
            + (precompute_point_transition.to_owned() * minus_one + &F::one());
        numerator *= skew_input; // degree-5

        let eccvm_set_permutation_delta = relation_parameters.eccvm_set_permutation_delta;
        numerator *= precompute_select.to_owned()
            * (eccvm_set_permutation_delta * minus_one + F::one())
            + &eccvm_set_permutation_delta; // degree-7

        // Second term: tuple of (point-counter, P.x, P.y, scalar-multiplier), used in ECCVMWnafRelation and
        // ECCVMPointTableRelation. ECCVMWnafRelation validates the sum of the wnaf slices associated with point-counter
        // equals scalar-multiplier. ECCVMPointTableRelation computes a table of multiples of [P]: { -15[P], -13[P], ...,
        // 15[P] }. We need to validate that scalar-multiplier and [P] = (P.x, P.y) come from MUL opcodes in the transcript
        // columns.

        fn convert_to_wnaf<F: PrimeField, const SIZE: usize>(
            s0: Univariate<F, SIZE>,
            s1: Univariate<F, SIZE>,
        ) -> Univariate<F, SIZE> {
            let mut t = s0.clone() + s0;
            t += t.clone();
            t += s1;

            t.clone() + t - &F::from(15u32)
        }

        let table_x = input.witness.precompute_tx();
        let table_y = input.witness.precompute_ty();

        let precompute_skew = input.witness.precompute_skew();
        let negative_inverse_seven = F::from(-7).inverse().expect("-7 is hopefully non-zero");
        let adjusted_skew = precompute_skew.to_owned() * negative_inverse_seven;

        let wnaf_scalar_sum = input.witness.precompute_scalar_sum();
        let w0 = convert_to_wnaf::<F, SIZE>(
            input.witness.precompute_s1hi().to_owned(),
            input.witness.precompute_s1lo().to_owned(),
        );
        let w1 = convert_to_wnaf::<F, SIZE>(
            input.witness.precompute_s2hi().to_owned(),
            input.witness.precompute_s2lo().to_owned(),
        );
        let w2 = convert_to_wnaf::<F, SIZE>(
            input.witness.precompute_s3hi().to_owned(),
            input.witness.precompute_s3lo().to_owned(),
        );
        let w3 = convert_to_wnaf::<F, SIZE>(
            input.witness.precompute_s4hi().to_owned(),
            input.witness.precompute_s4lo().to_owned(),
        );

        let mut row_slice = w0;
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += w1;
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += w2;
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += row_slice.clone();
        row_slice += w3;

        let mut scalar_sum_full = wnaf_scalar_sum.to_owned() * F::from(2);
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += scalar_sum_full.clone();
        scalar_sum_full += row_slice + adjusted_skew;

        let precompute_point_transition = input.witness.precompute_point_transition();

        let mut point_table_init_read = table_x.to_owned() * beta
            + precompute_pc
            + table_y.to_owned() * beta_sqr
            + scalar_sum_full * beta_cube;
        point_table_init_read = precompute_point_transition.to_owned()
            * (point_table_init_read + &gamma)
            + (precompute_point_transition.to_owned() * minus_one + &F::one());

        numerator *= point_table_init_read; // degree-9

        // Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMMSMRelation.
        // (P.x, P.y) is the output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
        // We need to validate that the same values (P.x, P.y) are present in the Transcript columns and describe a
        // multi-scalar multiplication of size `msm-size`, starting at `point-counter`.

        let lagrange_first = input.precomputed.lagrange_first();
        let partial_msm_transition_shift = input.shifted_witness.msm_transition_shift();
        let msm_transition_shift =
            (lagrange_first.to_owned() * minus_one + &F::one()) * partial_msm_transition_shift;
        let msm_pc_shift = input.shifted_witness.msm_pc_shift();

        let msm_x_shift = input.shifted_witness.msm_accumulator_x_shift();
        let msm_y_shift = input.shifted_witness.msm_accumulator_y_shift();
        let msm_size = input.witness.msm_size_of_msm();

        let mut msm_result_write = msm_x_shift.to_owned() * beta
            + msm_y_shift.to_owned() * beta_sqr
            + msm_size.to_owned() * beta_cube
            + msm_pc_shift;

        msm_result_write = msm_transition_shift.to_owned() * (msm_result_write + &gamma)
            + (msm_transition_shift * minus_one + &F::one());
        numerator *= msm_result_write; // degree-11

        numerator
    }

    fn compute_grand_product_denominator<P: HonkCurve<TranscriptFieldType>, const SIZE: usize>(
        input: &ProverUnivariatesSized<P::ScalarField, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<P::ScalarField>,
    ) -> Univariate<P::ScalarField, SIZE> {
        tracing::trace!("compute grand product denominator");

        // AZTEC TODO(@zac-williamson). The degree of this contribution is 17! makes overall relation degree 19.
        // Can optimise by refining the algebra, once we have a stable base to iterate off of.
        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let beta_sqr = relation_parameters.beta_sqr;
        let beta_cube = relation_parameters.beta_cube;
        let msm_pc = input.witness.msm_pc();
        let msm_count = input.witness.msm_count();
        let msm_round = input.witness.msm_round();
        let minus_one = P::ScalarField::from(-1);

        /*
         * @brief First term: tuple of (pc, round, wnaf_slice), used to determine which points we extract from lookup tables
         * when evaluaing MSMs in ECCVMMsmRelation.
         * These values must be equivalent to the values computed in the 1st term of `compute_grand_product_numerator`
         */
        let mut denominator = Univariate {
            evaluations: [P::ScalarField::one(); SIZE],
        }; // degree-0

        let add1 = input.witness.msm_add1();
        let msm_slice1 = input.witness.msm_slice1();

        let wnaf_slice_output1 = add1.to_owned()
            * (msm_slice1.to_owned()
                + &gamma
                + (msm_pc.to_owned() - msm_count) * beta
                + msm_round.to_owned() * beta_sqr)
            + (add1.to_owned() * minus_one + &P::ScalarField::one());
        denominator *= wnaf_slice_output1; // degree-2

        let add2 = input.witness.msm_add2();
        let msm_slice2 = input.witness.msm_slice2();

        let wnaf_slice_output2 = add2.to_owned()
            * (msm_slice2.to_owned()
                + &gamma
                + (msm_pc.to_owned() - msm_count + &minus_one) * beta
                + msm_round.to_owned() * beta_sqr)
            + (add2.to_owned() * minus_one + &P::ScalarField::one());
        denominator *= wnaf_slice_output2; // degree-4

        let add3 = input.witness.msm_add3();
        let msm_slice3 = input.witness.msm_slice3();

        let wnaf_slice_output3 = add3.to_owned()
            * (msm_slice3.to_owned()
                + &gamma
                + (msm_pc.to_owned() - msm_count + &P::ScalarField::from(-2)) * beta
                + msm_round.to_owned() * beta_sqr)
            + (add3.to_owned() * minus_one + &P::ScalarField::one());
        denominator *= wnaf_slice_output3; // degree-6

        let add4 = input.witness.msm_add4();
        let msm_slice4 = input.witness.msm_slice4();

        let wnaf_slice_output4 = add4.to_owned()
            * (msm_slice4.to_owned()
                + &gamma
                + (msm_pc.to_owned() - msm_count + &P::ScalarField::from(-3)) * beta
                + msm_round.to_owned() * beta_sqr)
            + (add4.to_owned() * minus_one + &P::ScalarField::one());
        denominator *= wnaf_slice_output4; // degree-8

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
        let base_infinity = input.witness.transcript_base_infinity();
        let transcript_mul = input.witness.transcript_mul();

        let lookup_first = z1_zero.to_owned() * minus_one + &P::ScalarField::one();
        let lookup_second = z2_zero.to_owned() * minus_one + &P::ScalarField::one();
        let endomorphism_base_field_shift = P::CycleGroup::get_cube_root_of_unity();

        let mut transcript_input1 = transcript_px.to_owned() * beta
            + transcript_pc
            + transcript_py.to_owned() * beta_sqr
            + z1.to_owned() * beta_cube; // degree = 1
        let mut transcript_input2 = transcript_px.to_owned() * endomorphism_base_field_shift * beta
            + transcript_pc.to_owned()
            + &minus_one
            + transcript_py.to_owned() * beta_sqr * minus_one
            + z2.to_owned() * beta_cube; // degree = 2

        transcript_input1 = (transcript_input1 + &gamma) * lookup_first.clone()
            + (lookup_first.to_owned() * minus_one + &P::ScalarField::one()); // degree 2
        transcript_input2 = (transcript_input2 + &gamma) * lookup_second.clone()
            + (lookup_second.to_owned() * minus_one + &P::ScalarField::one()); // degree 3

        let transcript_product = (transcript_input1 * transcript_input2)
            * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
            + base_infinity; // degree 6

        let point_table_init_write = transcript_mul.to_owned() * transcript_product
            + (transcript_mul.to_owned() * minus_one + &P::ScalarField::one());
        denominator *= point_table_init_write; // degree 17

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

        let full_msm_count = transcript_mul.to_owned()
            * ((z1_zero.to_owned() * minus_one + &P::ScalarField::one())
                + (z2_zero.to_owned() * minus_one + &P::ScalarField::one()))
            * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
            + transcript_msm_count;

        let mut msm_result_read = transcript_msm_x.to_owned() * beta
            + transcript_msm_y.to_owned() * beta_sqr
            + full_msm_count.to_owned() * beta_cube
            + transcript_pc_shift;
        msm_result_read = transcript_msm_transition.to_owned() * (msm_result_read + &gamma)
            + (transcript_msm_transition.to_owned() * minus_one + &P::ScalarField::one());
        denominator *= msm_result_read; // degree-20

        denominator
    }
    pub(crate) fn skip<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> bool {
        (input.witness.z_perm().to_owned() - input.shifted_witness.z_perm_shift().to_owned())
            .is_zero()
    }

    pub(crate) fn accumulate<P: HonkCurve<TranscriptFieldType>, const SIZE: usize>(
        univariate_accumulator: &mut EccSetRelationAcc<P::ScalarField>,
        input: &crate::decider::types::ProverUnivariatesSized<P::ScalarField, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        // degree-11
        let numerator_evaluation =
            EccSetRelation::compute_grand_product_numerator(input, relation_parameters);

        // degree-20
        let denominator_evaluation = EccSetRelation::compute_grand_product_denominator::<P, SIZE>(
            input,
            relation_parameters,
        );

        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm_shift();

        // degree-21
        let mut tmp = ((z_perm.to_owned() + lagrange_first) * numerator_evaluation
            - (z_perm_shift.to_owned() + lagrange_last) * denominator_evaluation)
            * scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // Contribution (2)
        tmp = lagrange_last.to_owned() * z_perm_shift * scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn _verify_accumulate<F: PrimeField>(
        _univariate_accumulator: &mut EccSetRelationEvals<F>,
        _input: &crate::prelude::ClaimedEvaluations<F, ECCVMFlavour>,
        _relation_parameters: &crate::prelude::RelationParameters<F>,
        _scaling_factor: &F,
    ) {
        todo!()
    }
}

impl<F: PrimeField> EccSetRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
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
    }
}
