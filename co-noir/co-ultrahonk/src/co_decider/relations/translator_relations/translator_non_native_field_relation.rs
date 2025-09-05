use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use mpc_net::Network;
use num_bigint::BigUint;
use std::str::FromStr;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorNonNativeFieldRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 3>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
    pub(crate) r2: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default
    for TranslatorNonNativeFieldRelationAcc<T, P>
{
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
            r2: SharedUnivariate::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorNonNativeFieldRelationAcc<T, P> {
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
    }
}

pub(crate) struct TranslatorNonNativeFieldRelation {}

impl TranslatorNonNativeFieldRelation {
    pub(crate) const NUM_RELATIONS: usize = 3;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorNonNativeFieldRelation
{
    type Acc = TranslatorNonNativeFieldRelationAcc<T, P>;
    type VerifyAcc = ();

    fn can_skip(
        _entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
    ) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, TranslatorFlavour>,
    ) {
        batch.add_op(entity);
        batch.add_p_x_low_limbs(entity);
        batch.add_p_y_low_limbs(entity);
        batch.add_p_x_high_limbs(entity);
        batch.add_p_y_high_limbs(entity);
        batch.add_accumulators_binary_limbs_0(entity);
        batch.add_accumulators_binary_limbs_1(entity);
        batch.add_accumulators_binary_limbs_2(entity);
        batch.add_accumulators_binary_limbs_3(entity);
        batch.add_z_low_limbs(entity);
        batch.add_z_high_limbs(entity);
        batch.add_quotient_low_binary_limbs(entity);
        batch.add_quotient_high_binary_limbs(entity);
        batch.add_relation_wide_limbs(entity);
        batch.add_p_x_low_limbs_shift(entity);
        batch.add_p_y_low_limbs_shift(entity);
        batch.add_p_x_high_limbs_shift(entity);
        batch.add_p_y_high_limbs_shift(entity);
        batch.add_accumulators_binary_limbs_0_shift(entity);
        batch.add_accumulators_binary_limbs_1_shift(entity);
        batch.add_accumulators_binary_limbs_2_shift(entity);
        batch.add_accumulators_binary_limbs_3_shift(entity);
        batch.add_z_low_limbs_shift(entity);
        batch.add_z_high_limbs_shift(entity);
        batch.add_quotient_low_binary_limbs_shift(entity);
        batch.add_quotient_high_binary_limbs_shift(entity);
        batch.add_relation_wide_limbs_shift(entity);
        batch.add_lagrange_even_in_minicircuit(entity);
    }

    /**
     * @brief Expression for the computation of Translator accumulator in integers through 68-bit limbs and
     * native field (prime) limb
     * @details This relation is a part of system of relations that enforce a formula in non-native field (base field of
     * bn254 curve Fp (p - modulus of Fp)). We are trying to compute:
     *
     * `current_accumulator = previous_accumulator ⋅ x + op + P.x ⋅ v + P.y ⋅ v² +z1 ⋅ v³ + z2 ⋅ v⁴ mod p`.
     *
     * However, we can only operate in Fr (scalar field of bn254) with
     * modulus r. To emulate arithmetic in Fp we rephrase the equation in integers:
     *
     * `previous_accumulator ⋅ x + op + P.x ⋅ v + P.y ⋅ v² +z1 ⋅ v³ + z2 ⋅ v⁴ - quotient⋅p - current_accumulator = 0`
     *
     * We can't operate over unbounded integers, but since we know the maximum value of each element (we also treat
     * powers of v as new constants constrained to 254 bits) we know that the maximum values of the sum of the positive
     * products is ~2⁵¹⁴, so we only need to make sure that no overflow happens till that bound. We calculate integer
     * logic until the bound 2²⁷²⋅r (which is more than 2⁵¹⁴) by using the representations modulo 2²⁷² (requires limb
     * computation over native scalar field) and r (native scalar field computation).
     *
     * We perform modulo 2²⁷² computations by separating each of values into 4 68-bit limbs (z1 and z2 are just two
     * since they represent the values < 2¹²⁸ and op is just itself). Then we compute the first subrelation (index means
     * sublimb and we use 2²⁷² - p instead of -p):
     * `      previous_accumulator[0]⋅x[0] + op + P.x[0]⋅v[0] + P.y[0]⋅v²[0] + z1[0] ⋅ v³[0] + z2[0] ⋅ v⁴[0]
     *          + quotient[0]⋅(-p)[0] - current_accumulator[0]
     * + 2⁶⁸⋅(previous_accumulator[1]⋅x[0] +      P.x[1]⋅v[0] + P.y[1]⋅v²[0] + z1[1] ⋅ v³[0] + z2[1] ⋅ v⁴[0]
     *   + quotient[1]⋅(-p)[0] +
     *     previous_accumulator[0]⋅x[1] +      P.x[0]⋅v[1] + P.y[0]⋅v²[1] + z1[0] ⋅ v³[1] + z2[0] ⋅ v⁴[1]
     *   + quotient[0]⋅(-p)[1] - current_accumulator[1])
     *  - 2¹³⁶⋅relation_wide_lower_limb
     *    == 0`
     *
     * We use 2 relation wide limbs which are called wide, because they contain the results of products (like you needed
     * EDX:EAX in x86 to hold the product results of two standard 32-bit registers) and because they are constrained to
     * 84 bits instead of 68 or lower by other relations.
     *
     * We show that the evaluation in 2 lower limbs results in relation_wide_lower_limb multiplied by 2¹³⁶. If
     * relation_wide_lower_limb is propertly constrained (this is performed in other relations), then that means that
     * the lower 136 bits of the result are 0. This is the first subrelation.
     *
     * We then use the relation_wide_lower_limb as carry and add it to the next expression, computing the evaluation in
     * higher bits (carry + combinations of limbs (0,2), (1,1), (2,0), (0,3), (2,1), (1,2), (0,3)) and checking that it
     * results in 2¹³⁶⋅relation_wide_higher_limb. This ensures that the logic was sound modulo 2²⁷². This is the second
     * subrelation.
     *
     * Finally, we check that the relation holds in the native field. For this we reconstruct each value, for example:
     * `previous_accumulator_native =        previous_accumulator[0] + 2⁶⁸ ⋅previous_accumulator[1]
     *                                + 2¹³⁶⋅previous_accumulator[2] + 2²⁰⁴⋅previous accumulator[3] mod r`
     *
     * Then the last subrelation is simply checking the integer equation in this native form
     *
     * All of these subrelations are multiplied by lagrange_even_in_minicircuit, which is a polynomial with 1 at each even
     * index less than the size of the mini-circuit (16 times smaller than the final circuit and the only part over
     * which we need to calculate non-permutation relations). All other indices are set to zero. Each EccOpQueue entry
     * (operation) occupies 2 rows in bn254 transcripts. So the Translator VM has a 2-row cycle and we need to
     * switch the checks being performed depending on which row we are at right now. We have half a cycle of
     * accumulation, where we perform this computation, and half a cycle where we just copy accumulator data.
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<N: Network, const SIZE: usize>(
        _net: &N,
        _state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate TranslatorNonNativeFieldRelation");

        const NUM_LIMB_BITS: usize = 68;
        let shift: P::ScalarField = (BigUint::one() << NUM_LIMB_BITS).into();
        let shiftx2: P::ScalarField = (BigUint::one() << (NUM_LIMB_BITS * 2)).into();
        let shiftx3: P::ScalarField = (BigUint::one() << (NUM_LIMB_BITS * 3)).into();
        // TACEO TODO: Probably not the nicest way to do this
        let negative_modulus_limbs: [P::ScalarField; 5] = [
            P::ScalarField::from_str("51007615349848998585")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str("187243884991886189399")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str("292141664167738113703")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str("295147053861416594661")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str(
                "21888242871839275222246405745257275088400417643534245024707370478506390782651",
            )
            .unwrap_or_else(|_| panic!("invalid field element literal")),
        ];
        let evaluation_input_x_0 = relation_parameters.evaluation_input_x[0];
        let evaluation_input_x_1 = relation_parameters.evaluation_input_x[1];
        let evaluation_input_x_2 = relation_parameters.evaluation_input_x[2];
        let evaluation_input_x_3 = relation_parameters.evaluation_input_x[3];
        let evaluation_input_x_4 = relation_parameters.evaluation_input_x[4];
        // for j < 4,  v_i_j is the j-th limb of v^{1+i}
        // v_i_4 is v^{1+i} in the native field
        let v_0_0 = relation_parameters.batching_challenge_v[0];
        let v_0_1 = relation_parameters.batching_challenge_v[1];
        let v_0_2 = relation_parameters.batching_challenge_v[2];
        let v_0_3 = relation_parameters.batching_challenge_v[3];
        let v_0_4 = relation_parameters.batching_challenge_v[4];
        let v_1_0 = relation_parameters.batching_challenge_v[5];
        let v_1_1 = relation_parameters.batching_challenge_v[6];
        let v_1_2 = relation_parameters.batching_challenge_v[7];
        let v_1_3 = relation_parameters.batching_challenge_v[8];
        let v_1_4 = relation_parameters.batching_challenge_v[9];
        let v_2_0 = relation_parameters.batching_challenge_v[10];
        let v_2_1 = relation_parameters.batching_challenge_v[11];
        let v_2_2 = relation_parameters.batching_challenge_v[12];
        let v_2_3 = relation_parameters.batching_challenge_v[13];
        let v_2_4 = relation_parameters.batching_challenge_v[14];
        let v_3_0 = relation_parameters.batching_challenge_v[15];
        let v_3_1 = relation_parameters.batching_challenge_v[16];
        let v_3_2 = relation_parameters.batching_challenge_v[17];
        let v_3_3 = relation_parameters.batching_challenge_v[18];
        let v_3_4 = relation_parameters.batching_challenge_v[19];

        let op = input.witness.op();
        let p_x_low_limbs = input.witness.p_x_low_limbs();
        let p_y_low_limbs = input.witness.p_y_low_limbs();
        let p_x_high_limbs = input.witness.p_x_high_limbs();
        let p_y_high_limbs = input.witness.p_y_high_limbs();
        let accumulators_binary_limbs_0 = input.witness.accumulators_binary_limbs_0();
        let accumulators_binary_limbs_1 = input.witness.accumulators_binary_limbs_1();
        let accumulators_binary_limbs_2 = input.witness.accumulators_binary_limbs_2();
        let accumulators_binary_limbs_3 = input.witness.accumulators_binary_limbs_3();
        let z_low_limbs = input.witness.z_low_limbs();
        let z_high_limbs = input.witness.z_high_limbs();
        let quotient_low_binary_limbs = input.witness.quotient_low_binary_limbs();
        let quotient_high_binary_limbs = input.witness.quotient_high_binary_limbs();
        let p_x_low_limbs_shift = input.shifted_witness.p_x_low_limbs_shift();
        let p_y_low_limbs_shift = input.shifted_witness.p_y_low_limbs_shift();
        let p_x_high_limbs_shift = input.shifted_witness.p_x_high_limbs_shift();
        let p_y_high_limbs_shift = input.shifted_witness.p_y_high_limbs_shift();
        let accumulators_binary_limbs_0_shift =
            input.shifted_witness.accumulators_binary_limbs_0_shift();
        let accumulators_binary_limbs_1_shift =
            input.shifted_witness.accumulators_binary_limbs_1_shift();
        let accumulators_binary_limbs_2_shift =
            input.shifted_witness.accumulators_binary_limbs_2_shift();
        let accumulators_binary_limbs_3_shift =
            input.shifted_witness.accumulators_binary_limbs_3_shift();
        let z_low_limbs_shift = input.shifted_witness.z_low_limbs_shift();
        let z_high_limbs_shift = input.shifted_witness.z_high_limbs_shift();
        let quotient_low_binary_limbs_shift =
            input.shifted_witness.quotient_low_binary_limbs_shift();
        let quotient_high_binary_limbs_shift =
            input.shifted_witness.quotient_high_binary_limbs_shift();
        let relation_wide_limbs = input.witness.relation_wide_limbs();
        let relation_wide_limbs_shift = input.shifted_witness.relation_wide_limbs_shift();
        let lagrange_even_in_minicircuit = input.precomputed.lagrange_even_in_minicircuit();

        // Contribution (1) Computing the mod 2²⁷² relation over lower 136 bits
        // clang-format off
        // the index-0 limb
        let mut tmp = T::scale_many(accumulators_binary_limbs_0_shift, evaluation_input_x_0);
        T::add_assign_many(&mut tmp, op);
        T::add_assign_many(&mut tmp, &T::scale_many(p_x_low_limbs, v_0_0));
        T::add_assign_many(&mut tmp, &T::scale_many(p_y_low_limbs, v_1_0));
        T::add_assign_many(&mut tmp, &T::scale_many(z_low_limbs, v_2_0));
        T::add_assign_many(&mut tmp, &T::scale_many(z_low_limbs_shift, v_3_0));
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(quotient_low_binary_limbs, negative_modulus_limbs[0]),
        );
        T::sub_assign_many(&mut tmp, accumulators_binary_limbs_0);

        // the index-1 limb
        let mut tmp2 = T::scale_many(accumulators_binary_limbs_1_shift, evaluation_input_x_0);
        T::add_assign_many(
            &mut tmp2,
            &T::scale_many(accumulators_binary_limbs_0_shift, evaluation_input_x_1),
        );
        T::add_assign_many(&mut tmp2, &T::scale_many(p_x_low_limbs, v_0_1));
        T::add_assign_many(&mut tmp2, &T::scale_many(p_x_low_limbs_shift, v_0_0));
        T::add_assign_many(&mut tmp2, &T::scale_many(p_y_low_limbs, v_1_1));
        T::add_assign_many(&mut tmp2, &T::scale_many(p_y_low_limbs_shift, v_1_0));
        T::add_assign_many(&mut tmp2, &T::scale_many(z_low_limbs, v_2_1));
        T::add_assign_many(&mut tmp2, &T::scale_many(z_high_limbs, v_2_0));
        T::add_assign_many(&mut tmp2, &T::scale_many(z_low_limbs_shift, v_3_1));
        T::add_assign_many(&mut tmp2, &T::scale_many(z_high_limbs_shift, v_3_0));
        T::add_assign_many(
            &mut tmp2,
            &T::scale_many(quotient_low_binary_limbs, negative_modulus_limbs[1]),
        );
        T::add_assign_many(
            &mut tmp2,
            &T::scale_many(quotient_low_binary_limbs_shift, negative_modulus_limbs[0]),
        );
        T::sub_assign_many(&mut tmp2, accumulators_binary_limbs_1);
        T::scale_many_in_place(&mut tmp2, shift);
        T::add_assign_many(&mut tmp, &tmp2);
        // clang-format on
        // subtract large value; vanishing shows the desired relation holds on low 136-bit limb
        T::sub_assign_many(&mut tmp, &T::scale_many(relation_wide_limbs, shiftx2));
        T::mul_assign_with_public_many(&mut tmp, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        // Contribution (2) Computing the 2²⁷² relation over higher 136 bits
        // why declare another temporary?
        // clang-format off
        // the index-2 limb, with a carry from the previous calculation
        tmp = relation_wide_limbs.to_owned();
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(accumulators_binary_limbs_2_shift, evaluation_input_x_0),
        );
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(accumulators_binary_limbs_1_shift, evaluation_input_x_1),
        );
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(accumulators_binary_limbs_0_shift, evaluation_input_x_2),
        );
        T::add_assign_many(&mut tmp, &T::scale_many(p_x_high_limbs, v_0_0));
        T::add_assign_many(&mut tmp, &T::scale_many(p_x_low_limbs_shift, v_0_1));
        T::add_assign_many(&mut tmp, &T::scale_many(p_x_low_limbs, v_0_2));
        T::add_assign_many(&mut tmp, &T::scale_many(p_y_high_limbs, v_1_0));
        T::add_assign_many(&mut tmp, &T::scale_many(p_y_low_limbs_shift, v_1_1));
        T::add_assign_many(&mut tmp, &T::scale_many(p_y_low_limbs, v_1_2));
        T::add_assign_many(&mut tmp, &T::scale_many(z_high_limbs, v_2_1));
        T::add_assign_many(&mut tmp, &T::scale_many(z_low_limbs, v_2_2));
        T::add_assign_many(&mut tmp, &T::scale_many(z_high_limbs_shift, v_3_1));
        T::add_assign_many(&mut tmp, &T::scale_many(z_low_limbs_shift, v_3_2));
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(quotient_high_binary_limbs, negative_modulus_limbs[0]),
        );
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(quotient_low_binary_limbs_shift, negative_modulus_limbs[1]),
        );
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(quotient_low_binary_limbs, negative_modulus_limbs[2]),
        );
        T::sub_assign_many(&mut tmp, accumulators_binary_limbs_2);

        // the index-2 limb
        let mut tmp3 = T::scale_many(accumulators_binary_limbs_3_shift, evaluation_input_x_0);
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(accumulators_binary_limbs_2_shift, evaluation_input_x_1),
        );
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(accumulators_binary_limbs_1_shift, evaluation_input_x_2),
        );
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(accumulators_binary_limbs_0_shift, evaluation_input_x_3),
        );
        T::add_assign_many(&mut tmp3, &T::scale_many(p_x_high_limbs_shift, v_0_0));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_x_high_limbs, v_0_1));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_x_low_limbs_shift, v_0_2));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_x_low_limbs, v_0_3));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_y_high_limbs_shift, v_1_0));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_y_high_limbs, v_1_1));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_y_low_limbs_shift, v_1_2));
        T::add_assign_many(&mut tmp3, &T::scale_many(p_y_low_limbs, v_1_3));
        T::add_assign_many(&mut tmp3, &T::scale_many(z_high_limbs, v_2_2));
        T::add_assign_many(&mut tmp3, &T::scale_many(z_low_limbs, v_2_3));
        T::add_assign_many(&mut tmp3, &T::scale_many(z_high_limbs_shift, v_3_2));
        T::add_assign_many(&mut tmp3, &T::scale_many(z_low_limbs_shift, v_3_3));
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(quotient_high_binary_limbs_shift, negative_modulus_limbs[0]),
        );
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(quotient_high_binary_limbs, negative_modulus_limbs[1]),
        );
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(quotient_low_binary_limbs_shift, negative_modulus_limbs[2]),
        );
        T::add_assign_many(
            &mut tmp3,
            &T::scale_many(quotient_low_binary_limbs, negative_modulus_limbs[3]),
        );
        T::sub_assign_many(&mut tmp3, accumulators_binary_limbs_3);
        T::scale_many_in_place(&mut tmp3, shift);
        T::add_assign_many(&mut tmp, &tmp3);
        // clang-format on
        // subtract large value; vanishing shows the desired relation holds on high 136-bit limb
        T::sub_assign_many(&mut tmp, &T::scale_many(relation_wide_limbs_shift, shiftx2));
        T::mul_assign_with_public_many(&mut tmp, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        let reconstruct_from_two =
            |l0: &[T::ArithmeticShare], l1: &[T::ArithmeticShare]| -> Vec<T::ArithmeticShare> {
                T::add_many(&T::scale_many(l1, shift), l0)
            };

        let reconstruct_from_four = |l0: &[T::ArithmeticShare],
                                     l1: &[T::ArithmeticShare],
                                     l2: &[T::ArithmeticShare],
                                     l3: &[T::ArithmeticShare]|
         -> Vec<T::ArithmeticShare> {
            T::add_many(
                &T::add_many(&T::scale_many(l1, shift), &T::scale_many(l2, shiftx2)),
                &T::add_many(&T::scale_many(l3, shiftx3), l0),
            )
        };

        // Reconstructing native versions of values
        let reconstructed_p_x = reconstruct_from_four(
            p_x_low_limbs,
            p_x_low_limbs_shift,
            p_x_high_limbs,
            p_x_high_limbs_shift,
        );
        let reconstructed_p_y = reconstruct_from_four(
            p_y_low_limbs,
            p_y_low_limbs_shift,
            p_y_high_limbs,
            p_y_high_limbs_shift,
        );
        let reconstructed_previous_accumulator = reconstruct_from_four(
            accumulators_binary_limbs_0_shift,
            accumulators_binary_limbs_1_shift,
            accumulators_binary_limbs_2_shift,
            accumulators_binary_limbs_3_shift,
        );
        let reconstructed_current_accumulator = reconstruct_from_four(
            accumulators_binary_limbs_0,
            accumulators_binary_limbs_1,
            accumulators_binary_limbs_2,
            accumulators_binary_limbs_3,
        );
        let reconstructed_z1 = reconstruct_from_two(z_low_limbs, z_high_limbs);
        let reconstructed_z2 = reconstruct_from_two(z_low_limbs_shift, z_high_limbs_shift);
        let reconstructed_quotient = reconstruct_from_four(
            quotient_low_binary_limbs,
            quotient_low_binary_limbs_shift,
            quotient_high_binary_limbs,
            quotient_high_binary_limbs_shift,
        );

        // Contribution (3). Evaluating integer relation over native field
        // clang-format off
        // the native limb index is 4
        let mut tmp = T::scale_many(&reconstructed_previous_accumulator, evaluation_input_x_4);
        T::add_assign_many(&mut tmp, op);
        T::add_assign_many(&mut tmp, &T::scale_many(&reconstructed_p_x, v_0_4));
        T::add_assign_many(&mut tmp, &T::scale_many(&reconstructed_p_y, v_1_4));
        T::add_assign_many(&mut tmp, &T::scale_many(&reconstructed_z1, v_2_4));
        T::add_assign_many(&mut tmp, &T::scale_many(&reconstructed_z2, v_3_4));
        T::add_assign_many(
            &mut tmp,
            &T::scale_many(&reconstructed_quotient, negative_modulus_limbs[4]),
        );
        T::sub_assign_many(&mut tmp, &reconstructed_current_accumulator);
        // clang-format on

        T::mul_assign_with_public_many(&mut tmp, lagrange_even_in_minicircuit);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);
        fold_accumulator!(univariate_accumulator.r2, tmp, SIZE);

        Ok(())
    }
}
