use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::decider::univariate::Univariate;
use ark_ff::One;
use ark_ff::{PrimeField, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use num_bigint::BigUint;

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorNonNativeFieldRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 3>,
    pub(crate) r1: Univariate<F, 3>,
    pub(crate) r2: Univariate<F, 3>,
}

impl<F: PrimeField> TranslatorNonNativeFieldRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
        *current_scalar *= challenge;
        self.r2 *= *current_scalar;
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
    }
}

#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct TranslatorNonNativeFieldRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
}

pub(crate) struct TranslatorNonNativeFieldRelation {}

impl TranslatorNonNativeFieldRelation {
    pub(crate) const NUM_RELATIONS: usize = 3;
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorNonNativeFieldRelation {
    type Acc = TranslatorNonNativeFieldRelationAcc<F>;

    type VerifyAcc = TranslatorNonNativeFieldRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>) -> bool {
        input.precomputed.lagrange_even_in_minicircuit().is_zero()
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
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate TranslatorNonNativeFieldRelation");

        const NUM_LIMB_BITS: usize = 68;
        let shift: F = (BigUint::one() << NUM_LIMB_BITS).into();
        let shiftx2: F = (BigUint::one() << (NUM_LIMB_BITS * 2)).into();
        let shiftx3: F = (BigUint::one() << (NUM_LIMB_BITS * 3)).into();
        //TODO FLORIN: make this nicer
        let negative_modulus_limbs: [F; 5] = [
            F::from_str("51007615349848998585")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            F::from_str("187243884991886189399")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            F::from_str("292141664167738113703")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            F::from_str("295147053861416594661")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            F::from_str(
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
        let mut tmp = accumulators_binary_limbs_0_shift.to_owned() * evaluation_input_x_0
            + op
            + p_x_low_limbs.to_owned() * v_0_0
            + p_y_low_limbs.to_owned() * v_1_0
            + z_low_limbs.to_owned() * v_2_0
            + z_low_limbs_shift.to_owned() * v_3_0
            + quotient_low_binary_limbs.to_owned() * negative_modulus_limbs[0]
            - accumulators_binary_limbs_0;

        // the index-1 limb
        tmp += (accumulators_binary_limbs_1_shift.to_owned() * evaluation_input_x_0
            + accumulators_binary_limbs_0_shift.to_owned() * evaluation_input_x_1
            + p_x_low_limbs.to_owned() * v_0_1
            + p_x_low_limbs_shift.to_owned() * v_0_0
            + p_y_low_limbs.to_owned() * v_1_1
            + p_y_low_limbs_shift.to_owned() * v_1_0
            + z_low_limbs.to_owned() * v_2_1
            + z_high_limbs.to_owned() * v_2_0
            + z_low_limbs_shift.to_owned() * v_3_1
            + z_high_limbs_shift.to_owned() * v_3_0
            + quotient_low_binary_limbs.to_owned() * negative_modulus_limbs[1]
            + quotient_low_binary_limbs_shift.to_owned() * negative_modulus_limbs[0]
            - accumulators_binary_limbs_1)
            * shift;
        // clang-format on
        // subtract large value; vanishing shows the desired relation holds on low 136-bit limb
        tmp -= relation_wide_limbs.to_owned() * shiftx2;
        tmp *= lagrange_even_in_minicircuit;
        tmp *= scaling_factor;
        // std::get<0>(accumulators) += tmp;

        // Contribution (2) Computing the 2²⁷² relation over higher 136 bits
        // why declare another temporary?
        // clang-format off
        // the index-2 limb, with a carry from the previous calculation
        tmp = relation_wide_limbs.to_owned()
            + accumulators_binary_limbs_2_shift.to_owned() * evaluation_input_x_0
            + accumulators_binary_limbs_1_shift.to_owned() * evaluation_input_x_1
            + accumulators_binary_limbs_0_shift.to_owned() * evaluation_input_x_2
            + p_x_high_limbs.to_owned() * v_0_0
            + p_x_low_limbs_shift.to_owned() * v_0_1
            + p_x_low_limbs.to_owned() * v_0_2
            + p_y_high_limbs.to_owned() * v_1_0
            + p_y_low_limbs_shift.to_owned() * v_1_1
            + p_y_low_limbs.to_owned() * v_1_2
            + z_high_limbs.to_owned() * v_2_1
            + z_low_limbs.to_owned() * v_2_2
            + z_high_limbs_shift.to_owned() * v_3_1
            + z_low_limbs_shift.to_owned() * v_3_2
            + quotient_high_binary_limbs.to_owned() * negative_modulus_limbs[0]
            + quotient_low_binary_limbs_shift.to_owned() * negative_modulus_limbs[1]
            + quotient_low_binary_limbs.to_owned() * negative_modulus_limbs[2]
            - accumulators_binary_limbs_2;

        // the index-2 limb
        tmp += (accumulators_binary_limbs_3_shift.to_owned() * evaluation_input_x_0
            + accumulators_binary_limbs_2_shift.to_owned() * evaluation_input_x_1
            + accumulators_binary_limbs_1_shift.to_owned() * evaluation_input_x_2
            + accumulators_binary_limbs_0_shift.to_owned() * evaluation_input_x_3
            + p_x_high_limbs_shift.to_owned() * v_0_0
            + p_x_high_limbs.to_owned() * v_0_1
            + p_x_low_limbs_shift.to_owned() * v_0_2
            + p_x_low_limbs.to_owned() * v_0_3
            + p_y_high_limbs_shift.to_owned() * v_1_0
            + p_y_high_limbs.to_owned() * v_1_1
            + p_y_low_limbs_shift.to_owned() * v_1_2
            + p_y_low_limbs.to_owned() * v_1_3
            + z_high_limbs.to_owned() * v_2_2
            + z_low_limbs.to_owned() * v_2_3
            + z_high_limbs_shift.to_owned() * v_3_2
            + z_low_limbs_shift.to_owned() * v_3_3
            + quotient_high_binary_limbs_shift.to_owned() * negative_modulus_limbs[0]
            + quotient_high_binary_limbs.to_owned() * negative_modulus_limbs[1]
            + quotient_low_binary_limbs_shift.to_owned() * negative_modulus_limbs[2]
            + quotient_low_binary_limbs.to_owned() * negative_modulus_limbs[3]
            - accumulators_binary_limbs_3)
            * shift;
        // clang-format on
        // subtract large value; vanishing shows the desired relation holds on high 136-bit limb
        tmp -= relation_wide_limbs_shift.to_owned() * shiftx2;
        tmp *= lagrange_even_in_minicircuit;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        let reconstruct_from_two = |l0: &Univariate<F, SIZE>,
                                    l1: Univariate<F, SIZE>|
         -> Univariate<F, SIZE> { l1 * shift + l0 };

        let reconstruct_from_four =
            |l0: &Univariate<F, SIZE>,
             l1: Univariate<F, SIZE>,
             l2: Univariate<F, SIZE>,
             l3: Univariate<F, SIZE>|
             -> Univariate<F, SIZE> { l1 * shift + l2 * shiftx2 + l3 * shiftx3 + l0 };

        // Reconstructing native versions of values
        let reconstructed_p_x = reconstruct_from_four(
            p_x_low_limbs,
            p_x_low_limbs_shift.to_owned(),
            p_x_high_limbs.to_owned(),
            p_x_high_limbs_shift.to_owned(),
        );
        let reconstructed_p_y = reconstruct_from_four(
            p_y_low_limbs,
            p_y_low_limbs_shift.to_owned(),
            p_y_high_limbs.to_owned(),
            p_y_high_limbs_shift.to_owned(),
        );
        let reconstructed_previous_accumulator = reconstruct_from_four(
            accumulators_binary_limbs_0_shift,
            accumulators_binary_limbs_1_shift.to_owned(),
            accumulators_binary_limbs_2_shift.to_owned(),
            accumulators_binary_limbs_3_shift.to_owned(),
        );
        let reconstructed_current_accumulator = reconstruct_from_four(
            accumulators_binary_limbs_0,
            accumulators_binary_limbs_1.to_owned(),
            accumulators_binary_limbs_2.to_owned(),
            accumulators_binary_limbs_3.to_owned(),
        );
        let reconstructed_z1 = reconstruct_from_two(z_low_limbs, z_high_limbs.to_owned());
        let reconstructed_z2 =
            reconstruct_from_two(z_low_limbs_shift, z_high_limbs_shift.to_owned());
        let reconstructed_quotient = reconstruct_from_four(
            quotient_low_binary_limbs,
            quotient_low_binary_limbs_shift.to_owned(),
            quotient_high_binary_limbs.to_owned(),
            quotient_high_binary_limbs_shift.to_owned(),
        );

        // Contribution (3). Evaluating integer relation over native field
        // clang-format off
        // the native limb index is 4
        tmp = reconstructed_previous_accumulator * evaluation_input_x_4
            + op
            + reconstructed_p_x * v_0_4
            + reconstructed_p_y * v_1_4
            + reconstructed_z1 * v_2_4
            + reconstructed_z2 * v_3_4
            + reconstructed_quotient * negative_modulus_limbs[4]
            - reconstructed_current_accumulator;
        // clang-format on
        tmp *= lagrange_even_in_minicircuit;
        tmp *= scaling_factor;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

 
}
