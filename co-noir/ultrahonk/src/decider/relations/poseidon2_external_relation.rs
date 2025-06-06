use super::Relation;
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
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct Poseidon2ExternalRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 7>,
    pub(crate) r1: Univariate<F, 7>,
    pub(crate) r2: Univariate<F, 7>,
    pub(crate) r3: Univariate<F, 7>,
}

impl<F: PrimeField> Poseidon2ExternalRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == Poseidon2ExternalRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
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
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Poseidon2ExternalRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
}

impl<F: PrimeField> Poseidon2ExternalRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == Poseidon2ExternalRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
    }
}

pub(crate) struct Poseidon2ExternalRelation {}

impl Poseidon2ExternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<F: PrimeField, L: PlainProverFlavour> Relation<F, L> for Poseidon2ExternalRelation {
    type Acc = Poseidon2ExternalRelationAcc<F>;
    type VerifyAcc = Poseidon2ExternalRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool {
        <Self as Relation<F, L>>::check_skippable();
        input.precomputed.q_poseidon2_external().is_zero()
    }

    /**
     * @brief Expression for the poseidon2 external round relation, based on E_i in Section 6 of
     * https://eprint.iacr.org/2023/323.pdf.
     * @details This relation is defined as C(in(X)...) :=
     * q_poseidon2_external * ( (v1 - w_1_shift) + \alpha * (v2 - w_2_shift) +
     * \alpha^2 * (v3 - w_3_shift) + \alpha^3 * (v4 - w_4_shift) ) = 0 where:
     *      u1 := (w_1 + q_1)^5
     *      u2 := (w_2 + q_2)^5
     *      u3 := (w_3 + q_3)^5
     *      u4 := (w_4 + q_4)^5
     *      t0 := u1 + u2                                           (1, 1, 0, 0)
     *      t1 := u3 + u4                                           (0, 0, 1, 1)
     *      t2 := 2 * u2 + t1 = 2 * u2 + u3 + u4                    (0, 2, 1, 1)
     *      t3 := 2 * u4 + t0 = u1 + u2 + 2 * u4                    (1, 1, 0, 2)
     *      v4 := 4 * t1 + t3 = u1 + u2 + 4 * u3 + 6 * u4           (1, 1, 4, 6)
     *      v2 := 4 * t0 + t2 = 4 * u1 + 6 * u2 + u3 + u4           (4, 6, 1, 1)
     *      v1 := t3 + v2 = 5 * u1 + 7 * u2 + 1 * u3 + 3 * u4       (5, 7, 1, 3)
     *      v3 := t2 + v4                                           (1, 3, 5, 7)
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate Poseidon2ExternalRelation");

        let w_l = input.witness.w_l();
        let w_r = input.witness.w_r();
        let w_o = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_l_shift = input.shifted_witness.w_l();
        let w_r_shift = input.shifted_witness.w_r();
        let w_o_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();
        let q_l = input.precomputed.q_l();
        let q_r = input.precomputed.q_r();
        let q_o = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_poseidon2_external = input.precomputed.q_poseidon2_external();

        // add round constants which are loaded in selectors
        let s1 = w_l.to_owned() + q_l;
        let s2 = w_r.to_owned() + q_r;
        let s3 = w_o.to_owned() + q_o;
        let s4 = w_4.to_owned() + q_4;

        // apply s-box round
        let mut u1 = s1.to_owned().sqr();
        u1 = u1.sqr();
        u1 *= s1;
        let mut u2 = s2.to_owned().sqr();
        u2 = u2.sqr();
        u2 *= s2;
        let mut u3 = s3.to_owned().sqr();
        u3 = u3.sqr();
        u3 *= s3;
        let mut u4 = s4.to_owned().sqr();
        u4 = u4.sqr();
        u4 *= s4;

        // matrix mul v = M_E * u with 14 additions
        let t0 = u1 + &u2; // u_1 + u_2
        let t1 = u3 + &u4; // u_3 + u_4
        let mut t2 = u2.double(); // 2u_2
        t2 += &t1; // 2u_2 + u_3 + u_4
        let mut t3 = u4.double(); // 2u_4
        t3 += &t0; // u_1 + u_2 + 2u_4
        let mut v4 = t1.double();
        v4.double_in_place();
        v4 += &t3; // u_1 + u_2 + 4u_3 + 6u_4
        let mut v2 = t0.double();
        v2.double_in_place();
        v2 += &t2; // 4u_1 + 6u_2 + u_3 + u_4
        let v1 = t3 + &v2; // 5u_1 + 7u_2 + u_3 + 3u_4
        let v3 = t2 + &v4; // u_1 + 3u_2 + 5u_3 + 7u_4

        let q_pos_by_scaling = q_poseidon2_external.to_owned() * scaling_factor;
        let tmp = (v1 - w_l_shift) * &q_pos_by_scaling;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = (v2 - w_r_shift) * &q_pos_by_scaling;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = (v3 - w_o_shift) * &q_pos_by_scaling;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = (v4 - w_4_shift) * q_pos_by_scaling;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        _relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate Poseidon2ExternalRelation");

        let w_l = input.witness.w_l();
        let w_r = input.witness.w_r();
        let w_o = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_l_shift = input.shifted_witness.w_l();
        let w_r_shift = input.shifted_witness.w_r();
        let w_o_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();
        let q_l = input.precomputed.q_l();
        let q_r = input.precomputed.q_r();
        let q_o = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_poseidon2_external = input.precomputed.q_poseidon2_external();

        // add round constants which are loaded in selectors
        let s1 = w_l.to_owned() + q_l;
        let s2 = w_r.to_owned() + q_r;
        let s3 = w_o.to_owned() + q_o;
        let s4 = w_4.to_owned() + q_4;

        // apply s-box round
        let mut u1 = s1.to_owned().square();
        u1 = u1.square();
        u1 *= s1;
        let mut u2 = s2.to_owned().square();
        u2 = u2.square();
        u2 *= s2;
        let mut u3 = s3.to_owned().square();
        u3 = u3.square();
        u3 *= s3;
        let mut u4 = s4.to_owned().square();
        u4 = u4.square();
        u4 *= s4;

        // matrix mul v = M_E * u with 14 additions
        let t0 = u1 + u2; // u_1 + u_2
        let t1 = u3 + u4; // u_3 + u_4
        let mut t2 = u2.double(); // 2u_2
        t2 += &t1; // 2u_2 + u_3 + u_4
        let mut t3 = u4.double(); // 2u_4
        t3 += &t0; // u_1 + u_2 + 2u_4
        let mut v4 = t1.double();
        v4.double_in_place();
        v4 += &t3; // u_1 + u_2 + 4u_3 + 6u_4
        let mut v2 = t0.double();
        v2.double_in_place();
        v2 += &t2; // 4u_1 + 6u_2 + u_3 + u_4
        let v1 = t3 + v2; // 5u_1 + 7u_2 + u_3 + 3u_4
        let v3 = t2 + v4; // u_1 + 3u_2 + 5u_3 + 7u_4

        let q_pos_by_scaling = q_poseidon2_external.to_owned() * scaling_factor;
        let tmp = (v1 - w_l_shift) * q_pos_by_scaling;
        univariate_accumulator.r0 += tmp;

        ///////////////////////////////////////////////////////////////////////

        let tmp = (v2 - w_r_shift) * q_pos_by_scaling;
        univariate_accumulator.r1 += tmp;

        ///////////////////////////////////////////////////////////////////////

        let tmp = (v3 - w_o_shift) * q_pos_by_scaling;
        univariate_accumulator.r2 += tmp;

        ///////////////////////////////////////////////////////////////////////

        let tmp = (v4 - w_4_shift) * q_pos_by_scaling;
        univariate_accumulator.r3 += tmp;
    }
}
