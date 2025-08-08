use super::Relation;
use crate::decider::types::ProverUnivariatesSized;
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

#[cfg(not(feature = "protogalaxy"))]
#[derive(Clone, Debug, Default)]
pub(crate) struct UltraPermutationRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 3>,
}

#[cfg(feature = "protogalaxy")]
#[derive(Clone, Debug, Default)]
pub(crate) struct UltraPermutationRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 11>,
    pub(crate) r1: Univariate<F, 3>,
}

impl<F: PrimeField> UltraPermutationRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == UltraPermutationRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
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

    pub(crate) fn extend_and_batch_univariates_2<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        running_challenge: &[Univariate<F, SIZE>],
    ) {
        self.r0
            .extend_and_batch_univariates_2(result, &running_challenge[0]);

        self.r1
            .extend_and_batch_univariates_2(result, &running_challenge[1]);
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UltraPermutationRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

impl<F: PrimeField> UltraPermutationRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == UltraPermutationRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
    }

    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut F,
        linearly_dependent_contribution: &mut F,
        running_challenge: &[F],
    ) {
        assert!(running_challenge.len() == UltraPermutationRelation::NUM_RELATIONS);

        // TODO CESAR: No dependent contributions
        *linearly_independent_contribution +=
            self.r0 * running_challenge[0] + self.r1 * running_challenge[1];
    }
}

pub(crate) struct UltraPermutationRelation {}

impl UltraPermutationRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
}

impl<F: PrimeField, L: PlainProverFlavour> Relation<F, L> for UltraPermutationRelation {
    type Acc = UltraPermutationRelationAcc<F>;
    type VerifyAcc = UltraPermutationRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool {
        <Self as Relation<F, L>>::check_skippable();
        // If z_perm == z_perm_shift, this implies that none of the wire values for the present input are involved in
        // non-trivial copy constraints.
        (input.witness.z_perm().to_owned() - input.shifted_witness.z_perm()).is_zero()
    }

    /**
     * @brief Compute contribution of the permutation relation for a given edge (internal function)
     *
     * @details This relation confirms faithful calculation of the grand
     * product polynomial \f$ Z_{\text{perm}}\f$.
     * In Sumcheck Prover Round, this method adds to accumulators evaluations of subrelations at the point
     * \f$(u_0,\ldots, u_{i-1}, k, \vec\ell)\f$ for \f$ k=0,\ldots, D\f$, where \f$ \vec \ell\f$ is a point  on the
     * Boolean hypercube \f$\{0,1\}^{d-1-i}\f$ and \f$ D \f$ is specified by the calling class. It does so by taking as
     * input an array of Prover Polynomials partially evaluated at the points \f$(u_0,\ldots, u_{i-1}, k, \vec\ell)\f$ and
     * computing point-wise evaluations of the sub-relations. \todo Protogalaxy Accumulation
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate UltraPermutationRelation");

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let id_1 = input.precomputed.id_1();
        let id_2 = input.precomputed.id_2();
        let id_3 = input.precomputed.id_3();
        let id_4 = input.precomputed.id_4();
        let sigma_1 = input.precomputed.sigma_1();
        let sigma_2 = input.precomputed.sigma_2();
        let sigma_3 = input.precomputed.sigma_3();
        let sigma_4 = input.precomputed.sigma_4();

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        let w_1_plus_gamma = w_1.to_owned() + gamma;
        let w_2_plus_gamma = w_2.to_owned() + gamma;
        let w_3_plus_gamma = w_3.to_owned() + gamma;
        let w_4_plus_gamma = w_4.to_owned() + gamma;

        let mut t1 = id_1.to_owned() * beta + &w_1_plus_gamma;
        t1 *= scaling_factor;
        let t2 = id_2.to_owned() * beta + &w_2_plus_gamma;
        let t3 = id_3.to_owned() * beta + &w_3_plus_gamma;
        let t4 = id_4.to_owned() * beta + &w_4_plus_gamma;
        t1 *= t2;
        t1 *= t3;
        t1 *= t4;
        let numerator = t1;

        let mut t5 = sigma_1.to_owned() * beta + w_1_plus_gamma;
        t5 *= scaling_factor;
        let t6 = sigma_2.to_owned() * beta + w_2_plus_gamma;
        let t7 = sigma_3.to_owned() * beta + w_3_plus_gamma;
        let t8 = sigma_4.to_owned() * beta + w_4_plus_gamma;
        t5 *= t6;
        t5 *= t7;
        t5 *= t8;
        let denominator = t5;

        let public_input_term = lagrange_last.to_owned() * public_input_delta + z_perm_shift;

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let tmp =
            ((z_perm.to_owned() + lagrange_first) * numerator) - (public_input_term * denominator);

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = (lagrange_last.to_owned() * z_perm_shift) * scaling_factor;

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn accumulate_with_extended_parameters<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate UltraPermutationRelation");

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let id_1 = input.precomputed.id_1();
        let id_2 = input.precomputed.id_2();
        let id_3 = input.precomputed.id_3();
        let id_4 = input.precomputed.id_4();
        let sigma_1 = input.precomputed.sigma_1();
        let sigma_2 = input.precomputed.sigma_2();
        let sigma_3 = input.precomputed.sigma_3();
        let sigma_4 = input.precomputed.sigma_4();

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        let w_1_plus_gamma = w_1.to_owned() + gamma;
        let w_2_plus_gamma = w_2.to_owned() + gamma;
        let w_3_plus_gamma = w_3.to_owned() + gamma;
        let w_4_plus_gamma = w_4.to_owned() + gamma;

        let mut t1 = id_1.to_owned() * beta + &w_1_plus_gamma;
        t1 *= scaling_factor;
        let t2 = id_2.to_owned() * beta + &w_2_plus_gamma;
        let t3 = id_3.to_owned() * beta + &w_3_plus_gamma;
        let t4 = id_4.to_owned() * beta + &w_4_plus_gamma;
        t1 *= t2;
        t1 *= t3;
        t1 *= t4;
        let numerator = t1;

        let mut t5 = sigma_1.to_owned() * beta + w_1_plus_gamma;
        t5 *= scaling_factor;
        let t6 = sigma_2.to_owned() * beta + w_2_plus_gamma;
        let t7 = sigma_3.to_owned() * beta + w_3_plus_gamma;
        let t8 = sigma_4.to_owned() * beta + w_4_plus_gamma;
        t5 *= t6;
        t5 *= t7;
        t5 *= t8;
        let denominator = t5;

        let public_input_term = lagrange_last.to_owned() * public_input_delta + z_perm_shift;

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let tmp =
            ((z_perm.to_owned() + lagrange_first) * numerator) - (public_input_term * denominator);

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = (lagrange_last.to_owned() * z_perm_shift) * scaling_factor;

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let id_1 = input.precomputed.id_1();
        let id_2 = input.precomputed.id_2();
        let id_3 = input.precomputed.id_3();
        let id_4 = input.precomputed.id_4();
        let sigma_1 = input.precomputed.sigma_1();
        let sigma_2 = input.precomputed.sigma_2();
        let sigma_3 = input.precomputed.sigma_3();
        let sigma_4 = input.precomputed.sigma_4();

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        let w_1_plus_gamma = w_1.to_owned() + gamma;
        let w_2_plus_gamma = w_2.to_owned() + gamma;
        let w_3_plus_gamma = w_3.to_owned() + gamma;
        let w_4_plus_gamma = w_4.to_owned() + gamma;

        let mut t1 = id_1.to_owned() * beta + w_1_plus_gamma;
        t1 *= scaling_factor;
        let t2 = id_2.to_owned() * beta + w_2_plus_gamma;
        let t3 = id_3.to_owned() * beta + w_3_plus_gamma;
        let t4 = id_4.to_owned() * beta + w_4_plus_gamma;
        t1 *= t2;
        t1 *= t3;
        t1 *= t4;
        let numerator = t1;

        let mut t5 = sigma_1.to_owned() * beta + w_1_plus_gamma;
        t5 *= scaling_factor;
        let t6 = sigma_2.to_owned() * beta + w_2_plus_gamma;
        let t7 = sigma_3.to_owned() * beta + w_3_plus_gamma;
        let t8 = sigma_4.to_owned() * beta + w_4_plus_gamma;
        t5 *= t6;
        t5 *= t7;
        t5 *= t8;
        let denominator = t5;

        let public_input_term = lagrange_last.to_owned() * public_input_delta + z_perm_shift;

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let tmp =
            ((z_perm.to_owned() + lagrange_first) * numerator) - (public_input_term * denominator);

        univariate_accumulator.r0 += tmp;

        ///////////////////////////////////////////////////////////////////////

        let tmp = (lagrange_last.to_owned() * z_perm_shift) * scaling_factor;

        univariate_accumulator.r1 += tmp;
    }
}
