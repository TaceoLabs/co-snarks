use super::{ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{
        relations::fold_accumulator,
        types::{RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use co_builder::prelude::HonkCurve;
use co_builder::HonkProofResult;
use itertools::Itertools as _;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2ExternalRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 7>,
    pub(crate) r2: SharedUnivariate<T, P, 7>,
    pub(crate) r3: SharedUnivariate<T, P, 7>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for Poseidon2ExternalRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Poseidon2ExternalRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == Poseidon2ExternalRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
        self.r2.scale_inplace(elements[2]);
        self.r3.scale_inplace(elements[3]);
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
    }
}

pub(crate) struct Poseidon2ExternalRelation {}

impl Poseidon2ExternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 12;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for Poseidon2ExternalRelation
{
    type Acc = Poseidon2ExternalRelationAcc<T, P>;

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
    fn accumulate(
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
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

        let id = driver.get_party_id();
        // add round constants which are loaded in selectors
        let s1 = T::add_with_public_many(q_l, w_l, id);
        let s2 = T::add_with_public_many(q_r, w_r, id);
        let s3 = T::add_with_public_many(q_o, w_o, id);
        let s4 = T::add_with_public_many(q_4, w_4, id);

        let mut s = Vec::with_capacity(s1.len() + s2.len() + s3.len() + s4.len());
        s.extend(s1);
        s.extend(s2);
        s.extend(s3);
        s.extend(s4);
        // apply s-box round
        // FRANCO TODO better mul depth for x^5?
        let u = driver.mul_many(&s, &s)?;
        let u = driver.mul_many(&u, &u)?;
        let u = driver.mul_many(&u, &s)?;

        let u = u.chunks_exact(u.len() / 4).collect_vec();
        // matrix mul v = M_E * u with 14 additions
        let t0 = T::add_many(u[0], u[1]); // u_1 + u_2
        let t1 = T::add_many(u[2], u[3]); // u_3 + u_4
        let mut t2 = T::add_many(u[1], u[1]); // 2u_2
        T::add_assign_many(&mut t2, &t1); // 2u_2 + u_3 + u_4
        let mut t3 = T::add_many(u[3], u[3]); // 2u_4
        T::add_assign_many(&mut t3, &t0); // u_1 + u_2 + 2u_4

        let v4 = T::add_many(&t1, &t1);
        let mut v4 = T::add_many(&v4, &v4);
        T::add_assign_many(&mut v4, &t3); // u_1 + u_2 + 4u_3 + 6u_4
        let v2 = T::add_many(&t0, &t0);
        let mut v2 = T::add_many(&v2, &v2);
        T::add_assign_many(&mut v2, &t2); // 4u_1 + 6u_2 + u_3 + u_4
        let v1 = T::add_many(&t3, &v2); // 5u_1 + 7u_2 + u_3 + 3u_4
        let v3 = T::add_many(&t2, &v4); // u_1 + 3u_2 + 5u_3 + 7u_4

        let q_pos_by_scaling = q_poseidon2_external
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| *a * *b)
            .collect_vec();
        let mut tmp = T::sub_many(&v1, w_l_shift);
        T::mul_assign_with_public_many(&mut tmp, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r0, tmp);

        ///////////////////////////////////////////////////////////////////////

        let mut tmp = T::sub_many(&v2, w_r_shift);
        T::mul_assign_with_public_many(&mut tmp, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r1, tmp);

        ///////////////////////////////////////////////////////////////////////
        let mut tmp = T::sub_many(&v3, w_o_shift);
        T::mul_assign_with_public_many(&mut tmp, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r2, tmp);

        ///////////////////////////////////////////////////////////////////////
        let mut tmp = T::sub_many(&v4, w_4_shift);
        T::mul_assign_with_public_many(&mut tmp, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r3, tmp);
        Ok(())
    }
}
