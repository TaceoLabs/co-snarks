use super::{fold_accumulator, ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{
        types::{RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use co_builder::prelude::HonkCurve;
use co_builder::HonkProofResult;
use itertools::Itertools as _;
use mpc_core::gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS;
use num_bigint::BigUint;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2InternalRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 7>,
    pub(crate) r2: SharedUnivariate<T, P, 7>,
    pub(crate) r3: SharedUnivariate<T, P, 7>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for Poseidon2InternalRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Poseidon2InternalRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == Poseidon2InternalRelation::NUM_RELATIONS);
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

pub(crate) struct Poseidon2InternalRelation {}

impl Poseidon2InternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 3;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for Poseidon2InternalRelation
{
    type Acc = Poseidon2InternalRelationAcc<T, P>;

    /**
     * @brief Expression for the poseidon2 internal round relation, based on I_i in Section 6 of
     * https://eprint.iacr.org/2023/323.pdf.
     * @details This relation is defined as C(in(X)...) :=
     * q_poseidon2_internal * ( (v1 - w_1_shift) + \alpha * (v2 - w_2_shift) +
     * \alpha^2 * (v3 - w_3_shift) + \alpha^3 * (v4 - w_4_shift) ) = 0 where:
     *      u1 := (w_1 + q_1)^5
     *      sum := u1 + w_2 + w_3 + w_4
     *      v1 := u1 * D1 + sum
     *      v2 := w_2 * D2 + sum
     *      v3 := w_3 * D3 + sum
     *      v4 := w_4 * D4 + sum
     *      Di is the ith internal diagonal value - 1 of the internal matrix M_I
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
        scaling_factors: &[P::ScalarField],
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
        let q_poseidon2_internal = input.precomputed.q_poseidon2_internal();

        if w_l.is_empty() {
            return Ok(());
        }
        // add round constants
        let s1 = T::add_with_public_many(q_l, w_l, driver.get_party_id());

        // apply s-box round
        // FRANCO TODO again can we do something better for x^5?
        let u1 = driver.mul_many(&s1, &s1)?;
        let u1 = driver.mul_many(&u1, &u1)?;
        let mut u1 = driver.mul_many(&u1, &s1)?;

        let mut u2 = w_r.to_owned();
        let mut u3 = w_o.to_owned();
        let mut u4 = w_4.to_owned();

        // matrix mul with v = M_I * u 4 muls and 7 additions
        let mut sum = T::add_many(&u1, &u2);
        T::add_assign_many(&mut sum, &u3);
        T::add_assign_many(&mut sum, &u4);

        let q_pos_by_scaling = q_poseidon2_internal
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| *a * *b)
            .collect_vec();

        // TACEO TODO this poseidon instance is very hardcoded to the bn254 curve
        let internal_matrix_diag_0 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[0],
        ));
        let internal_matrix_diag_1 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[1],
        ));
        let internal_matrix_diag_2 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[2],
        ));
        let internal_matrix_diag_3 = P::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[3],
        ));

        T::scale_many_in_place(&mut u1, internal_matrix_diag_0);
        T::add_assign_many(&mut u1, &sum);
        T::sub_assign_many(&mut u1, w_l_shift);
        T::mul_assign_with_public_many(&mut u1, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r0, u1);

        ///////////////////////////////////////////////////////////////////////
        T::scale_many_in_place(&mut u2, internal_matrix_diag_1);
        T::add_assign_many(&mut u2, &sum);
        T::sub_assign_many(&mut u2, w_r_shift);
        T::mul_assign_with_public_many(&mut u2, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r1, u2);

        ///////////////////////////////////////////////////////////////////////

        T::scale_many_in_place(&mut u3, internal_matrix_diag_2);
        T::add_assign_many(&mut u3, &sum);
        T::sub_assign_many(&mut u3, w_o_shift);
        T::mul_assign_with_public_many(&mut u3, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r2, u3);

        ///////////////////////////////////////////////////////////////////////

        T::scale_many_in_place(&mut u4, internal_matrix_diag_3);
        T::add_assign_many(&mut u4, &sum);
        T::sub_assign_many(&mut u4, w_4_shift);
        T::mul_assign_with_public_many(&mut u4, &q_pos_by_scaling);

        fold_accumulator!(univariate_accumulator.r3, u4);

        ///////////////////////////////////////////////////////////////////////
        Ok(())
    }
}
