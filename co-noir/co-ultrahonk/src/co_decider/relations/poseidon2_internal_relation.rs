use super::{ProverUnivariatesBatch, Relation, MIN_RAYON_ITER};
use crate::{
    co_decider::{
        types::{RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Zero};
use co_builder::prelude::HonkCurve;
use co_builder::HonkProofResult;
use itertools::izip;
use mpc_core::gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS;
use num_bigint::BigUint;
use rayon::prelude::*;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2InternalRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 7>,
    pub(crate) r2: SharedUnivariate<T, P, 7>,
    pub(crate) r3: SharedUnivariate<T, P, 7>,
}

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2InternalRelationAccHalfShared<F: PrimeField> {
    pub(crate) r0: Univariate<F, 7>,
    pub(crate) r1: Univariate<F, 7>,
    pub(crate) r2: Univariate<F, 7>,
    pub(crate) r3: Univariate<F, 7>,
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

impl<F: PrimeField> Default for Poseidon2InternalRelationAccHalfShared<F> {
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

#[derive(Default)]
struct IntermediateAcc<F: PrimeField + Default> {
    r0: [F; MAX_PARTIAL_RELATION_LENGTH],
    r1: [F; MAX_PARTIAL_RELATION_LENGTH],
    r2: [F; MAX_PARTIAL_RELATION_LENGTH],
    r3: [F; MAX_PARTIAL_RELATION_LENGTH],
}

impl Poseidon2InternalRelation {
    fn accumulate_multi_threaded<T, P>(
        driver: &mut T,
        univariate_accumulator: &mut Poseidon2InternalRelationAccHalfShared<P::ScalarField>,
        input: &ProverUnivariatesBatch<T, P>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()>
    where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    {
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

        let party_id = driver.get_party_id();
        // add round constants
        let s1 = (q_l, w_l)
            .into_par_iter()
            .with_min_len(MIN_RAYON_ITER)
            .map(|(q_l, w_l)| T::add_with_public(*q_l, *w_l, party_id))
            .collect::<Vec<_>>();
        // apply s-box round
        // FRANCO TODO again can we do something better for x^5?
        let u1 = driver.mul_many(&s1, &s1)?;
        let u1 = driver.mul_many(&u1, &u1)?;
        let u1 = driver.local_mul_vec(&u1, &s1);
        let intermediate_acc = (
            &u1,
            w_r,
            w_o,
            w_4,
            q_poseidon2_internal,
            scaling_factors,
            w_l_shift,
            w_r_shift,
            w_o_shift,
            w_4_shift,
        )
            .into_par_iter()
            .with_min_len(MIN_RAYON_ITER)
            .map(
                |(
                    u1,
                    u2,
                    u3,
                    u4,
                    q_poseidon2_internal,
                    scaling_factor,
                    w_l_shift,
                    w_r_shift,
                    w_o_shift,
                    w_4_shift,
                )| {
                    let sum = T::add_to_half_share(*u1, *u2);
                    let sum = T::add_to_half_share(sum, *u3);
                    let sum = T::add_to_half_share(sum, *u4);
                    let q_pos_by_scaling = *q_poseidon2_internal * scaling_factor;

                    let u1 = *u1 * internal_matrix_diag_0;
                    let u2 = T::mul_with_public_to_half_share(internal_matrix_diag_1, *u2);
                    let u3 = T::mul_with_public_to_half_share(internal_matrix_diag_2, *u3);
                    let u4 = T::mul_with_public_to_half_share(internal_matrix_diag_3, *u4);

                    let mut u1 = T::sub_to_half_share(u1 + sum, *w_l_shift);
                    let mut u2 = T::sub_to_half_share(u2 + sum, *w_r_shift);
                    let mut u3 = T::sub_to_half_share(u3 + sum, *w_o_shift);
                    let mut u4 = T::sub_to_half_share(u4 + sum, *w_4_shift);

                    u1 *= q_pos_by_scaling;
                    u2 *= q_pos_by_scaling;
                    u3 *= q_pos_by_scaling;
                    u4 *= q_pos_by_scaling;
                    (u1, u2, u3, u4)
                },
            )
            .enumerate()
            .fold(
                IntermediateAcc::<P::ScalarField>::default,
                |mut acc, (idx, (r0, r1, r2, r3))| {
                    acc.r0[idx % MAX_PARTIAL_RELATION_LENGTH] += r0;
                    acc.r1[idx % MAX_PARTIAL_RELATION_LENGTH] += r1;
                    acc.r2[idx % MAX_PARTIAL_RELATION_LENGTH] += r2;
                    acc.r3[idx % MAX_PARTIAL_RELATION_LENGTH] += r3;
                    acc
                },
            )
            .reduce(
                IntermediateAcc::<P::ScalarField>::default,
                |mut acc, next| {
                    for (acc, next) in izip!(acc.r0.iter_mut(), next.r0) {
                        *acc += next;
                    }
                    for (acc, next) in izip!(acc.r1.iter_mut(), next.r1) {
                        *acc += next;
                    }
                    for (acc, next) in izip!(acc.r2.iter_mut(), next.r2) {
                        *acc += next;
                    }
                    for (acc, next) in izip!(acc.r3.iter_mut(), next.r3) {
                        *acc += next;
                    }
                    acc
                },
            );

        for (evaluations, new) in izip!(
            univariate_accumulator.r0.evaluations.iter_mut(),
            intermediate_acc.r0
        ) {
            *evaluations += new;
        }

        for (evaluations, new) in izip!(
            univariate_accumulator.r1.evaluations.iter_mut(),
            intermediate_acc.r1
        ) {
            *evaluations += new;
        }

        for (evaluations, new) in izip!(
            univariate_accumulator.r2.evaluations.iter_mut(),
            intermediate_acc.r2
        ) {
            *evaluations += new;
        }

        for (evaluations, new) in izip!(
            univariate_accumulator.r3.evaluations.iter_mut(),
            intermediate_acc.r3
        ) {
            *evaluations += new;
        }
        Ok(())
    }
    fn accumulate_small<T, P>(
        driver: &mut T,
        univariate_accumulator: &mut Poseidon2InternalRelationAccHalfShared<P::ScalarField>,
        input: &ProverUnivariatesBatch<T, P>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()>
    where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    {
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

        // add round constants
        let s1 = T::add_with_public_many(q_l, w_l, driver.get_party_id());

        // apply s-box round
        // FRANCO TODO again can we do something better for x^5?
        let u1 = driver.mul_many(&s1, &s1)?;
        let u1 = driver.mul_many(&u1, &u1)?;
        let u1 = driver.local_mul_vec(&u1, &s1);

        let evaluations_len = univariate_accumulator.r0.evaluations.len();
        let mut intermediate_acc = IntermediateAcc::default();
        intermediate_acc.r0[..evaluations_len]
            .clone_from_slice(&univariate_accumulator.r0.evaluations);
        intermediate_acc.r1[..evaluations_len]
            .clone_from_slice(&univariate_accumulator.r1.evaluations);
        intermediate_acc.r2[..evaluations_len]
            .clone_from_slice(&univariate_accumulator.r2.evaluations);
        intermediate_acc.r3[..evaluations_len]
            .clone_from_slice(&univariate_accumulator.r3.evaluations);
        izip!(
            &u1,
            w_r,
            w_o,
            w_4,
            q_poseidon2_internal,
            scaling_factors,
            w_l_shift,
            w_r_shift,
            w_o_shift,
            w_4_shift,
        )
        .enumerate()
        .for_each(
            |(
                idx,
                (
                    u1,
                    u2,
                    u3,
                    u4,
                    q_poseidon2_internal,
                    scaling_factor,
                    w_l_shift,
                    w_r_shift,
                    w_o_shift,
                    w_4_shift,
                ),
            )| {
                let sum = T::add_to_half_share(*u1, *u2);
                let sum = T::add_to_half_share(sum, *u3);
                let sum = T::add_to_half_share(sum, *u4);
                let q_pos_by_scaling = *q_poseidon2_internal * scaling_factor;

                let u1 = *u1 * internal_matrix_diag_0;
                let u2 = T::mul_with_public_to_half_share(internal_matrix_diag_1, *u2);
                let u3 = T::mul_with_public_to_half_share(internal_matrix_diag_2, *u3);
                let u4 = T::mul_with_public_to_half_share(internal_matrix_diag_3, *u4);

                let mut u1 = T::sub_to_half_share(u1 + sum, *w_l_shift);
                let mut u2 = T::sub_to_half_share(u2 + sum, *w_r_shift);
                let mut u3 = T::sub_to_half_share(u3 + sum, *w_o_shift);
                let mut u4 = T::sub_to_half_share(u4 + sum, *w_4_shift);

                u1 *= q_pos_by_scaling;
                u2 *= q_pos_by_scaling;
                u3 *= q_pos_by_scaling;
                u4 *= q_pos_by_scaling;

                intermediate_acc.r0[idx % MAX_PARTIAL_RELATION_LENGTH] += u1;
                intermediate_acc.r1[idx % MAX_PARTIAL_RELATION_LENGTH] += u2;
                intermediate_acc.r2[idx % MAX_PARTIAL_RELATION_LENGTH] += u3;
                intermediate_acc.r3[idx % MAX_PARTIAL_RELATION_LENGTH] += u4;
            },
        );
        univariate_accumulator
            .r0
            .evaluations
            .clone_from_slice(&intermediate_acc.r0[..evaluations_len]);
        univariate_accumulator
            .r1
            .evaluations
            .clone_from_slice(&intermediate_acc.r1[..evaluations_len]);
        univariate_accumulator
            .r2
            .evaluations
            .clone_from_slice(&intermediate_acc.r2[..evaluations_len]);
        univariate_accumulator
            .r3
            .evaluations
            .clone_from_slice(&intermediate_acc.r3[..evaluations_len]);

        Ok(())
    }
}

impl Poseidon2InternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 3;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for Poseidon2InternalRelation
{
    type Acc = Poseidon2InternalRelationAccHalfShared<P::ScalarField>;

    fn can_skip(entity: &super::ProverUnivariates<T, P>) -> bool {
        entity.precomputed.q_poseidon2_internal().is_zero()
    }

    fn add_entites(
        entity: &super::ProverUnivariates<T, P>,
        batch: &mut ProverUnivariatesBatch<T, P>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_q_l(entity);

        batch.add_q_poseidon2_internal(entity);
    }

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
        if input.witness.w_l().len() > 1 << 14 {
            Self::accumulate_multi_threaded::<T, P>(
                driver,
                univariate_accumulator,
                input,
                scaling_factors,
            )?;
        } else {
            Self::accumulate_small::<T, P>(driver, univariate_accumulator, input, scaling_factors)?;
        }
        Ok(())
    }
}
