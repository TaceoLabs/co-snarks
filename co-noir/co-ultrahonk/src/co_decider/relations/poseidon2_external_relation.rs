use super::MIN_RAYON_ITER;
use super::{ProverUnivariatesBatch, Relation};
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
use itertools::Itertools as _;
use rayon::prelude::*;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2ExternalRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 7>,
    pub(crate) r1: SharedUnivariate<T, P, 7>,
    pub(crate) r2: SharedUnivariate<T, P, 7>,
    pub(crate) r3: SharedUnivariate<T, P, 7>,
}

#[derive(Clone, Debug)]
pub struct Poseidon2ExternalRelationAccHalfShared<F: PrimeField> {
    pub(crate) r0: Univariate<F, 7>,
    pub(crate) r1: Univariate<F, 7>,
    pub(crate) r2: Univariate<F, 7>,
    pub(crate) r3: Univariate<F, 7>,
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

impl<F: PrimeField> Default for Poseidon2ExternalRelationAccHalfShared<F> {
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

pub struct Poseidon2ExternalRelation {}

#[derive(Default)]
struct IntermediateAcc<F: PrimeField + Default> {
    r0: [F; MAX_PARTIAL_RELATION_LENGTH],
    r1: [F; MAX_PARTIAL_RELATION_LENGTH],
    r2: [F; MAX_PARTIAL_RELATION_LENGTH],
    r3: [F; MAX_PARTIAL_RELATION_LENGTH],
}

impl Poseidon2ExternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 12;
}

impl Poseidon2ExternalRelation {
    pub fn accumulate_small<T, P>(
        driver: &mut T,
        univariate_accumulator: &mut Poseidon2ExternalRelationAccHalfShared<P::ScalarField>,
        input: &ProverUnivariatesBatch<T, P>,
        scaling_factors: &[<P>::ScalarField],
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
        let q_r = input.precomputed.q_r();
        let q_o = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_poseidon2_external = input.precomputed.q_poseidon2_external();

        let party_id = driver.get_party_id();
        macro_rules! add_round_constants {
            ($lhs: expr, $rhs: expr) => {
                izip!($lhs, $rhs).map(|(lhs, rhs)| T::add_with_public(*lhs, *rhs, party_id))
            };
        }
        // add round constants which are loaded in selectors
        let s1 = add_round_constants!(q_l, w_l);
        let s2 = add_round_constants!(q_r, w_r);
        let s3 = add_round_constants!(q_o, w_o);
        let s4 = add_round_constants!(q_4, w_4);

        let s = s1.chain(s2).chain(s3).chain(s4).collect::<Vec<_>>();

        let u = driver.mul_many(&s, &s)?;
        let u = driver.mul_many(&u, &u)?;
        let u = driver.local_mul_vec(&u, &s);

        let u = u.chunks_exact(u.len() / 4).collect_vec();

        let evaluations_len = univariate_accumulator.r0.evaluations.len();
        let mut acc_r0 = [P::ScalarField::default(); MAX_PARTIAL_RELATION_LENGTH];
        let mut acc_r1 = [P::ScalarField::default(); MAX_PARTIAL_RELATION_LENGTH];
        let mut acc_r2 = [P::ScalarField::default(); MAX_PARTIAL_RELATION_LENGTH];
        let mut acc_r3 = [P::ScalarField::default(); MAX_PARTIAL_RELATION_LENGTH];
        acc_r0[..evaluations_len].clone_from_slice(&univariate_accumulator.r0.evaluations);
        acc_r1[..evaluations_len].clone_from_slice(&univariate_accumulator.r1.evaluations);
        acc_r2[..evaluations_len].clone_from_slice(&univariate_accumulator.r2.evaluations);
        acc_r3[..evaluations_len].clone_from_slice(&univariate_accumulator.r3.evaluations);
        izip!(
            u[0],
            u[1],
            u[2],
            u[3],
            q_poseidon2_external,
            scaling_factors,
            w_l_shift,
            w_r_shift,
            w_o_shift,
            w_4_shift
        )
        .enumerate()
        .for_each(
            |(
                idx,
                (
                    u0,
                    u1,
                    u2,
                    u3,
                    q_poseidon2_external,
                    scaling_factor,
                    w_l_shift,
                    w_r_shift,
                    w_o_shift,
                    w_4_shift,
                ),
            )| {
                //// matrix mul v = M_E * u with 14 additions

                let t0 = *u0 + u1;
                let t1 = *u2 + u3;
                let mut t2 = *u1 + u1;
                t2 += t1;
                let mut t3 = *u3 + u3;
                t3 += t0;

                let mut v4 = t1 + t1;
                v4 += v4;
                v4 += t3;
                let mut v2 = t0 + t0;
                v2 += v2;
                v2 += t2;
                let v1 = t3 + v2;
                let v3 = t2 + v4;

                let q_pos_by_scaling = *q_poseidon2_external * scaling_factor;

                let r0 = T::sub_to_half_share(v1, *w_l_shift) * q_pos_by_scaling;
                let r1 = T::sub_to_half_share(v2, *w_r_shift) * q_pos_by_scaling;
                let r2 = T::sub_to_half_share(v3, *w_o_shift) * q_pos_by_scaling;
                let r3 = T::sub_to_half_share(v4, *w_4_shift) * q_pos_by_scaling;

                acc_r0[idx % MAX_PARTIAL_RELATION_LENGTH] += r0;
                acc_r1[idx % MAX_PARTIAL_RELATION_LENGTH] += r1;
                acc_r2[idx % MAX_PARTIAL_RELATION_LENGTH] += r2;
                acc_r3[idx % MAX_PARTIAL_RELATION_LENGTH] += r3;
            },
        );

        univariate_accumulator
            .r0
            .evaluations
            .clone_from_slice(&acc_r0[..evaluations_len]);
        univariate_accumulator
            .r1
            .evaluations
            .clone_from_slice(&acc_r1[..evaluations_len]);
        univariate_accumulator
            .r2
            .evaluations
            .clone_from_slice(&acc_r2[..evaluations_len]);
        univariate_accumulator
            .r3
            .evaluations
            .clone_from_slice(&acc_r3[..evaluations_len]);
        Ok(())
    }

    pub fn accumulate_multithreaded<T, P>(
        driver: &mut T,
        univariate_accumulator: &mut Poseidon2ExternalRelationAccHalfShared<P::ScalarField>,
        input: &ProverUnivariatesBatch<T, P>,
        scaling_factors: &[<P>::ScalarField],
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
        let q_r = input.precomputed.q_r();
        let q_o = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_poseidon2_external = input.precomputed.q_poseidon2_external();

        let party_id = driver.get_party_id();
        macro_rules! add_round_constants {
            ($lhs: expr, $rhs: expr) => {
                ($lhs, $rhs)
                    .into_par_iter()
                    .with_min_len(MIN_RAYON_ITER)
                    .map(|(lhs, rhs)| T::add_with_public(*lhs, *rhs, party_id))
            };
        }
        // add round constants which are loaded in selectors
        let s1 = add_round_constants!(q_l, w_l);
        let s2 = add_round_constants!(q_r, w_r);
        let s3 = add_round_constants!(q_o, w_o);
        let s4 = add_round_constants!(q_4, w_4);

        let s = s1.chain(s2).chain(s3).chain(s4).collect::<Vec<_>>();

        // apply s-box round
        // 0xThemis TODO better mul depth for x^5?
        let u = driver.mul_many(&s, &s)?;
        let u = driver.mul_many(&u, &u)?;
        let u = driver.local_mul_vec(&u, &s);

        let u = u.chunks_exact(u.len() / 4).collect::<Vec<_>>();

        let intermediate_acc = (
            u[0],
            u[1],
            u[2],
            u[3],
            q_poseidon2_external,
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
                    u0,
                    u1,
                    u2,
                    u3,
                    q_poseidon2_external,
                    scaling_factor,
                    w_l_shift,
                    w_r_shift,
                    w_o_shift,
                    w_4_shift,
                )| {
                    //// matrix mul v = M_E * u with 14 additions

                    let t0 = *u0 + u1;
                    let t1 = *u2 + u3;
                    let mut t2 = *u1 + u1;
                    t2 += t1;
                    let mut t3 = *u3 + u3;
                    t3 += t0;

                    let mut v4 = t1 + t1;
                    v4 += v4;
                    v4 += t3;
                    let mut v2 = t0 + t0;
                    v2 += v2;
                    v2 += t2;
                    let v1 = t3 + v2;
                    let v3 = t2 + v4;

                    let q_pos_by_scaling = *q_poseidon2_external * scaling_factor;

                    let r0 = T::sub_to_half_share(v1, *w_l_shift) * q_pos_by_scaling;
                    let r1 = T::sub_to_half_share(v2, *w_r_shift) * q_pos_by_scaling;
                    let r2 = T::sub_to_half_share(v3, *w_o_shift) * q_pos_by_scaling;
                    let r3 = T::sub_to_half_share(v4, *w_4_shift) * q_pos_by_scaling;
                    (r0, r1, r2, r3)
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
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for Poseidon2ExternalRelation
{
    type Acc = Poseidon2ExternalRelationAccHalfShared<P::ScalarField>;

    fn can_skip(entity: &super::ProverUnivariates<T, P>) -> bool {
        entity.precomputed.q_poseidon2_external().is_zero()
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
        batch.add_q_r(entity);
        batch.add_q_o(entity);
        batch.add_q_4(entity);

        batch.add_q_poseidon2_external(entity);
    }
    /**
     * @brief Expression for the poseidon2 external round relation, based on E_i in Section 6 of
     * <https://eprint.iacr.org/2023/323.pdf.>
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
        if input.witness.w_l().len() > 1 << 14 {
            Self::accumulate_multithreaded(driver, univariate_accumulator, input, scaling_factors)?;
        } else {
            Self::accumulate_small(driver, univariate_accumulator, input, scaling_factors)?;
        }
        Ok(())
    }
}
