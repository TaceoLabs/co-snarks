use super::{
    relation_utils::{self},
    MIN_RAYON_ITER,
};
use itertools::izip;

use super::{ProverUnivariatesBatch, Relation};
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
use rayon::prelude::*;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct UltraPermutationRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
}

#[derive(Clone, Debug)]
pub(crate) struct UltraPermutationRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: Univariate<P::ScalarField, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for UltraPermutationRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default
    for UltraPermutationRelationAccHalfShared<T, P>
{
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> UltraPermutationRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == UltraPermutationRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
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

pub(crate) struct UltraPermutationRelation {}

impl UltraPermutationRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 8;
}

impl UltraPermutationRelation {
    fn compute_grand_product_numerator_and_denominator_batch<
        T: NoirUltraHonkProver<P>,
        P: Pairing,
    >(
        party_id: T::PartyID,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> (Vec<T::ArithmeticShare>, Vec<T::ArithmeticShare>) {
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

        // witness degree 4; full degree 8
        let mut wid1 = None;
        let mut wid2 = None;
        let mut wid3 = None;
        let mut wid4 = None;

        let mut wsigma1 = None;
        let mut wsigma2 = None;
        let mut wsigma3 = None;
        let mut wsigma4 = None;

        macro_rules! add_with_beta_gamma {
            ($pub: expr, $sh: expr) => {
                Some(
                    ($pub, $sh)
                        .into_par_iter()
                        .with_min_len(MIN_RAYON_ITER)
                        .map(|(p, s)| T::add_with_public(*p * beta + gamma, *s, party_id))
                        .collect::<Vec<_>>(),
                )
            };
        }
        rayon::scope(|scope| {
            scope.spawn(|_| wid1 = add_with_beta_gamma!(id_1, w_1));
            scope.spawn(|_| wid2 = add_with_beta_gamma!(id_2, w_2));
            scope.spawn(|_| wid3 = add_with_beta_gamma!(id_3, w_3));
            scope.spawn(|_| wid4 = add_with_beta_gamma!(id_4, w_4));
            scope.spawn(|_| wsigma1 = add_with_beta_gamma!(sigma_1, w_1));
            scope.spawn(|_| wsigma2 = add_with_beta_gamma!(sigma_2, w_2));
            scope.spawn(|_| wsigma3 = add_with_beta_gamma!(sigma_3, w_3));
            scope.spawn(|_| wsigma4 = add_with_beta_gamma!(sigma_4, w_4));
        });
        // we can unwrap here because rayon scope cannot fail
        // and therefore we have Some values for sures
        let wid1 = wid1.unwrap();
        let wid2 = wid2.unwrap();
        let wid3 = wid3.unwrap();
        let wid4 = wid4.unwrap();

        let wsigma1 = wsigma1.unwrap();
        let wsigma2 = wsigma2.unwrap();
        let wsigma3 = wsigma3.unwrap();
        let wsigma4 = wsigma4.unwrap();

        let len = wid1.len() * 4;

        rayon::join(
            || {
                let mut lhs = Vec::with_capacity(len);

                lhs.extend(wid1);
                lhs.extend(wsigma1);
                lhs.extend(wid3);
                lhs.extend(wsigma3);
                lhs
            },
            || {
                let mut rhs = Vec::with_capacity(len);
                rhs.extend(wid2);
                rhs.extend(wsigma2);
                rhs.extend(wid4);
                rhs.extend(wsigma4);
                rhs
            },
        )
    }

    fn compute_r1<T, P>(
        r1: &mut SharedUnivariate<T, P, 3>,
        input: &ProverUnivariatesBatch<T, P>,
        scaling_factors: &[P::ScalarField],
    ) where
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    {
        let lagrange_last = input.precomputed.lagrange_last();
        let z_perm_shift = input.shifted_witness.z_perm();
        let acc = (lagrange_last, z_perm_shift, scaling_factors)
            .into_par_iter()
            .with_min_len(MIN_RAYON_ITER)
            .map(|(lagrange_last, z_perm_shift, scaling_factor)| {
                let tmp = T::mul_with_public(*lagrange_last, *z_perm_shift);
                T::mul_with_public(*scaling_factor, tmp)
            });
        relation_utils::accumulate!(acc, r1);
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for UltraPermutationRelation
{
    type Acc = UltraPermutationRelationAccHalfShared<T, P>;

    fn can_skip(_: &super::ProverUnivariates<T, P>) -> bool {
        false
    }

    fn add_entites(
        entity: &super::ProverUnivariates<T, P>,
        batch: &mut ProverUnivariatesBatch<T, P>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_id_1(entity);
        batch.add_id_2(entity);
        batch.add_id_3(entity);
        batch.add_id_4(entity);

        batch.add_sigma_1(entity);
        batch.add_sigma_2(entity);
        batch.add_sigma_3(entity);
        batch.add_sigma_4(entity);

        batch.add_z_perm(entity);
        batch.add_shifted_z_perm(entity);
        batch.add_lagrange_first(entity);
        batch.add_lagrange_last(entity);
    }
    /**
    * @brief Compute contribution of the permutation relation for a given edge (internal function)
    *
    * @details This relation confirms faithful calculation of the grand
    * product polynomial \f$ Z_{\text{perm}}\f$.
    * In Sumcheck Prover Round, this method adds to accumulators evaluations of subrelations at the point
       \f$(u_0,\ldots, u_{i-1}, k, \vec\ell)\f$ for \f$ k=0,\ldots, D\f$, where \f$ \vec \ell\f$ is a point  on the
       Boolean hypercube \f$\{0,1\}^{d-1-i}\f$ and \f$ D \f$ is specified by the calling class. It does so by taking as
       input an array of Prover Polynomials partially evaluated at the points \f$(u_0,\ldots, u_{i-1}, k, \vec\ell)\f$ and
       computing point-wise evaluations of the sub-relations. \todo Protogalaxy Accumulation
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
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let party_id = driver.get_party_id();
        let ((num_den_lhs, num_den_rhs), tmp_lhs, tmp_rhs, _) = relation_utils::rayon_multi_join!(
            Self::compute_grand_product_numerator_and_denominator_batch(
                party_id,
                input,
                relation_parameters,
            ),
            (lagrange_first, z_perm)
                .into_par_iter()
                .with_min_len(MIN_RAYON_ITER)
                .map(|(lagrange_first, z_perm)| {
                    T::add_with_public(*lagrange_first, *z_perm, party_id)
                })
                .collect::<Vec<_>>(),
            (lagrange_last, z_perm_shift)
                .into_par_iter()
                .with_min_len(MIN_RAYON_ITER)
                .map(|(lagrange_last, z_perm_shift)| {
                    T::add_with_public(
                        *lagrange_last * *public_input_delta,
                        *z_perm_shift,
                        party_id,
                    )
                })
                .collect::<Vec<_>>(),
            Self::compute_r1(&mut univariate_accumulator.r1, input, scaling_factors)
        );
        // 0xThemis TODO can we reduce mul depth here??
        let mul1 = driver.mul_many(&num_den_lhs, &num_den_rhs)?;
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        let lhs = driver.mul_many(lhs, rhs)?;

        // 0xThemis TODO we dont have to copy all together - does it matter?
        let mut rhs = Vec::with_capacity(tmp_lhs.len() + tmp_lhs.len());
        rhs.extend(tmp_lhs);
        rhs.extend(tmp_rhs);
        let mul1 = driver.local_mul_vec(&lhs, &rhs);
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        let acc = (lhs, rhs, scaling_factors)
            .into_par_iter()
            .with_min_len(MIN_RAYON_ITER)
            .map(|(lhs, rhs, scaling_factor)| (*lhs - rhs) * scaling_factor);

        relation_utils::accumulate_half_share!(acc, univariate_accumulator.r0);

        Ok(())
    }
}
