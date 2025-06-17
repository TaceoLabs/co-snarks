use super::{ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{
        relations::fold_accumulator,
        types::{MAX_PARTIAL_RELATION_LENGTH, RelationParameters},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use co_builder::HonkProofResult;
use co_builder::prelude::HonkCurve;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

#[derive(Clone, Debug)]
pub(crate) struct UltraPermutationRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
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
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
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

        let id = state.id();
        // witness degree 4; full degree 8
        let id_1 = id_1.iter().map(|x| *x * beta + gamma);
        let id_2 = id_2.iter().map(|x| *x * beta + gamma);
        let id_3 = id_3.iter().map(|x| *x * beta + gamma);
        let id_4 = id_4.iter().map(|x| *x * beta + gamma);

        let sigma_1 = sigma_1.iter().map(|x| *x * beta + gamma);
        let sigma_2 = sigma_2.iter().map(|x| *x * beta + gamma);
        let sigma_3 = sigma_3.iter().map(|x| *x * beta + gamma);
        let sigma_4 = sigma_4.iter().map(|x| *x * beta + gamma);

        let mut wid1 = None;
        let mut wid2 = None;
        let mut wid3 = None;
        let mut wid4 = None;

        let mut wsigma1 = None;
        let mut wsigma2 = None;
        let mut wsigma3 = None;
        let mut wsigma4 = None;

        rayon::scope(|scope| {
            scope.spawn(|_| wid1 = Some(T::add_with_public_many_iter(id_1, w_1, id)));
            scope.spawn(|_| wid2 = Some(T::add_with_public_many_iter(id_2, w_2, id)));
            scope.spawn(|_| wid3 = Some(T::add_with_public_many_iter(id_3, w_3, id)));
            scope.spawn(|_| wid4 = Some(T::add_with_public_many_iter(id_4, w_4, id)));
            scope.spawn(|_| wsigma1 = Some(T::add_with_public_many_iter(sigma_1, w_1, id)));
            scope.spawn(|_| wsigma2 = Some(T::add_with_public_many_iter(sigma_2, w_2, id)));
            scope.spawn(|_| wsigma3 = Some(T::add_with_public_many_iter(sigma_3, w_3, id)));
            scope.spawn(|_| wsigma4 = Some(T::add_with_public_many_iter(sigma_4, w_4, id)));
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

        let mut lhs = Vec::with_capacity(wid1.len() + wsigma1.len() + wid3.len() + wsigma3.len());
        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(wid1);
        lhs.extend(wsigma1);
        lhs.extend(wid3);
        lhs.extend(wsigma3);

        rhs.extend(wid2);
        rhs.extend(wsigma2);
        rhs.extend(wid4);
        rhs.extend(wsigma4);
        let mul1 = T::mul_many(&lhs, &rhs, net, state)?;
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        Ok(T::mul_many(lhs, rhs, net, state)?)
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for UltraPermutationRelation
{
    type Acc = UltraPermutationRelationAcc<T, P>;

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
    fn accumulate<N: Network>(
        net: &N,
        state: &mut T::State,
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

        let num_den = Self::compute_grand_product_numerator_and_denominator_batch(
            net,
            state,
            input,
            relation_parameters,
        )?;

        let id = state.id();
        let tmp_lhs = T::add_with_public_many(lagrange_first, z_perm, id);
        let lagrange_last_delta = lagrange_last.iter().map(|x| *x * *public_input_delta);
        let tmp_rhs = T::add_with_public_many_iter(lagrange_last_delta, z_perm_shift, id);

        let lhs = num_den;
        let mut rhs = Vec::with_capacity(tmp_lhs.len() + tmp_lhs.len());
        rhs.extend(tmp_lhs);
        rhs.extend(tmp_rhs);
        let mul1 = T::mul_many(&lhs, &rhs, net, state)?;
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        let mut tmp = lhs.to_vec();
        T::sub_assign_many(&mut tmp, rhs);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, tmp);

        let mut tmp = T::mul_with_public_many(lagrange_last, z_perm_shift);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r1, tmp);

        Ok(())
    }
}
