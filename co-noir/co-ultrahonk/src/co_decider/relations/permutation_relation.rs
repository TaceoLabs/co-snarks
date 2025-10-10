use super::{ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{
        relations::fold_accumulator, types::RelationParameters, univariates::SharedUnivariate,
    },
    fold_type_accumulator, impl_relation_acc_type_methods,
    mpc_prover_flavour::MPCProverFlavour,
    types::AllEntities,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_noir_common::mpc::NoirUltraHonkProver;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

pub enum UltraPermutationRelationAccType<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    Partial(UltraPermutationRelationAcc<T, P, 6>),
    Total(UltraPermutationRelationAcc<T, P, 11>),
}

impl_relation_acc_type_methods!(UltraPermutationRelationAccType);

#[derive(Clone, Debug)]
pub(crate) struct UltraPermutationRelationAcc<
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    const LENGTH: usize,
> {
    pub(crate) r0: SharedUnivariate<T, P, LENGTH>,
    pub(crate) r1: SharedUnivariate<T, P, 3>,
}

#[derive(Clone, Debug)]
pub(crate) struct UltraPermutationRelationEvals<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: T::ArithmeticShare,
    pub(crate) r1: T::ArithmeticShare,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup, const LENGTH: usize> Default
    for UltraPermutationRelationAcc<T, P, LENGTH>
{
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for UltraPermutationRelationEvals<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> UltraPermutationRelationEvals<T, P> {
    pub(crate) fn scale_by_challenge_and_accumulate(
        &self,
        linearly_independent_contribution: &mut T::ArithmeticShare,
        running_challenge: &[P::ScalarField],
    ) {
        assert!(running_challenge.len() == UltraPermutationRelation::NUM_RELATIONS);

        let tmp = T::mul_with_public_many(running_challenge, &[self.r0, self.r1])
            .into_iter()
            .reduce(T::add)
            .expect("Failed to accumulate permutation relation evaluations");
        T::add_assign(linearly_independent_contribution, tmp);
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup, const LENGTH: usize>
    UltraPermutationRelationAcc<T, P, LENGTH>
{
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

    pub(crate) fn extend_and_batch_univariates_with_distinct_challenges<const SIZE: usize>(
        &self,
        result: &mut SharedUnivariate<T, P, SIZE>,
        running_challenge: &[Univariate<P::ScalarField, SIZE>],
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            &running_challenge[0],
            &P::ScalarField::ONE,
            true,
        );

        self.r1.extend_and_batch_univariates(
            result,
            &running_challenge[1],
            &P::ScalarField::ONE,
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
        P: CurveGroup,
        N: Network,
        L: MPCProverFlavour,
    >(
        net: &N,
        state: &mut T::State,
        input: &ProverUnivariatesBatch<T, P, L>,
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

    fn compute_grand_product_numerator_and_denominator_batch_with_extended_parameters<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        N: Network,
        L: MPCProverFlavour,
        const SIZE: usize,
    >(
        net: &N,
        state: &mut T::State,
        input: &ProverUnivariatesBatch<T, P, L>,
        relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();

        let id_1 = Univariate::from(input.precomputed.id_1().to_owned());
        let id_2 = Univariate::from(input.precomputed.id_2().to_owned());
        let id_3 = Univariate::from(input.precomputed.id_3().to_owned());
        let id_4 = Univariate::from(input.precomputed.id_4().to_owned());
        let sigma_1 = Univariate::from(input.precomputed.sigma_1().to_owned());
        let sigma_2 = Univariate::from(input.precomputed.sigma_2().to_owned());
        let sigma_3 = Univariate::from(input.precomputed.sigma_3().to_owned());
        let sigma_4 = Univariate::from(input.precomputed.sigma_4().to_owned());

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        let id = state.id();
        // witness degree 4; full degree 8
        let id_1 = id_1 * beta + gamma;
        let id_2 = id_2 * beta + gamma;
        let id_3 = id_3 * beta + gamma;
        let id_4 = id_4 * beta + gamma;

        let sigma_1 = sigma_1 * beta + gamma;
        let sigma_2 = sigma_2 * beta + gamma;
        let sigma_3 = sigma_3 * beta + gamma;
        let sigma_4 = sigma_4 * beta + gamma;

        let mut wid1 = None;
        let mut wid2 = None;
        let mut wid3 = None;
        let mut wid4 = None;

        let mut wsigma1 = None;
        let mut wsigma2 = None;
        let mut wsigma3 = None;
        let mut wsigma4 = None;

        rayon::scope(|scope| {
            scope.spawn(|_| wid1 = Some(T::add_with_public_many(&id_1.evaluations, w_1, id)));
            scope.spawn(|_| wid2 = Some(T::add_with_public_many(&id_2.evaluations, w_2, id)));
            scope.spawn(|_| wid3 = Some(T::add_with_public_many(&id_3.evaluations, w_3, id)));
            scope.spawn(|_| wid4 = Some(T::add_with_public_many(&id_4.evaluations, w_4, id)));
            scope.spawn(|_| wsigma1 = Some(T::add_with_public_many(&sigma_1.evaluations, w_1, id)));
            scope.spawn(|_| wsigma2 = Some(T::add_with_public_many(&sigma_2.evaluations, w_2, id)));
            scope.spawn(|_| wsigma3 = Some(T::add_with_public_many(&sigma_3.evaluations, w_3, id)));
            scope.spawn(|_| wsigma4 = Some(T::add_with_public_many(&sigma_4.evaluations, w_4, id)));
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

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for UltraPermutationRelation
{
    type Acc = UltraPermutationRelationAccType<T, P>;
    type VerifyAcc = UltraPermutationRelationEvals<T, P>;

    fn can_skip(_: &super::ProverUnivariates<T, P, L>) -> bool {
        false
    }

    fn add_entities(
        entity: &super::ProverUnivariates<T, P, L>,
        batch: &mut ProverUnivariatesBatch<T, P, L>,
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
    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
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

        fold_type_accumulator!(
            UltraPermutationRelationAccType,
            univariate_accumulator,
            r0,
            tmp,
            SIZE
        );

        let mut tmp = T::mul_with_public_many(lagrange_last, z_perm_shift);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_type_accumulator!(
            UltraPermutationRelationAccType,
            univariate_accumulator,
            r1,
            tmp,
            SIZE
        );

        Ok(())
    }

    fn accumulate_with_extended_parameters<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
        relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let num_den =
            Self::compute_grand_product_numerator_and_denominator_batch_with_extended_parameters(
                net,
                state,
                input,
                relation_parameters,
            )?;

        let id = state.id();
        let tmp_lhs = T::add_with_public_many(lagrange_first, z_perm, id);
        let lagrange_last_delta = lagrange_last
            .iter()
            .zip(public_input_delta.evaluations.iter())
            .map(|(x, delta)| *x * *delta);
        let tmp_rhs = T::add_with_public_many_iter(lagrange_last_delta, z_perm_shift, id);

        let lhs = num_den;
        let mut rhs = Vec::with_capacity(tmp_lhs.len() + tmp_lhs.len());
        rhs.extend(tmp_lhs);
        rhs.extend(tmp_rhs);
        let mul1 = T::mul_many(&lhs, &rhs, net, state)?;
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        let mut tmp = lhs.to_vec();
        T::sub_assign_many(&mut tmp, rhs);
        T::scale_many_in_place(&mut tmp, *scaling_factor);

        fold_type_accumulator!(
            UltraPermutationRelationAccType,
            univariate_accumulator,
            r0,
            tmp,
            SIZE
        );

        let mut tmp = T::mul_with_public_many(lagrange_last, z_perm_shift);
        T::scale_many_in_place(&mut tmp, *scaling_factor);

        fold_type_accumulator!(
            UltraPermutationRelationAccType,
            univariate_accumulator,
            r1,
            tmp,
            SIZE
        );

        Ok(())
    }

    fn accumulate_evaluations<N: Network>(
        net: &N,
        state: &mut T::State,
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<T::ArithmeticShare, P::ScalarField, L>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let id_1 = input.precomputed.id_1().to_owned();
        let id_2 = input.precomputed.id_2().to_owned();
        let id_3 = input.precomputed.id_3().to_owned();
        let id_4 = input.precomputed.id_4().to_owned();
        let sigma_1 = input.precomputed.sigma_1().to_owned();
        let sigma_2 = input.precomputed.sigma_2().to_owned();
        let sigma_3 = input.precomputed.sigma_3().to_owned();
        let sigma_4 = input.precomputed.sigma_4().to_owned();

        let beta = relation_parameters.beta;
        let gamma = relation_parameters.gamma;

        let public_input_delta = relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm().to_owned();
        let lagrange_first = input.precomputed.lagrange_first().to_owned();
        let lagrange_last = input.precomputed.lagrange_last().to_owned();

        let w_1_plus_gamma = T::add_with_public(gamma, w_1.to_owned(), state.id());
        let w_2_plus_gamma = T::add_with_public(gamma, w_2.to_owned(), state.id());
        let w_3_plus_gamma = T::add_with_public(gamma, w_3.to_owned(), state.id());
        let w_4_plus_gamma = T::add_with_public(gamma, w_4.to_owned(), state.id());

        let t1 = T::add_with_public(id_1 * beta, w_1_plus_gamma, state.id());
        let t2 = T::add_with_public(id_2 * beta, w_2_plus_gamma, state.id());
        let t3 = T::add_with_public(id_3 * beta, w_3_plus_gamma, state.id());
        let t4 = T::add_with_public(id_4 * beta, w_4_plus_gamma, state.id());

        let t5 = T::add_with_public(sigma_1 * beta, w_1_plus_gamma, state.id());
        let t6 = T::add_with_public(sigma_2 * beta, w_2_plus_gamma, state.id());
        let t7 = T::add_with_public(sigma_3 * beta, w_3_plus_gamma, state.id());
        let t8 = T::add_with_public(sigma_4 * beta, w_4_plus_gamma, state.id());

        let num_den = T::mul_many(&[t1, t2, t5, t6], &[t3, t4, t7, t8], net, state)?;
        let [numerator, denominator] = T::mul_many(
            &[num_den[0], num_den[2]],
            &[num_den[1], num_den[3]],
            net,
            state,
        )?
        .try_into()
        .unwrap();

        let public_input_term =
            T::add_with_public(public_input_delta * lagrange_last, z_perm_shift, state.id());

        let public_input_term_by_denominator = T::mul(public_input_term, denominator, net, state)?;
        let z_perm_plus_lagrange_first_by_numerator = T::mul(
            numerator,
            T::add_with_public(lagrange_first, z_perm.to_owned(), state.id()),
            net,
            state,
        )?;

        let tmp = T::sub(
            z_perm_plus_lagrange_first_by_numerator,
            public_input_term_by_denominator,
        );

        T::add_assign(&mut accumulator.r0, tmp);

        let lagrange_last_by_z_perm_shift = T::mul_with_public(lagrange_last, z_perm_shift);
        let tmp = T::mul_with_public(*scaling_factor, lagrange_last_by_z_perm_shift);

        T::add_assign(&mut accumulator.r1, tmp);

        Ok(())
    }
}
