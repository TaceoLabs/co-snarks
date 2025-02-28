use super::{ProverUnivariatesBatch, Relation};
use crate::{
    co_decider::{
        types::{ProverUnivariates, RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
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
    fn compute_grand_product_numerator_and_denominator<T: NoirUltraHonkProver<P>, P: Pairing>(
        driver: &mut T,
        input: &ProverUnivariates<T, P>,
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

        let party_id = driver.get_party_id();
        // witness degree 4; full degree 8
        let wid1 = w_1.add_public(&(id_1.to_owned() * beta + gamma), party_id);
        let wid2 = w_2.add_public(&(id_2.to_owned() * beta + gamma), party_id);
        let wid3 = w_3.add_public(&(id_3.to_owned() * beta + gamma), party_id);
        let wid4 = w_4.add_public(&(id_4.to_owned() * beta + gamma), party_id);

        let wsigma1 = w_1.add_public(&(sigma_1.to_owned() * beta + gamma), party_id);
        let wsigma2 = w_2.add_public(&(sigma_2.to_owned() * beta + gamma), party_id);
        let wsigma3 = w_3.add_public(&(sigma_3.to_owned() * beta + gamma), party_id);
        let wsigma4 = w_4.add_public(&(sigma_4.to_owned() * beta + gamma), party_id);

        let lhs = SharedUnivariate::univariates_to_vec(&[wid1, wsigma1, wid3, wsigma3]);
        let rhs = SharedUnivariate::univariates_to_vec(&[wid2, wsigma2, wid4, wsigma4]);

        let mul1 = driver.mul_many(&lhs, &rhs)?;

        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        let mul2 = driver.mul_many(lhs, rhs)?;
        // We need the result as input to the mul operations
        // let (num, den) = mul2.split_at(mul2.len() >> 1);
        // let num = SharedUnivariate::from_vec(num);
        // let den = SharedUnivariate::from_vec(den);
        // Ok((num, den))
        Ok(mul2)
    }

    fn compute_grand_product_numerator_and_denominator_batch<
        T: NoirUltraHonkProver<P>,
        P: Pairing,
    >(
        driver: &mut T,
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

        let party_id = driver.get_party_id();
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
            scope.spawn(|_| wid1 = Some(T::add_with_public_many_iter(id_1, w_1, party_id)));
            scope.spawn(|_| wid2 = Some(T::add_with_public_many_iter(id_2, w_2, party_id)));
            scope.spawn(|_| wid3 = Some(T::add_with_public_many_iter(id_3, w_3, party_id)));
            scope.spawn(|_| wid4 = Some(T::add_with_public_many_iter(id_4, w_4, party_id)));
            scope.spawn(|_| wsigma1 = Some(T::add_with_public_many_iter(sigma_1, w_1, party_id)));
            scope.spawn(|_| wsigma2 = Some(T::add_with_public_many_iter(sigma_2, w_2, party_id)));
            scope.spawn(|_| wsigma3 = Some(T::add_with_public_many_iter(sigma_3, w_3, party_id)));
            scope.spawn(|_| wsigma4 = Some(T::add_with_public_many_iter(sigma_4, w_4, party_id)));
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
        let mul1 = driver.mul_many(&lhs, &rhs)?;
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        Ok(driver.mul_many(lhs, rhs)?)
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for UltraPermutationRelation
{
    type Acc = UltraPermutationRelationAcc<T, P>;
    const SKIPPABLE: bool = false;

    fn skip(_input: &ProverUnivariates<T, P>) -> bool {
        <Self as Relation<T, P>>::check_skippable();
        // Cannot skip because z_perm and z_perm_shift are secret-shared
        false
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
        input: &ProverUnivariates<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
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

        let party_id = driver.get_party_id();

        let w_1_plus_gamma = w_1.add_scalar(*gamma, party_id);
        let w_2_plus_gamma = w_2.add_scalar(*gamma, party_id);
        let w_3_plus_gamma = w_3.add_scalar(*gamma, party_id);
        let w_4_plus_gamma = w_4.add_scalar(*gamma, party_id);

        let mut t1 = w_1_plus_gamma.add_public(&(id_1.to_owned() * beta), party_id);
        t1.scale_inplace(*scaling_factor);
        let t2 = w_2_plus_gamma.add_public(&(id_2.to_owned() * beta), party_id);
        let t3 = w_3_plus_gamma.add_public(&(id_3.to_owned() * beta), party_id);
        let t4 = w_4_plus_gamma.add_public(&(id_4.to_owned() * beta), party_id);

        let mut t5 = w_1_plus_gamma.add_public(&(sigma_1.to_owned() * beta), party_id);
        t5.scale_inplace(*scaling_factor);
        let t6 = w_2_plus_gamma.add_public(&(sigma_2.to_owned() * beta), party_id);
        let t7 = w_3_plus_gamma.add_public(&(sigma_3.to_owned() * beta), party_id);
        let t8 = w_4_plus_gamma.add_public(&(sigma_4.to_owned() * beta), party_id);

        let lhs = SharedUnivariate::univariates_to_vec(&[t1, t5, t3, t7]);
        let rhs = SharedUnivariate::univariates_to_vec(&[t2, t6, t4, t8]);
        let mul = driver.mul_many(&lhs, &rhs)?;
        let (lhs, rhs) = mul.split_at(mul.len() >> 1);
        let num_den = driver.mul_many(lhs, rhs)?;

        let public_input_term =
            z_perm_shift.add_public(&(lagrange_last.to_owned() * public_input_delta), party_id);

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let tmp_lhs = z_perm.add_public(lagrange_first, party_id);
        let lhs = num_den;
        let rhs = SharedUnivariate::univariates_to_vec(&[tmp_lhs, public_input_term]);

        let mul = driver.mul_many(&lhs, &rhs)?;
        let (lhs, rhs) = mul.split_at(mul.len() >> 1);
        let lhs = SharedUnivariate::<T, P, MAX_PARTIAL_RELATION_LENGTH>::from_vec(lhs);
        let rhs = SharedUnivariate::<T, P, MAX_PARTIAL_RELATION_LENGTH>::from_vec(rhs);

        let tmp = lhs.sub(&rhs);

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] =
                T::add(univariate_accumulator.r0.evaluations[i], tmp.evaluations[i]);
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = z_perm_shift
            .mul_public(lagrange_last)
            .scale(*scaling_factor);

        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] =
                T::add(univariate_accumulator.r1.evaluations[i], tmp.evaluations[i]);
        }

        Ok(())
    }

    fn accumulate_batch(
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm();
        let lagrange_first = input.precomputed.lagrange_first();
        let lagrange_last = input.precomputed.lagrange_last();

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let num_den = Self::compute_grand_product_numerator_and_denominator_batch(
            driver,
            input,
            relation_parameters,
        )?;

        let party_id = driver.get_party_id();
        let tmp_lhs = T::add_with_public_many(lagrange_first, z_perm, party_id);
        let lagrange_last_delta = lagrange_last.iter().map(|x| *x * *public_input_delta);
        let tmp_rhs = T::add_with_public_many_iter(lagrange_last_delta, z_perm_shift, party_id);

        let lhs = num_den;
        let mut rhs = Vec::with_capacity(tmp_lhs.len() + tmp_lhs.len());
        rhs.extend(tmp_lhs);
        rhs.extend(tmp_rhs);
        let mul1 = driver.mul_many(&lhs, &rhs)?;
        let (lhs, rhs) = mul1.split_at(mul1.len() >> 1);
        let mut tmp = lhs.to_vec();
        T::sub_assign_many(&mut tmp, rhs);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        let evaluations_len = univariate_accumulator.r0.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r0
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);

        let mut tmp = T::mul_with_public_many(lagrange_last, z_perm_shift);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        let evaluations_len = univariate_accumulator.r1.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r1
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);
        Ok(())
    }
}
