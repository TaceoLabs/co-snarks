use super::zk_data::SharedZKSumcheckData;
use crate::{
    co_decider::{
        relations::{
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::EllipticRelation, logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
            ultra_arithmetic_relation::UltraArithmeticRelation, AllRelationAcc, Relation,
        },
        types::{
            ProverUnivariates, ProverUnivariatesBatch, RelationParameters,
            BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK,
        },
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
    types::AllEntities,
    types_batch::AllEntitiesBatchRelations,
};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use co_builder::prelude::{HonkCurve, RowDisablingPolynomial};
use co_builder::HonkProofResult;
use ultrahonk::prelude::{GateSeparatorPolynomial, TranscriptFieldType, Univariate};

pub(crate) type SumcheckRoundOutput<T, P, const U: usize> = SharedUnivariate<T, P, U>;

pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}

impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    fn extend_edges<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>>(
        extended_edges: &mut ProverUnivariates<T, P>,
        multivariates: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        edge_index: usize,
    ) {
        tracing::trace!("Extend edges");
        for (src, des) in multivariates
            .public_iter()
            .zip(extended_edges.public_iter_mut())
        {
            des.extend_from(&src[edge_index..edge_index + 2]);
        }

        for (src, des) in multivariates
            .shared_iter()
            .zip(extended_edges.shared_iter_mut())
        {
            des.extend_from(&src[edge_index..edge_index + 2]);
        }
    }

    /**
     * @brief Extend Univariates then sum them multiplying by the current \f$ pow_{\beta} \f$-contributions.
     * @details Since the sub-relations comprising full Honk relation are of different degrees, the computation of the
     * evaluations of round univariate \f$ \tilde{S}_{i}(X_{i}) \f$ at points \f$ X_{i} = 0,\ldots, D \f$ requires to
     * extend evaluations of individual relations to the domain \f$ 0,\ldots, D\f$. Moreover, linearly independent
     * sub-relations, i.e. whose validity is being checked at every point of the hypercube, are multiplied by the
     * constant \f$ c_i = pow_\beta(u_0,\ldots, u_{i-1}) \f$ and the current \f$pow_{\beta}\f$-factor \f$ ( (1−X_i) +
     * X_i\cdot \beta_i ) \vert_{X_i = k} \f$ for \f$ k = 0,\ldots, D\f$.
     * @tparam extended_size Size after extension
     * @param tuple A tuple of tuples of Univariates
     * @param result Round univariate \f$ \tilde{S}^i\f$ represented by its evaluations over \f$ \{0,\ldots, D\} \f$.
     * @param gate_sparators Round \f$pow_{\beta}\f$-factor  \f$ ( (1−X_i) + X_i\cdot \beta_i )\f$.
     */
    fn extend_and_batch_univariates<T: NoirUltraHonkProver<P>, P: Pairing, const SIZE: usize>(
        result: &mut SumcheckRoundOutput<T, P, SIZE>,
        univariate_accumulators: AllRelationAcc<T, P>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [P::ScalarField::one(), gate_sparators.current_element()];
        let mut extended_random_polynomial = Univariate::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        univariate_accumulators.extend_and_batch_univariates(
            result,
            &extended_random_polynomial,
            &gate_sparators.partial_evaluation_result,
        )
    }

    /**
     * @brief Given a tuple of tuples of extended per-relation contributions,  \f$ (t_0, t_1, \ldots,
     * t_{\text{NUM_SUBRELATIONS}-1}) \f$ and a challenge \f$ \alpha \f$, scale them by the relation separator
     * \f$\alpha\f$, extend to the correct degree, and take the sum multiplying by \f$pow_{\beta}\f$-contributions.
     *
     * @details This method receives as input the univariate accumulators computed by \ref
     * accumulate_relation_univariates "accumulate relation univariates" after passing through the entire hypercube and
     * applying \ref bb::RelationUtils::add_nested_tuples "add_nested_tuples" method to join the threads. The
     * accumulators are scaled using the method \ref bb::RelationUtils< Flavor >::scale_univariates "scale univariates",
     * extended to the degree \f$ D \f$ and summed with appropriate  \f$pow_{\beta}\f$-factors using \ref
     * extend_and_batch_univariates "extend and batch univariates method" to return a vector \f$(\tilde{S}^i(0), \ldots,
     * \tilde{S}^i(D))\f$.
     *
     * @param challenge Challenge \f$\alpha\f$.
     * @param gate_sparators Round \f$pow_{\beta}\f$-factor given by  \f$ ( (1−u_i) + u_i\cdot \beta_i )\f$.
     */
    fn batch_over_relations_univariates<
        T: NoirUltraHonkProver<P>,
        P: Pairing,
        const SIZE: usize,
    >(
        mut univariate_accumulators: AllRelationAcc<T, P>,
        alphas: &[P::ScalarField; crate::NUM_ALPHAS],
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
    ) -> SumcheckRoundOutput<T, P, SIZE> {
        tracing::trace!("batch over relations");

        let running_challenge = P::ScalarField::one();
        univariate_accumulators.scale(running_challenge, alphas);

        let mut res = SumcheckRoundOutput::default();
        Self::extend_and_batch_univariates(&mut res, univariate_accumulators, gate_sparators);
        res
    }

    fn accumulate_relation_univariates_batch<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    >(
        driver: &mut T,
        univariate_accumulators: &mut AllRelationAcc<T, P>,
        sum_check_data: &AllEntitiesBatchRelations<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate relations");
        Self::accumulate_one_relation_univariates_batch::<_, _, UltraArithmeticRelation>(
            driver,
            &mut univariate_accumulators.r_arith,
            &sum_check_data.ultra_arith.all_entites,
            relation_parameters,
            &sum_check_data.ultra_arith.scaling_factors,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, UltraPermutationRelation>(
            driver,
            &mut univariate_accumulators.r_perm,
            &sum_check_data.not_skippable.all_entites,
            relation_parameters,
            &sum_check_data.not_skippable.scaling_factors,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, DeltaRangeConstraintRelation>(
            driver,
            &mut univariate_accumulators.r_delta,
            &sum_check_data.delta_range.all_entites,
            relation_parameters,
            &sum_check_data.delta_range.scaling_factors,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, EllipticRelation>(
            driver,
            &mut univariate_accumulators.r_elliptic,
            &sum_check_data.elliptic.all_entites,
            relation_parameters,
            &sum_check_data.elliptic.scaling_factors,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, AuxiliaryRelation>(
            driver,
            &mut univariate_accumulators.r_aux,
            &sum_check_data.auxiliary.all_entites,
            relation_parameters,
            &sum_check_data.auxiliary.scaling_factors,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, LogDerivLookupRelation>(
            driver,
            &mut univariate_accumulators.r_lookup,
            &sum_check_data.not_skippable.all_entites,
            relation_parameters,
            &sum_check_data.not_skippable.scaling_factors,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, Poseidon2ExternalRelation>(
            driver,
            &mut univariate_accumulators.r_pos_ext,
            &sum_check_data.poseidon_ext.all_entites,
            relation_parameters,
            &sum_check_data.poseidon_ext.scaling_factors,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, Poseidon2InternalRelation>(
            driver,
            &mut univariate_accumulators.r_pos_int,
            &sum_check_data.poseidon_int.all_entites,
            relation_parameters,
            &sum_check_data.poseidon_int.scaling_factors,
        )?;
        Ok(())
    }

    fn accumulate_one_relation_univariates_batch<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        R: Relation<T, P>,
    >(
        driver: &mut T,
        univariate_accumulator: &mut R::Acc,
        extended_edges: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        R::accumulate(
            driver,
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factors,
        )
    }

    pub(crate) fn compute_univariate_inner<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        &self,
        driver: &mut T,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, SIZE>> {
        // Barretenberg uses multithreading here

        // Construct extended edge containers

        // we have the round size and then reduce it by power of two steps
        // what can we mt here?
        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        // Construct extended edge containers
        let mut all_entites = AllEntitiesBatchRelations::new();
        for edge_idx in (0..self.round_size).step_by(2) {
            let mut extended_edges = ProverUnivariates::<T, P>::default();
            Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
            let scaling_factor =
                gate_sparators.beta_products[(edge_idx >> 1) * gate_sparators.periodicity];
            all_entites.fold_and_filter(extended_edges, scaling_factor);
        }

        let mut univariate_accumulators = AllRelationAcc::<T, P>::default();

        Self::accumulate_relation_univariates_batch(
            driver,
            &mut univariate_accumulators,
            &all_entites,
            relation_parameters,
        )?;

        let res = Self::batch_over_relations_univariates(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_sparators,
        );
        Ok(res)
    }

    pub(crate) fn compute_univariate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    >(
        &self,
        driver: &mut T,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH>> {
        tracing::trace!("Sumcheck round {}", round_index);

        self.compute_univariate_inner::<T, P, BATCHED_RELATION_PARTIAL_LENGTH>(
            driver,
            relation_parameters,
            gate_sparators,
            polynomials,
        )
    }
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_univariate_zk<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    >(
        &self,
        driver: &mut T,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        zk_sumcheck_data: &SharedZKSumcheckData<T, P>,
        row_disabling_polynomial: &mut RowDisablingPolynomial<P::ScalarField>,
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>> {
        tracing::trace!("Sumcheck round {}", round_index);

        let round_univariate = self
            .compute_univariate_inner::<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>(
                driver,
                relation_parameters,
                gate_sparators,
                polynomials,
            )?;

        let contribution_from_disabled_rows = Self::compute_disabled_contribution::<T, P>(
            driver,
            polynomials,
            relation_parameters,
            gate_sparators,
            self.round_size,
            round_index,
            row_disabling_polynomial,
        )?;

        let libra_round_univariate =
            Self::compute_libra_round_univariate(zk_sumcheck_data, round_index);

        let sub = libra_round_univariate.sub(&contribution_from_disabled_rows);
        Ok(round_univariate.add(&sub))
    }

    fn compute_libra_round_univariate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    >(
        zk_sumcheck_data: &SharedZKSumcheckData<T, P>,
        round_idx: usize,
    ) -> SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK> {
        let mut libra_round_univariate =
            SharedUnivariate::<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::default();

        // select the i'th column of Libra book-keeping table
        let current_column = &zk_sumcheck_data.libra_univariates[round_idx];
        // the evaluation of Libra round univariate at k=0...D are equal to \f$\texttt{libra_univariates}_{i}(k)\f$
        // corrected by the Libra running sum
        for idx in 0..P::LIBRA_UNIVARIATES_LENGTH {
            let eval = T::eval_poly(
                &current_column.coefficients,
                P::ScalarField::from(idx as u64),
            );
            libra_round_univariate.evaluations[idx] =
                T::add(eval, zk_sumcheck_data.libra_running_sum);
        }

        if BATCHED_RELATION_PARTIAL_LENGTH_ZK == P::LIBRA_UNIVARIATES_LENGTH {
            libra_round_univariate
        } else {
            // Note: Currently not happening
            let mut libra_round_univariate_extended =
                SharedUnivariate::<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::default();
            libra_round_univariate_extended.extend_from(&libra_round_univariate.evaluations);
            libra_round_univariate_extended
        }
    }

    fn compute_disabled_contribution<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
    >(
        driver: &mut T,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        round_size: usize,
        round_idx: usize,
        row_disabling_polynomial: &RowDisablingPolynomial<P::ScalarField>,
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>> {
        // In Round 0, we have to compute the contribution from 2 edges: n - 1 = (1,1,...,1) and n-4 = (0,1,...,1).
        let start_edge_idx = if round_idx == 0 {
            round_size - 4
        } else {
            round_size - 2
        };

        let mut all_entites = AllEntitiesBatchRelations::new();
        for edge_idx in (start_edge_idx..round_size).step_by(2) {
            let mut extended_edges = ProverUnivariates::<T, P>::default();
            Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
            let scaling_factor =
                gate_sparators.beta_products[(edge_idx >> 1) * gate_sparators.periodicity];
            all_entites.fold_and_filter(extended_edges, scaling_factor);
        }

        let mut univariate_accumulators = AllRelationAcc::<T, P>::default();

        Self::accumulate_relation_univariates_batch(
            driver,
            &mut univariate_accumulators,
            &all_entites,
            relation_parameters,
        )?;
        let mut result = Self::batch_over_relations_univariates(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_sparators,
        );

        let mut row_disabling_factor =
            Univariate::<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::default();
        row_disabling_factor.extend_from(&[
            row_disabling_polynomial.eval_at_0,
            row_disabling_polynomial.eval_at_1,
        ]);
        result = result.mul_public(&row_disabling_factor);

        Ok(result)
    }
}
