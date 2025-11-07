use super::zk_data::SharedZKSumcheckData;
use crate::co_decider::relations::memory_relation::MemoryRelation;
use crate::co_decider::relations::non_native_field_relation::NonNativeFieldRelation;
use crate::{
    co_decider::{
        relations::{
            AllRelationAcc, AllRelationAccHalfShared, Relation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::EllipticRelation, logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
            ultra_arithmetic_relation::UltraArithmeticRelation,
        },
        types::{
            BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK, ProverUnivariates,
        },
        univariates::SharedUnivariate,
    },
    types_batch::{AllEntitiesBatchRelations, SumCheckDataForRelation},
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
    polynomials::polynomial::RowDisablingPolynomial,
};
use mpc_net::Network;
use ultrahonk::{
    NUM_ALPHAS,
    prelude::{GateSeparatorPolynomial, Univariate},
};

const MAX_ROUND_SIZE_PER_BATCH: usize = 1 << 20;

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
     * @param gate_separators Round \f$pow_{\beta}\f$-factor  \f$ ( (1−X_i) + X_i\cdot \beta_i )\f$.
     */
    fn extend_and_batch_univariates<T: NoirUltraHonkProver<P>, P: CurveGroup, const SIZE: usize>(
        result: &mut SumcheckRoundOutput<T, P, SIZE>,
        univariate_accumulators: AllRelationAcc<T, P>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [P::ScalarField::one(), gate_separators.current_element()];
        let mut extended_random_polynomial = Univariate::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        univariate_accumulators.extend_and_batch_univariates(
            result,
            &extended_random_polynomial,
            &gate_separators.partial_evaluation_result,
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
     * @param gate_separators Round \f$pow_{\beta}\f$-factor given by  \f$ ( (1−u_i) + u_i\cdot \beta_i )\f$.
     */
    fn batch_over_relations_univariates<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        const SIZE: usize,
    >(
        mut univariate_accumulators: AllRelationAcc<T, P>,
        alphas: &[P::ScalarField; NUM_ALPHAS],
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
    ) -> SumcheckRoundOutput<T, P, SIZE> {
        tracing::trace!("batch over relations");

        let running_challenge = P::ScalarField::one();
        univariate_accumulators.scale(running_challenge, alphas);

        let mut res = SumcheckRoundOutput::default();
        Self::extend_and_batch_univariates(&mut res, univariate_accumulators, gate_separators);
        res
    }

    fn accumulate_relation_univariates_batch<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut AllRelationAccHalfShared<T, P>,
        sum_check_data: &AllEntitiesBatchRelations<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate relations");
        Self::accumulate_one_relation_univariates_batch::<_, _, _, UltraArithmeticRelation>(
            net,
            state,
            &mut univariate_accumulators.r_arith,
            relation_parameters,
            &sum_check_data.ultra_arith,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, _, UltraPermutationRelation>(
            net,
            state,
            &mut univariate_accumulators.r_perm,
            relation_parameters,
            &sum_check_data.ultra_perm,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, _, DeltaRangeConstraintRelation>(
            net,
            state,
            &mut univariate_accumulators.r_delta,
            relation_parameters,
            &sum_check_data.delta_range,
        )?;

        Self::accumulate_one_relation_univariates_batch::<_, _, _, EllipticRelation>(
            net,
            state,
            &mut univariate_accumulators.r_elliptic,
            relation_parameters,
            &sum_check_data.elliptic,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, _, MemoryRelation>(
            net,
            state,
            &mut univariate_accumulators.r_memory,
            relation_parameters,
            &sum_check_data.memory,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, _, NonNativeFieldRelation>(
            net,
            state,
            &mut univariate_accumulators.r_nnf,
            relation_parameters,
            &sum_check_data.nnf,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, _, LogDerivLookupRelation>(
            net,
            state,
            &mut univariate_accumulators.r_lookup,
            relation_parameters,
            &sum_check_data.log_lookup,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, _, Poseidon2ExternalRelation>(
            net,
            state,
            &mut univariate_accumulators.r_pos_ext,
            relation_parameters,
            &sum_check_data.poseidon_ext,
        )?;
        Self::accumulate_one_relation_univariates_batch::<_, _, _, Poseidon2InternalRelation>(
            net,
            state,
            &mut univariate_accumulators.r_pos_int,
            relation_parameters,
            &sum_check_data.poseidon_int,
        )?;
        Ok(())
    }

    fn accumulate_one_relation_univariates_batch<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        R: Relation<T, P>,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut R::Acc,
        relation_parameters: &RelationParameters<P::ScalarField>,
        sum_check_data: &SumCheckDataForRelation<T, P>,
    ) -> HonkProofResult<()> {
        if sum_check_data.can_skip {
            return Ok(());
        }
        R::accumulate(
            net,
            state,
            univariate_accumulator,
            &sum_check_data.all_entities,
            relation_parameters,
            &sum_check_data.scaling_factors,
        )
    }

    pub(crate) fn compute_univariate_inner<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        const SIZE: usize,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        alphas: &[P::ScalarField; NUM_ALPHAS],
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, SIZE>> {
        // Barretenberg uses multithreading here

        // Construct extended edge containers

        // we have the round size and then reduce it by power of two steps
        // what can we mt here?
        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        // Construct extended edge containers

        //
        let batch_size = MAX_ROUND_SIZE_PER_BATCH;
        let mut start = 0;
        let mut univariate_accumulators = AllRelationAccHalfShared::<T, P>::default();
        while start < self.round_size {
            let end = (start + batch_size).min(self.round_size);
            let mut all_entities = AllEntitiesBatchRelations::new();
            for edge_idx in (start..end).step_by(2) {
                let mut extended_edges = ProverUnivariates::<T, P>::default();
                Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
                let scaling_factor =
                    gate_separators.beta_products[(edge_idx >> 1) * gate_separators.periodicity];
                all_entities.fold_and_filter(extended_edges, scaling_factor);
            }
            Self::accumulate_relation_univariates_batch(
                net,
                state,
                &mut univariate_accumulators,
                &all_entities,
                relation_parameters,
            )?;
            start = end;
        }
        let univariate_accumulators = univariate_accumulators.reshare(net, state)?;

        let res = Self::batch_over_relations_univariates(
            univariate_accumulators,
            alphas,
            gate_separators,
        );
        Ok(res)
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_univariate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        alphas: &[P::ScalarField; NUM_ALPHAS],
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH>> {
        tracing::trace!("Sumcheck round {}", round_index);

        self.compute_univariate_inner::<T, P, N, BATCHED_RELATION_PARTIAL_LENGTH>(
            net,
            state,
            relation_parameters,
            gate_separators,
            polynomials,
            alphas,
        )
    }
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_univariate_zk<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        zk_sumcheck_data: &SharedZKSumcheckData<T, P>,
        row_disabling_polynomial: &mut RowDisablingPolynomial<P::ScalarField>,
        alphas: &[P::ScalarField; NUM_ALPHAS],
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>> {
        tracing::trace!("Sumcheck round {}", round_index);

        let round_univariate = self
            .compute_univariate_inner::<T, P, N, BATCHED_RELATION_PARTIAL_LENGTH_ZK>(
                net,
                state,
                relation_parameters,
                gate_separators,
                polynomials,
                alphas,
            )?;

        let contribution_from_disabled_rows = Self::compute_disabled_contribution::<T, P, N>(
            net,
            state,
            polynomials,
            relation_parameters,
            gate_separators,
            self.round_size,
            round_index,
            row_disabling_polynomial,
            alphas,
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

    #[expect(clippy::too_many_arguments)]
    fn compute_disabled_contribution<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        round_size: usize,
        round_idx: usize,
        row_disabling_polynomial: &RowDisablingPolynomial<P::ScalarField>,
        alphas: &[P::ScalarField; NUM_ALPHAS],
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>> {
        // In Round 0, we have to compute the contribution from 2 edges: n - 1 = (1,1,...,1) and n-4 = (0,1,...,1).
        let start_edge_idx = if round_idx == 0 {
            round_size - 4
        } else {
            round_size - 2
        };

        let mut all_entities = AllEntitiesBatchRelations::new();
        for edge_idx in (start_edge_idx..round_size).step_by(2) {
            let mut extended_edges = ProverUnivariates::<T, P>::default();
            Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
            let scaling_factor =
                gate_separators.beta_products[(edge_idx >> 1) * gate_separators.periodicity];
            all_entities.fold_and_filter(extended_edges, scaling_factor);
        }

        let mut univariate_accumulators = AllRelationAccHalfShared::<T, P>::default();

        Self::accumulate_relation_univariates_batch(
            net,
            state,
            &mut univariate_accumulators,
            &all_entities,
            relation_parameters,
        )?;
        let univariate_accumulators = univariate_accumulators.reshare(net, state)?;
        let mut result = Self::batch_over_relations_univariates(
            univariate_accumulators,
            alphas,
            gate_separators,
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

    pub(crate) fn compute_virtual_contribution<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[P::ScalarField; NUM_ALPHAS],
    ) -> HonkProofResult<SumcheckRoundOutput<T, P, BATCHED_RELATION_PARTIAL_LENGTH>> {
        // Initialize univariate accumulator
        let mut univariate_accumulators = AllRelationAccHalfShared::<T, P>::default();
        let mut extended_edges = ProverUnivariates::<T, P>::default();
        let mut all_entities = AllEntitiesBatchRelations::new();

        // For a given prover polynomial P_i(X_0, ..., X_{d-1}) extended by zero, i.e. multiplied by
        //      \tau(X_d, ..., X_{virtual_log_n - 1}) =  \prod (1 - X_k)
        // for k = d, ..., virtual_log_n - 1, the computation of the virtual sumcheck round univariate reduces to the
        // edge (0, ...,0).
        let virtual_contribution_edge_idx = 0;

        // Perform the usual sumcheck accumulation, but for a single edge.
        Self::extend_edges(
            &mut extended_edges,
            polynomials,
            virtual_contribution_edge_idx,
        );

        // The tail of G(X) = \prod_{k} (1 + X_k(\beta_k - 1) ) evaluated at the edge (0, ..., 0).
        let gate_separator_tail = P::ScalarField::one();
        all_entities.fold_and_filter(extended_edges, gate_separator_tail);
        Self::accumulate_relation_univariates_batch(
            net,
            state,
            &mut univariate_accumulators,
            &all_entities,
            relation_parameters,
        )?;
        let univariate_accumulators = univariate_accumulators.reshare(net, state)?;

        let res = Self::batch_over_relations_univariates(
            univariate_accumulators,
            alphas,
            gate_separators,
        );
        Ok(res)
    }
}
