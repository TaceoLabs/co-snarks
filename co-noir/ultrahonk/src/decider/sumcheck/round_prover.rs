use super::{
    super::{
        types::{GateSeparatorPolynomial, RelationParameters},
        univariate::Univariate,
    },
    zk_data::ZKSumcheckData,
};
use crate::decider::types::{BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK};
use crate::{
    decider::{
        relations::{
            AllRelationAcc, Relation,
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::{EllipticRelation, EllipticRelationAcc},
            logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
            ultra_arithmetic_relation::UltraArithmeticRelation,
        },
        types::ProverUnivariates,
    },
    transcript::TranscriptFieldType,
    types::AllEntities,
};
use ark_ff::PrimeField;
use co_builder::prelude::{HonkCurve, RowDisablingPolynomial};

pub(crate) type SumcheckRoundOutput<F, const U: usize> = Univariate<F, U>;

pub(crate) struct SumcheckProverRound {
    pub(crate) round_size: usize,
}

impl SumcheckProverRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        Self {
            round_size: initial_round_size,
        }
    }

    fn extend_edges<F: PrimeField>(
        extended_edges: &mut ProverUnivariates<F>,
        multivariates: &AllEntities<Vec<F>>,
        edge_index: usize,
    ) {
        tracing::trace!("Extend edges");

        for (src, des) in multivariates.iter().zip(extended_edges.iter_mut()) {
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
    fn extend_and_batch_univariates<F: PrimeField, const SIZE: usize>(
        result: &mut SumcheckRoundOutput<F, SIZE>,
        univariate_accumulators: AllRelationAcc<F>,
        gate_sparators: &GateSeparatorPolynomial<F>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [F::one(), gate_sparators.current_element()];
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
    fn batch_over_relations_univariates<F: PrimeField, const SIZE: usize>(
        mut univariate_accumulators: AllRelationAcc<F>,
        alphas: &[F; crate::NUM_ALPHAS],
        gate_sparators: &GateSeparatorPolynomial<F>,
    ) -> SumcheckRoundOutput<F, SIZE> {
        tracing::trace!("batch over relations");

        let running_challenge = F::one();
        univariate_accumulators.scale(running_challenge, alphas);

        let mut res = SumcheckRoundOutput::default();
        Self::extend_and_batch_univariates(&mut res, univariate_accumulators, gate_sparators);
        res
    }

    fn accumulate_one_relation_univariates<F: PrimeField, R: Relation<F>>(
        univariate_accumulator: &mut R::Acc,
        extended_edges: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        if R::SKIPPABLE && R::skip(extended_edges) {
            return;
        }

        R::accumulate(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_elliptic_curve_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulator: &mut EllipticRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        if EllipticRelation::SKIPPABLE && EllipticRelation::skip(extended_edges) {
            return;
        }

        EllipticRelation::accumulate::<P>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Accumulate relations");

        Self::accumulate_one_relation_univariates::<_, UltraArithmeticRelation>(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<_, UltraPermutationRelation>(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<_, DeltaRangeConstraintRelation>(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_elliptic_curve_relation_univariates::<P>(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<_, AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<_, LogDerivLookupRelation>(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<_, Poseidon2ExternalRelation>(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<_, Poseidon2InternalRelation>(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn compute_univariate_inner<P: HonkCurve<TranscriptFieldType>, const SIZE: usize>(
        &self,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<P::ScalarField>>,
    ) -> SumcheckRoundOutput<P::ScalarField, SIZE> {
        // Barretenberg uses multithreading here

        // Construct extended edge containers
        let mut extended_edge = ProverUnivariates::<P::ScalarField>::default();

        let mut univariate_accumulators = AllRelationAcc::<P::ScalarField>::default();

        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        for edge_idx in (0..self.round_size).step_by(2) {
            Self::extend_edges(&mut extended_edge, polynomials, edge_idx);
            // Compute the \f$ \ell \f$-th edge's univariate contribution,
            // scale it by the corresponding \f$ pow_{\beta} \f$ contribution and add it to the accumulators for \f$
            // \tilde{S}^i(X_i) \f$. If \f$ \ell \f$'s binary representation is given by \f$ (\ell_{i+1},\ldots,
            // \ell_{d-1})\f$, the \f$ pow_{\beta}\f$-contribution is \f$\beta_{i+1}^{\ell_{i+1}} \cdot \ldots \cdot
            // \beta_{d-1}^{\ell_{d-1}}\f$.
            Self::accumulate_relation_univariates::<P>(
                &mut univariate_accumulators,
                &extended_edge,
                relation_parameters,
                &gate_sparators.beta_products[(edge_idx >> 1) * gate_sparators.periodicity],
            );
        }

        Self::batch_over_relations_univariates(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_sparators,
        )
    }

    pub(crate) fn compute_univariate<P: HonkCurve<TranscriptFieldType>>(
        &self,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<P::ScalarField>>,
    ) -> SumcheckRoundOutput<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH> {
        tracing::trace!("Sumcheck round {}", round_index);

        self.compute_univariate_inner::<P, BATCHED_RELATION_PARTIAL_LENGTH>(
            relation_parameters,
            gate_sparators,
            polynomials,
        )
    }

    pub(crate) fn compute_univariate_zk<P: HonkCurve<TranscriptFieldType>>(
        &self,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<P::ScalarField>>,
        zk_sumcheck_data: &ZKSumcheckData<P>,
        row_disabling_polynomial: &mut RowDisablingPolynomial<P::ScalarField>,
    ) -> SumcheckRoundOutput<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK> {
        tracing::trace!("Sumcheck round {}", round_index);

        let round_univariate = self
            .compute_univariate_inner::<P, BATCHED_RELATION_PARTIAL_LENGTH_ZK>(
                relation_parameters,
                gate_sparators,
                polynomials,
            );

        let contribution_from_disabled_rows = Self::compute_disabled_contribution::<P>(
            polynomials,
            relation_parameters,
            gate_sparators,
            self.round_size,
            round_index,
            row_disabling_polynomial,
        );

        let libra_round_univariate =
            Self::compute_libra_round_univariate(zk_sumcheck_data, round_index);

        round_univariate + libra_round_univariate - contribution_from_disabled_rows
    }

    fn compute_libra_round_univariate<P: HonkCurve<TranscriptFieldType>>(
        zk_sumcheck_data: &ZKSumcheckData<P>,
        round_idx: usize,
    ) -> SumcheckRoundOutput<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK> {
        let mut libra_round_univariate =
            Univariate::<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::default();

        // select the i'th column of Libra book-keeping table
        let current_column = &zk_sumcheck_data.libra_univariates[round_idx];
        // the evaluation of Libra round univariate at k=0...D are equal to \f$\texttt{libra_univariates}_{i}(k)\f$
        // corrected by the Libra running sum
        for idx in 0..P::LIBRA_UNIVARIATES_LENGTH {
            libra_round_univariate.evaluations[idx] = current_column
                .eval_poly(P::ScalarField::from(idx as u64))
                + zk_sumcheck_data.libra_running_sum;
        }

        if BATCHED_RELATION_PARTIAL_LENGTH_ZK == P::LIBRA_UNIVARIATES_LENGTH {
            libra_round_univariate
        } else {
            // Note: Currently not happening
            let mut libra_round_univariate_extended =
                Univariate::<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK>::default();
            libra_round_univariate_extended.extend_from(&libra_round_univariate.evaluations);
            libra_round_univariate_extended
        }
    }

    fn compute_disabled_contribution<P: HonkCurve<TranscriptFieldType>>(
        polynomials: &AllEntities<Vec<P::ScalarField>>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        round_size: usize,
        round_idx: usize,
        row_disabling_polynomial: &RowDisablingPolynomial<P::ScalarField>,
    ) -> SumcheckRoundOutput<P::ScalarField, BATCHED_RELATION_PARTIAL_LENGTH_ZK> {
        // Barretenberg uses multithreading here
        let mut univariate_accumulators = AllRelationAcc::<P::ScalarField>::default();

        // Construct extended edge containers
        let mut extended_edges = ProverUnivariates::<P::ScalarField>::default();

        // In Round 0, we have to compute the contribution from 2 edges: n - 1 = (1,1,...,1) and n-4 = (0,1,...,1).
        let start_edge_idx = if round_idx == 0 {
            round_size - 4
        } else {
            round_size - 2
        };

        for edge_idx in (start_edge_idx..round_size).step_by(2) {
            Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
            Self::accumulate_relation_univariates::<P>(
                &mut univariate_accumulators,
                &extended_edges,
                relation_parameters,
                &gate_sparators.beta_products[(edge_idx >> 1) * gate_sparators.periodicity],
            );
        }
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
        result *= row_disabling_factor;

        result
    }
}
