use super::zk_data::SharedZKSumcheckData;
use crate::mpc_prover_flavour::MPCProverFlavour;
use crate::mpc_prover_flavour::SharedUnivariateTrait;
use crate::types_batch::AllEntitiesBatchRelationsTrait;
use crate::{
    co_decider::{
        relations::Relation,
        types::{ProverUnivariates, RelationParameters},
    },
    types::AllEntities,
    types_batch::SumCheckDataForRelation,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use co_builder::prelude::{HonkCurve, RowDisablingPolynomial};
use common::mpc::NoirUltraHonkProver;
use mpc_net::Network;
use ultrahonk::plain_prover_flavour::UnivariateTrait;
use ultrahonk::prelude::GateSeparatorPolynomial;

const MAX_ROUND_SIZE_PER_BATCH: usize = 1 << 20;

pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}

impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    fn extend_edges<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        extended_edges: &mut ProverUnivariates<T, P, L>,
        multivariates: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
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
    fn extend_and_batch_univariates<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        L: MPCProverFlavour,
    >(
        result: &mut L::SumcheckRoundOutput<T, P>,
        univariate_accumulators: L::AllRelationAcc<T, P>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [P::ScalarField::one(), gate_separators.current_element()];
        let mut extended_random_polynomial = L::SumcheckRoundOutputPublic::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        L::extend_and_batch_univariates(
            &univariate_accumulators,
            result,
            &extended_random_polynomial,
            &gate_separators.partial_evaluation_result,
        )
    }

    fn extend_and_batch_univariates_zk<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        L: MPCProverFlavour,
    >(
        result: &mut L::SumcheckRoundOutputZK<T, P>,
        univariate_accumulators: L::AllRelationAcc<T, P>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [P::ScalarField::one(), gate_separators.current_element()];
        let mut extended_random_polynomial = L::SumcheckRoundOutputZKPublic::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        L::extend_and_batch_univariates_zk(
            &univariate_accumulators,
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
        L: MPCProverFlavour,
    >(
        mut univariate_accumulators: L::AllRelationAcc<T, P>,
        alphas: &L::Alphas<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
    ) -> L::SumcheckRoundOutput<T, P> {
        tracing::trace!("batch over relations");

        L::scale(&mut univariate_accumulators, P::ScalarField::one(), alphas);

        let mut res = L::SumcheckRoundOutput::default();
        Self::extend_and_batch_univariates::<T, P, L>(
            &mut res,
            univariate_accumulators,
            gate_separators,
        );
        res
    }

    fn batch_over_relations_univariates_zk<
        T: NoirUltraHonkProver<P>,
        P: CurveGroup,
        L: MPCProverFlavour,
    >(
        mut univariate_accumulators: L::AllRelationAcc<T, P>,
        alphas: &L::Alphas<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
    ) -> L::SumcheckRoundOutputZK<T, P> {
        tracing::trace!("batch over relations");

        L::scale(&mut univariate_accumulators, P::ScalarField::one(), alphas);

        let mut res = L::SumcheckRoundOutputZK::default();
        Self::extend_and_batch_univariates_zk::<T, P, L>(
            &mut res,
            univariate_accumulators,
            gate_separators,
        );
        res
    }

    pub(crate) fn accumulate_one_relation_univariates_batch<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
        R: Relation<T, P, L>,
        const SIZE: usize,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut R::Acc,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        sum_check_data: &SumCheckDataForRelation<T, P, L>,
    ) -> HonkProofResult<()> {
        if sum_check_data.can_skip {
            return Ok(());
        }
        R::accumulate::<N, SIZE>(
            net,
            state,
            univariate_accumulator,
            &sum_check_data.all_entites,
            relation_parameters,
            &sum_check_data.scaling_factors,
        )
    }

    fn compute_univariate_inner_template<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    ) -> HonkProofResult<<L as MPCProverFlavour>::AllRelationAcc<T, P>> {
        // Barretenberg uses multithreading here

        // Construct extended edge containers

        // we have the round size and then reduce it by power of two steps
        // what can we mt here?
        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        // Construct extended edge containers

        //
        let batch_size = MAX_ROUND_SIZE_PER_BATCH;
        let mut start = 0;
        let mut univariate_accumulators = L::AllRelationAccHalfShared::<T, P>::default();
        while start < self.round_size {
            let end = (start + batch_size).min(self.round_size);
            let mut all_entites = L::AllEntitiesBatchRelations::new();
            for edge_idx in (start..end).step_by(2) {
                let mut extended_edges = ProverUnivariates::<T, P, L>::default();
                Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
                let scaling_factor =
                    gate_separators.beta_products[(edge_idx >> 1) * gate_separators.periodicity];
                all_entites.fold_and_filter(extended_edges, scaling_factor);
            }
            L::accumulate_relation_univariates_batch(
                net,
                state,
                &mut univariate_accumulators,
                &all_entites,
                relation_parameters,
            )?;
            start = end;
        }
        L::reshare(univariate_accumulators, net, state)
    }

    pub(crate) fn compute_univariate_inner<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    ) -> HonkProofResult<L::SumcheckRoundOutput<T, P>> {
        let univariate_accumulators = self.compute_univariate_inner_template(
            net,
            state,
            relation_parameters,
            gate_separators,
            polynomials,
        )?;

        let res = Self::batch_over_relations_univariates::<T, P, L>(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_separators,
        );
        Ok(res)
    }

    pub(crate) fn compute_univariate_inner_zk<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    ) -> HonkProofResult<L::SumcheckRoundOutputZK<T, P>> {
        let univariate_accumulators = self.compute_univariate_inner_template(
            net,
            state,
            relation_parameters,
            gate_separators,
            polynomials,
        )?;

        let res = Self::batch_over_relations_univariates_zk::<T, P, L>(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_separators,
        );
        Ok(res)
    }

    pub(crate) fn compute_univariate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    ) -> HonkProofResult<L::SumcheckRoundOutput<T, P>> {
        tracing::trace!("Sumcheck round {}", round_index);

        self.compute_univariate_inner::<T, P, N, L>(
            net,
            state,
            relation_parameters,
            gate_separators,
            polynomials,
        )
    }
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_univariate_zk<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
    >(
        &self,
        net: &N,
        state: &mut T::State,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
        zk_sumcheck_data: &SharedZKSumcheckData<T, P>,
        row_disabling_polynomial: &mut RowDisablingPolynomial<P::ScalarField>,
    ) -> HonkProofResult<L::SumcheckRoundOutputZK<T, P>> {
        tracing::trace!("Sumcheck round {}", round_index);

        let round_univariate = self.compute_univariate_inner_zk(
            net,
            state,
            relation_parameters,
            gate_separators,
            polynomials,
        )?;

        let contribution_from_disabled_rows = Self::compute_disabled_contribution(
            net,
            state,
            polynomials,
            relation_parameters,
            gate_separators,
            self.round_size,
            round_index,
            row_disabling_polynomial,
        )?;

        let libra_round_univariate: L::SumcheckRoundOutputZK<T, P> =
            Self::compute_libra_round_univariate::<T, P, L>(zk_sumcheck_data, round_index);

        let sub = libra_round_univariate.sub(&contribution_from_disabled_rows);
        Ok(round_univariate.add(&sub))
    }

    fn compute_libra_round_univariate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        zk_sumcheck_data: &SharedZKSumcheckData<T, P>,
        round_idx: usize,
    ) -> L::SumcheckRoundOutputZK<T, P> {
        let mut libra_round_univariate = L::SumcheckRoundOutputZK::<T, P>::default();

        // select the i'th column of Libra book-keeping table
        let current_column = &zk_sumcheck_data.libra_univariates[round_idx];
        // the evaluation of Libra round univariate at k=0...D are equal to \f$\texttt{libra_univariates}_{i}(k)\f$
        // corrected by the Libra running sum
        for idx in 0..P::LIBRA_UNIVARIATES_LENGTH {
            let eval = T::eval_poly(
                &current_column.coefficients,
                P::ScalarField::from(idx as u64),
            );
            libra_round_univariate.evaluations()[idx] =
                T::add(eval, zk_sumcheck_data.libra_running_sum);
        }

        if L::BATCHED_RELATION_PARTIAL_LENGTH_ZK == P::LIBRA_UNIVARIATES_LENGTH {
            libra_round_univariate
        } else {
            // Note: Currently not happening
            let mut libra_round_univariate_extended = L::SumcheckRoundOutputZK::<T, P>::default();
            libra_round_univariate_extended
                .extend_from(libra_round_univariate.evaluations_as_ref());
            libra_round_univariate_extended
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn compute_disabled_contribution<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
    >(
        net: &N,
        state: &mut T::State,
        polynomials: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        round_size: usize,
        round_idx: usize,
        row_disabling_polynomial: &RowDisablingPolynomial<P::ScalarField>,
    ) -> HonkProofResult<L::SumcheckRoundOutputZK<T, P>> {
        // In Round 0, we have to compute the contribution from 2 edges: n - 1 = (1,1,...,1) and n-4 = (0,1,...,1).
        let start_edge_idx = if round_idx == 0 {
            round_size - 4
        } else {
            round_size - 2
        };

        let mut all_entites = L::AllEntitiesBatchRelations::new();
        for edge_idx in (start_edge_idx..round_size).step_by(2) {
            let mut extended_edges = ProverUnivariates::<T, P, L>::default();
            Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
            let scaling_factor =
                gate_separators.beta_products[(edge_idx >> 1) * gate_separators.periodicity];
            all_entites.fold_and_filter(extended_edges, scaling_factor);
        }

        let mut univariate_accumulators = L::AllRelationAccHalfShared::<T, P>::default();

        L::accumulate_relation_univariates_batch(
            net,
            state,
            &mut univariate_accumulators,
            &all_entites,
            relation_parameters,
        )?;
        let univariate_accumulators = L::reshare(univariate_accumulators, net, state)?;
        let mut result = Self::batch_over_relations_univariates_zk::<T, P, L>(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_separators,
        );

        let mut row_disabling_factor = L::SumcheckRoundOutputZKPublic::<P::ScalarField>::default();
        row_disabling_factor.extend_from(&[
            row_disabling_polynomial.eval_at_0,
            row_disabling_polynomial.eval_at_1,
        ]);
        result = result
            .mul_public::<L::SumcheckRoundOutputZKPublic<P::ScalarField>>(&row_disabling_factor);

        Ok(result)
    }
}
