use super::{
    super::types::{GateSeparatorPolynomial, RelationParameters},
    zk_data::ZKSumcheckData,
};
use crate::{
    decider::types::ProverUnivariates, plain_prover_flavour::PlainProverFlavour,
    prelude::Univariate,
};
use crate::{
    decider::{
        relations::{
            Relation,
            elliptic_relation::{EllipticRelation, EllipticRelationAcc},
        },
        types::ProverUnivariatesSized,
    },
    plain_prover_flavour::UnivariateTrait,
    types::AllEntities,
};

use ark_ff::PrimeField;
use co_builder::prelude::{HonkCurve, RowDisablingPolynomial};
use common::transcript::TranscriptFieldType;

pub(crate) struct SumcheckProverRound<F: PrimeField, L: PlainProverFlavour> {
    pub(crate) round_size: usize,
    phantom_field: std::marker::PhantomData<(F, L)>,
}

impl<F: PrimeField, L: PlainProverFlavour> SumcheckProverRound<F, L> {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        Self {
            round_size: initial_round_size,
            phantom_field: std::marker::PhantomData,
        }
    }

    fn extend_edges(
        extended_edges: &mut ProverUnivariates<F, L>,
        multivariates: &AllEntities<Vec<F>, L>,
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
     * @param gate_separators Round \f$pow_{\beta}\f$-factor  \f$ ( (1−X_i) + X_i\cdot \beta_i )\f$.
     */
    fn extend_and_batch_univariates(
        result: &mut L::SumcheckRoundOutput<F>,
        univariate_accumulators: L::AllRelationAcc<F>,
        gate_separators: &GateSeparatorPolynomial<F>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [F::one(), gate_separators.current_element()];
        let mut extended_random_polynomial = L::SumcheckRoundOutput::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        <L as PlainProverFlavour>::extend_and_batch_univariates(
            &univariate_accumulators,
            result,
            &extended_random_polynomial,
            &gate_separators.partial_evaluation_result,
        );
    }

    fn extend_and_batch_univariates_zk(
        result: &mut L::SumcheckRoundOutputZK<F>,
        univariate_accumulators: L::AllRelationAcc<F>,
        gate_separators: &GateSeparatorPolynomial<F>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [F::one(), gate_separators.current_element()];
        let mut extended_random_polynomial = L::SumcheckRoundOutputZK::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        <L as PlainProverFlavour>::extend_and_batch_univariates_zk(
            &univariate_accumulators,
            result,
            &extended_random_polynomial,
            &gate_separators.partial_evaluation_result,
        );
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
    fn batch_over_relations_univariates(
        mut univariate_accumulators: L::AllRelationAcc<F>,
        alphas: &[L::Alpha<F>],
        gate_separators: &GateSeparatorPolynomial<F>,
    ) -> L::SumcheckRoundOutput<F> {
        tracing::trace!("batch over relations");

        L::scale(&mut univariate_accumulators, F::one(), alphas);

        let mut res = L::SumcheckRoundOutput::default();
        Self::extend_and_batch_univariates(&mut res, univariate_accumulators, gate_separators);
        res
    }

    fn batch_over_relations_univariates_zk(
        mut univariate_accumulators: L::AllRelationAcc<F>,
        alphas: &[L::Alpha<F>],
        gate_separators: &GateSeparatorPolynomial<F>,
    ) -> L::SumcheckRoundOutputZK<F> {
        tracing::trace!("batch over relations");

        L::scale(&mut univariate_accumulators, F::one(), alphas);

        let mut res = L::SumcheckRoundOutputZK::default();
        Self::extend_and_batch_univariates_zk(&mut res, univariate_accumulators, gate_separators);
        res
    }

    pub(crate) fn accumulate_one_relation_univariates<R: Relation<F, L>, const SIZE: usize>(
        univariate_accumulator: &mut R::Acc,
        extended_edges: &ProverUnivariatesSized<F, L, SIZE>,
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

    pub(crate) fn accumulate_one_relation_univariates_extended_params<
        R: Relation<F, L>,
        const SIZE: usize,
    >(
        univariate_accumulator: &mut R::Acc,
        extended_edges: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        if R::SKIPPABLE && R::skip(extended_edges) {
            return;
        }

        R::accumulate_with_extended_parameters(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    pub(crate) fn accumulate_elliptic_curve_relation_univariates<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        const SIZE: usize,
    >(
        univariate_accumulator: &mut EllipticRelationAcc<F>,
        extended_edges: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        if EllipticRelation::SKIPPABLE && EllipticRelation::skip::<F, L, SIZE>(extended_edges) {
            return;
        }

        EllipticRelation::accumulate::<P, L, SIZE>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    pub(crate) fn accumulate_elliptic_curve_relation_univariates_extended_params<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        const SIZE: usize,
    >(
        univariate_accumulator: &mut EllipticRelationAcc<F>,
        extended_edges: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        scaling_factor: &F,
    ) {
        if EllipticRelation::SKIPPABLE && EllipticRelation::skip::<F, L, SIZE>(extended_edges) {
            return;
        }

        EllipticRelation::accumulate_with_extended_parameters::<P, L, SIZE>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn compute_univariate_inner_template<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        &self,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        polynomials: &AllEntities<Vec<P::ScalarField>, L>,
    ) -> L::AllRelationAcc<F> {
        // Barretenberg uses multithreading here

        // Construct extended edge containers
        let mut extended_edge = ProverUnivariates::<F, L>::default();

        let mut univariate_accumulators = L::AllRelationAcc::<F>::default();

        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        for edge_idx in (0..self.round_size).step_by(2) {
            Self::extend_edges(&mut extended_edge, polynomials, edge_idx);
            // Compute the \f$ \ell \f$-th edge's univariate contribution,
            // scale it by the corresponding \f$ pow_{\beta} \f$ contribution and add it to the accumulators for \f$
            // \tilde{S}^i(X_i) \f$. If \f$ \ell \f$'s binary representation is given by \f$ (\ell_{i+1},\ldots,
            // \ell_{d-1})\f$, the \f$ pow_{\beta}\f$-contribution is \f$\beta_{i+1}^{\ell_{i+1}} \cdot \ldots \cdot
            // \beta_{d-1}^{\ell_{d-1}}\f$.
            L::accumulate_relation_univariates::<P>(
                &mut univariate_accumulators,
                &extended_edge,
                relation_parameters,
                &gate_separators.beta_products[(edge_idx >> 1) * gate_separators.periodicity],
            );
        }
        univariate_accumulators
    }

    fn compute_univariate_inner<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        &self,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[L::Alpha<F>],
        polynomials: &AllEntities<Vec<P::ScalarField>, L>,
    ) -> L::SumcheckRoundOutput<P::ScalarField> {
        let univariate_accumulators = self.compute_univariate_inner_template::<P>(
            relation_parameters,
            gate_separators,
            polynomials,
        );

        Self::batch_over_relations_univariates(univariate_accumulators, alphas, gate_separators)
    }

    fn compute_univariate_inner_zk<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        &self,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[L::Alpha<F>],
        polynomials: &AllEntities<Vec<P::ScalarField>, L>,
    ) -> L::SumcheckRoundOutputZK<P::ScalarField> {
        let univariate_accumulators = self.compute_univariate_inner_template::<P>(
            relation_parameters,
            gate_separators,
            polynomials,
        );

        Self::batch_over_relations_univariates_zk(univariate_accumulators, alphas, gate_separators)
    }

    pub(crate) fn compute_univariate<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        &self,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[L::Alpha<F>],
        polynomials: &AllEntities<Vec<P::ScalarField>, L>,
    ) -> L::SumcheckRoundOutput<P::ScalarField> {
        tracing::trace!("Sumcheck round {}", round_index);

        self.compute_univariate_inner::<P>(
            relation_parameters,
            gate_separators,
            alphas,
            polynomials,
        )
    }

    pub(crate) fn compute_univariate_zk<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        &self,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[L::Alpha<F>],
        polynomials: &AllEntities<Vec<P::ScalarField>, L>,
        zk_sumcheck_data: &ZKSumcheckData<P>,
        row_disabling_polynomial: &mut RowDisablingPolynomial<P::ScalarField>,
    ) -> L::SumcheckRoundOutputZK<P::ScalarField> {
        tracing::trace!("Sumcheck round {}", round_index);

        let round_univariate = self.compute_univariate_inner_zk::<P>(
            relation_parameters,
            gate_separators,
            alphas,
            polynomials,
        );

        let contribution_from_disabled_rows = Self::compute_disabled_contribution::<P>(
            polynomials,
            relation_parameters,
            gate_separators,
            alphas,
            self.round_size,
            round_index,
            row_disabling_polynomial,
        );

        let mut libra_round_univariate =
            Self::compute_libra_round_univariate(zk_sumcheck_data, round_index);
        libra_round_univariate += round_univariate;
        libra_round_univariate -= contribution_from_disabled_rows;
        libra_round_univariate
    }

    fn compute_libra_round_univariate<P: HonkCurve<TranscriptFieldType>>(
        zk_sumcheck_data: &ZKSumcheckData<P>,
        round_idx: usize,
    ) -> L::SumcheckRoundOutputZK<P::ScalarField> {
        let mut libra_round_univariate = L::SumcheckRoundOutputZK::default();

        // select the i'th column of Libra book-keeping table
        let current_column = &zk_sumcheck_data.libra_univariates[round_idx];
        // the evaluation of Libra round univariate at k=0...D are equal to \f$\texttt{libra_univariates}_{i}(k)\f$
        // corrected by the Libra running sum
        for idx in 0..P::LIBRA_UNIVARIATES_LENGTH {
            libra_round_univariate.evaluations()[idx] = current_column
                .eval_poly(P::ScalarField::from(idx as u64))
                + zk_sumcheck_data.libra_running_sum;
        }

        if L::BATCHED_RELATION_PARTIAL_LENGTH_ZK == P::LIBRA_UNIVARIATES_LENGTH {
            libra_round_univariate
        } else {
            // Note: Currently not happening
            let mut libra_round_univariate_extended = L::SumcheckRoundOutputZK::default();
            libra_round_univariate_extended
                .extend_from(libra_round_univariate.evaluations_as_ref());
            libra_round_univariate_extended
        }
    }

    fn compute_disabled_contribution<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        polynomials: &AllEntities<Vec<P::ScalarField>, L>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_separators: &GateSeparatorPolynomial<P::ScalarField>,
        alphas: &[L::Alpha<F>],
        round_size: usize,
        round_idx: usize,
        row_disabling_polynomial: &RowDisablingPolynomial<P::ScalarField>,
    ) -> L::SumcheckRoundOutputZK<P::ScalarField> {
        // Barretenberg uses multithreading here
        let mut univariate_accumulators = L::AllRelationAcc::<F>::default();

        // Construct extended edge containers
        let mut extended_edges = ProverUnivariates::<P::ScalarField, L>::default();

        // In Round 0, we have to compute the contribution from 2 edges: n - 1 = (1,1,...,1) and n-4 = (0,1,...,1).
        let start_edge_idx = if round_idx == 0 {
            round_size - 4
        } else {
            round_size - 2
        };

        for edge_idx in (start_edge_idx..round_size).step_by(2) {
            Self::extend_edges(&mut extended_edges, polynomials, edge_idx);
            L::accumulate_relation_univariates::<P>(
                &mut univariate_accumulators,
                &extended_edges,
                relation_parameters,
                &gate_separators.beta_products[(edge_idx >> 1) * gate_separators.periodicity],
            );
        }
        let mut result = Self::batch_over_relations_univariates_zk(
            univariate_accumulators,
            alphas,
            gate_separators,
        );

        let mut row_disabling_factor = L::SumcheckRoundOutputZK::<P::ScalarField>::default();
        row_disabling_factor.extend_from(&[
            row_disabling_polynomial.eval_at_0,
            row_disabling_polynomial.eval_at_1,
        ]);
        result *= row_disabling_factor;

        result
    }
}
