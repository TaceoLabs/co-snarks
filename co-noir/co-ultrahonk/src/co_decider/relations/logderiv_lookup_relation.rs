use super::{ProverUnivariatesBatch, Relation, fold_accumulator};
use crate::co_decider::{
    types::{MAX_PARTIAL_RELATION_LENGTH, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
};
use itertools::{Itertools as _, izip};
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct LogDerivLookupRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 5>,
    pub(crate) r1: SharedUnivariate<T, P, 5>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for LogDerivLookupRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> LogDerivLookupRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == LogDerivLookupRelation::NUM_RELATIONS);
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
            false,
        );
    }
}

pub(crate) struct LogDerivLookupRelation {}

impl LogDerivLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 2;
}

impl LogDerivLookupRelation {
    fn compute_inverse_exists<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        id: <T::State as MpcState>::PartyID,
        input: &ProverUnivariatesBatch<T, P>,
        // ) -> Univariate<P::ScalarField, MAX_PARTIAL_RELATION_LENGTH> {
    ) -> Vec<T::ArithmeticShare> {
        let row_has_write = input.witness.lookup_read_tags();
        let row_has_read = input.precomputed.q_lookup();

        let mut res = T::mul_with_public_many(row_has_read, row_has_write);
        T::neg_many(&mut res);
        T::add_assign_many(&mut res, row_has_write);
        T::add_assign_public_many(&mut res, row_has_read, id);
        res
    }

    fn compute_read_term<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        id: <T::State as MpcState>::PartyID,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> Vec<T::ArithmeticShare> {
        let gamma = &relation_parameters.gamma;
        let eta_1 = &relation_parameters.eta_1;
        let eta_2 = &relation_parameters.eta_2;
        let eta_3 = &relation_parameters.eta_3;
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let table_index = input.precomputed.q_o();
        let negative_column_1_step_size = input.precomputed.q_r();
        let negative_column_2_step_size = input.precomputed.q_m();
        let negative_column_3_step_size = input.precomputed.q_c();

        // The wire values for lookup gates are accumulators structured in such a way that the differences w_i -
        // step_size*w_i_shift result in values present in column i of a corresponding table. See the documentation in
        // method get_lookup_accumulators() in  for a detailed explanation.
        let mut derived_table_entry_1 =
            T::mul_with_public_many(negative_column_1_step_size, w_1_shift);
        T::add_assign_many(&mut derived_table_entry_1, w_1);
        T::add_scalar_in_place(&mut derived_table_entry_1, *gamma, id);

        let mut derived_table_entry_2 =
            T::mul_with_public_many(negative_column_2_step_size, w_2_shift);
        T::add_assign_many(&mut derived_table_entry_2, w_2);

        let mut derived_table_entry_3 =
            T::mul_with_public_many(negative_column_3_step_size, w_3_shift);
        T::add_assign_many(&mut derived_table_entry_3, w_3);

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        // deg 2 or 3
        T::scale_many_in_place(&mut derived_table_entry_2, *eta_1);
        T::scale_many_in_place(&mut derived_table_entry_3, *eta_2);

        T::add_assign_many(&mut derived_table_entry_1, &derived_table_entry_2);
        T::add_assign_many(&mut derived_table_entry_1, &derived_table_entry_3);
        // 0xThemis TODO we dont need to collect this
        let table_index = table_index.iter().map(|x| *x * *eta_3).collect_vec();
        T::add_assign_public_many(&mut derived_table_entry_1, &table_index, id);
        derived_table_entry_1
    }

    // Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> Vec<P::ScalarField> {
        let gamma = &relation_parameters.gamma;
        let eta_1 = &relation_parameters.eta_1;
        let eta_2 = &relation_parameters.eta_2;
        let eta_3 = &relation_parameters.eta_3;

        let table_1 = input.precomputed.table_1();
        let table_2 = input.precomputed.table_2();
        let table_3 = input.precomputed.table_3();
        let table_4 = input.precomputed.table_4();

        let mut result = Vec::with_capacity(table_1.len());
        for (table_1, table_2, table_3, table_4) in izip!(table_1, table_2, table_3, table_4) {
            result.push(
                table_1.to_owned()
                    + gamma
                    + table_2.to_owned() * eta_1
                    + table_3.to_owned() * eta_2
                    + table_4.to_owned() * eta_3,
            );
        }

        result
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for LogDerivLookupRelation
{
    type Acc = LogDerivLookupRelationAcc<T, P>;

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

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);

        batch.add_q_r(entity);
        batch.add_q_o(entity);
        batch.add_q_c(entity);
        batch.add_q_m(entity);

        batch.add_table_1(entity);
        batch.add_table_2(entity);
        batch.add_table_3(entity);
        batch.add_table_4(entity);

        batch.add_lookup_read_tags(entity);
        batch.add_lookup_inverses(entity);
        batch.add_lookup_read_counts(entity);
        batch.add_q_lookup(entity);
    }
    /**
     * @brief Log-derivative style lookup argument for conventional lookups form tables with 3 or fewer columns
     * @details The identity to be checked is of the form
     *
     * \sum{i=0}^{n-1} \frac{read_counts_i}{write_term_i} - \frac{q_lookup}{read_term_i} = 0
     *
     * where write_term = table_col_1 + \gamma + table_col_2 * \eta_1 + table_col_3 * \eta_2 + table_index * \eta_3
     * and read_term = derived_table_entry_1 + \gamma + derived_table_entry_2 * \eta_1 + derived_table_entry_3 * \eta_2
     * + table_index * \eta_3, with derived_table_entry_i = w_i - col_step_size_i\cdot w_i_shift. (The table entries
     *   must be 'derived' from wire values in this way since the stored witnesses are actually successive accumulators,
     *   the differences of which are equal to entries in a table. This is an efficiency trick to avoid using additional
     *   gates to reconstruct full size values from the limbs contained in tables).
     *
     * In practice this identity is expressed in terms of polynomials by defining a polynomial of inverses I_i =
     * \frac{1}{read_term_i\cdot write_term_i} then rewriting the above identity as
     *
     * (1) \sum{i=0}^{n-1} (read_counts_i\cdot I_i\cdot read_term_i) - (q_lookup\cdot I_i\cdot write_term_i) = 0
     *
     * This requires a second subrelation to check that polynomial I was computed correctly. For all i, it must hold
     * that
     *
     * (2) I_i\cdot read_term_i\cdot write_term_i - 1 = 0
     *
     * Note that (1) is 'linearly dependent' in the sense that it holds only as a sum across the entire execution trace.
     * (2) on the other hand holds independently at every row. Finally, note that to avoid unnecessary computation, we
     * only compute I_i at indices where the relation is 'active', i.e. on rows which either contain a lookup gate or
     * table data that has been read. For inactive rows i, we set I_i = 0. We can thus rewrite (2) as
     *
     * (2) I_i\cdot read_term_i\cdot write_term_i - is_active_i
     *
     * where is_active = q_lookup + read_tags - q_lookup\cdot read_tags
     *
     * and read_tags is a polynomial taking boolean values indicating whether the table entry at the corresponding row
     * has been read or not.
     * @note This relation utilizes functionality in the log-derivative library to compute the polynomial of inverses
     *
     */
    fn accumulate<N: Network>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        let inverses = input.witness.lookup_inverses(); // Degree 1
        let read_counts = input.witness.lookup_read_counts(); // Degree 1
        let read_selector = input.precomputed.q_lookup(); // Degree 1

        let inverse_exists = Self::compute_inverse_exists(state.id(), input); // Degree 2
        let read_term = Self::compute_read_term(state.id(), input, relation_parameters); // Degree 2 (3)
        let write_term = Self::compute_write_term(input, relation_parameters); // Degree 1 (2)
        let write_inverse = T::mul_many(&read_term, inverses, net, state)?;
        let read_inverse = T::mul_with_public_many(&write_term, inverses);

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value is 0
        // if !inverse_exists.
        // Degrees:                     2 (3)       1 (2)        1              1
        let mut tmp = T::mul_with_public_many(&write_term, &write_inverse);
        T::sub_assign_many(&mut tmp, &inverse_exists);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, tmp);

        ///////////////////////////////////////////////////////////////////////

        // Establish validity of the read. Note: no scaling factor here since this constraint is 'linearly dependent,
        // i.e. enforced across the entire trace, not on a per-row basis.
        // Degrees:                       1            2 (3)            1            3 (4)
        //
        let mul = T::mul_many(&write_inverse, read_counts, net, state)?;
        let mut tmp = T::mul_with_public_many(read_selector, &read_inverse);
        T::sub_assign_many(&mut tmp, &mul);

        fold_accumulator!(univariate_accumulator.r1, tmp);

        Ok(())
    }
}
