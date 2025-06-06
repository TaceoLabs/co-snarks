use super::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::{
    decider::{
        types::{ClaimedEvaluations, RelationParameters},
        univariate::Univariate,
    },
    plain_prover_flavour::PlainProverFlavour,
};
use ark_ff::{PrimeField, Zero};
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct LogDerivLookupRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 5>,
    pub(crate) r1: Univariate<F, 5>,
}

impl<F: PrimeField> LogDerivLookupRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == LogDerivLookupRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
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

#[derive(Clone, Debug, Default)]
pub(crate) struct LogDerivLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

impl<F: PrimeField> LogDerivLookupRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == LogDerivLookupRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
    }
}

pub(crate) struct LogDerivLookupRelation {}

impl LogDerivLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
}

impl LogDerivLookupRelation {
    // Used in the inverse correctness subrelation; facilitates only computing inverses where necessary
    fn compute_inverse_exists<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> Univariate<F, SIZE> {
        let row_has_write = input.witness.lookup_read_tags();
        let row_has_read = input.precomputed.q_lookup();

        -(row_has_write.to_owned() * row_has_read) + row_has_write + row_has_read
    }

    fn compute_inverse_exists_verifier<F: PrimeField, L: PlainProverFlavour>(
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        let row_has_write = input.witness.lookup_read_tags();
        let row_has_read = input.precomputed.q_lookup();

        -(row_has_write.to_owned() * row_has_read) + row_has_write + row_has_read
    }

    fn compute_read_term<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<F, L>,
    ) -> Univariate<F, SIZE> {
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
        let derived_table_entry_1 =
            w_1.to_owned() + gamma + negative_column_1_step_size.to_owned() * w_1_shift;
        let derived_table_entry_2 = negative_column_2_step_size.to_owned() * w_2_shift + w_2;
        let derived_table_entry_3 = negative_column_3_step_size.to_owned() * w_3_shift + w_3;

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        // deg 2 or 3
        derived_table_entry_1
            + derived_table_entry_2 * eta_1
            + derived_table_entry_3 * eta_2
            + table_index.to_owned() * eta_3
    }

    fn compute_read_term_verifier<F: PrimeField, L: PlainProverFlavour>(
        input: &ClaimedEvaluations<F, L>,
        relation_parameters: &RelationParameters<F, L>,
    ) -> F {
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
        let derived_table_entry_1 =
            w_1.to_owned() + gamma + negative_column_1_step_size.to_owned() * w_1_shift;
        let derived_table_entry_2 = negative_column_2_step_size.to_owned() * w_2_shift + w_2;
        let derived_table_entry_3 = negative_column_3_step_size.to_owned() * w_3_shift + w_3;

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        // deg 2 or 3
        derived_table_entry_1
            + derived_table_entry_2 * eta_1
            + derived_table_entry_3 * eta_2
            + table_index.to_owned() * eta_3
    }

    // Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<F, L>,
    ) -> Univariate<F, SIZE> {
        let gamma = &relation_parameters.gamma;
        let eta_1 = &relation_parameters.eta_1;
        let eta_2 = &relation_parameters.eta_2;
        let eta_3 = &relation_parameters.eta_3;

        let table_1 = input.precomputed.table_1();
        let table_2 = input.precomputed.table_2();
        let table_3 = input.precomputed.table_3();
        let table_4 = input.precomputed.table_4();

        table_1.to_owned()
            + gamma
            + table_2.to_owned() * eta_1
            + table_3.to_owned() * eta_2
            + table_4.to_owned() * eta_3
    }

    fn compute_write_term_verifier<F: PrimeField, L: PlainProverFlavour>(
        input: &ClaimedEvaluations<F, L>,
        relation_parameters: &RelationParameters<F, L>,
    ) -> F {
        let gamma = &relation_parameters.gamma;
        let eta_1 = &relation_parameters.eta_1;
        let eta_2 = &relation_parameters.eta_2;
        let eta_3 = &relation_parameters.eta_3;

        let table_1 = input.precomputed.table_1();
        let table_2 = input.precomputed.table_2();
        let table_3 = input.precomputed.table_3();
        let table_4 = input.precomputed.table_4();

        table_1.to_owned()
            + gamma
            + table_2.to_owned() * eta_1
            + table_3.to_owned() * eta_2
            + table_4.to_owned() * eta_3
    }
}

impl<F: PrimeField, L: PlainProverFlavour> Relation<F, L> for LogDerivLookupRelation {
    type Acc = LogDerivLookupRelationAcc<F>;
    type VerifyAcc = LogDerivLookupRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool {
        <Self as Relation<F, L>>::check_skippable();
        input.precomputed.q_lookup().is_zero() && input.witness.lookup_read_counts().is_zero()
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
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate LogDerivLookupRelation");

        let inverses = input.witness.lookup_inverses(); // Degree 1
        let read_counts = input.witness.lookup_read_counts(); // Degree 1
        let read_selector = input.precomputed.q_lookup(); // Degree 1

        let inverse_exists = Self::compute_inverse_exists(input); // Degree 2
        let read_term = Self::compute_read_term(input, relation_parameters); // Degree 2 (3)
        let write_term = Self::compute_write_term(input, relation_parameters); // Degree 1 (2)
        let write_inverse = read_term.to_owned() * inverses; // Degree 3 (4)
        let read_inverse = write_term.to_owned() * inverses; // Degree 2 (3)

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value is 0
        // if !inverse_exists.
        // Degrees:                     2 (3)       1 (2)        1              1
        let tmp = (read_term * write_term * inverses - inverse_exists) * scaling_factor; // Deg 4 (6)
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        // Establish validity of the read. Note: no scaling factor here since this constraint is 'linearly dependent,
        // i.e. enforced across the entire trace, not on a per-row basis.
        // Degrees:                       1            2 (3)            1            3 (4)
        let tmp = read_inverse * read_selector - write_inverse * read_counts; // Deg 4 (5)
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate LogDerivLookupRelation");

        let inverses = input.witness.lookup_inverses(); // Degree 1
        let read_counts = input.witness.lookup_read_counts(); // Degree 1
        let read_selector = input.precomputed.q_lookup(); // Degree 1

        let inverse_exists = Self::compute_inverse_exists_verifier(input); // Degree 2
        let read_term = Self::compute_read_term_verifier(input, relation_parameters); // Degree 2 (3)
        let write_term = Self::compute_write_term_verifier(input, relation_parameters); // Degree 1 (2)
        let write_inverse = read_term.to_owned() * inverses; // Degree 3 (4)
        let read_inverse = write_term.to_owned() * inverses; // Degree 2 (3)

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value is 0
        // if !inverse_exists.
        // Degrees:                     2 (3)       1 (2)        1              1
        let tmp = (read_term * write_term * inverses - inverse_exists) * scaling_factor; // Deg 4 (6)
        univariate_accumulator.r0 += tmp;

        ///////////////////////////////////////////////////////////////////////

        // Establish validity of the read. Note: no scaling factor here since this constraint is 'linearly dependent,
        // i.e. enforced across the entire trace, not on a per-row basis.
        // Degrees:                       1            2 (3)            1            3 (4)
        let tmp = read_inverse * read_selector - write_inverse * read_counts; // Deg 4 (5)
        univariate_accumulator.r1 += tmp;
    }
}
