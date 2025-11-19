use super::Relation;
use crate::decider::{
    types::{ClaimedEvaluations, ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ff::{PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct MemoryRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 6>,
    pub(crate) r3: Univariate<F, 6>,
    pub(crate) r4: Univariate<F, 6>,
    pub(crate) r5: Univariate<F, 6>,
}

impl<F: PrimeField> MemoryRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == MemoryRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
        self.r4 *= elements[4];
        self.r5 *= elements[5];
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
            true,
        );

        self.r2.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r3.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r4.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r5.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MemoryRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
    pub(crate) r4: F,
    pub(crate) r5: F,
}

impl<F: PrimeField> MemoryRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == MemoryRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
        *result += self.r4 * running_challenge[4];
        *result += self.r5 * running_challenge[5];
    }
}

pub(crate) struct MemoryRelation {}

impl MemoryRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
}

impl<F: PrimeField> Relation<F> for MemoryRelation {
    type Acc = MemoryRelationAcc<F>;
    type VerifyAcc = MemoryRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        <Self as Relation<F>>::check_skippable();
        input.precomputed.q_memory().is_zero()
    }

    /**
     * @brief RAM/ROM memory relation
     * @details Adds contributions for identities associated with RAM/ROM memory operations custom gates:
     *  * RAM/ROM read-write consistency check
     *  * RAM timestamp difference consistency check
     *  * RAM/ROM index difference consistency check
     *
     * Multiple selectors are used to 'switch' memory gates on/off according to the following pattern:
     *
     * | gate type                    | q_mem | q_1 | q_2 | q_3 | q_4 | q_m | q_c |
     * | ---------------------------- | ----- | --- | --- | --- | --- | --- | --- |
     * | RAM/ROM access gate          | 1     | 1   | 0   | 0   | 0   | 1   | --- |
     * | RAM timestamp check          | 1     | 1   | 0   | 0   | 1   | 0   | --- |
     * | ROM consistency check        | 1     | 1   | 1   | 0   | 0   | 0   | --- |
     * | RAM consistency check        | 1     | 0   | 0   | 1   | 0   | 0   | 0   |
     *
     * N.B. The RAM consistency check identity is degree 3. To keep the overall quotient degree at <=5, only 2 selectors
     * can be used to select it.
     *
     * N.B.2 The q_c selector is used to store circuit-specific values in the RAM/ROM access gate
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the Totaly extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate MemoryRelation");
        let eta = &relation_parameters.eta_1;
        let eta_two = &relation_parameters.eta_2;
        let eta_three = &relation_parameters.eta_3;

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let q_1 = input.precomputed.q_l();
        let q_2 = input.precomputed.q_r();
        let q_3 = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_m = input.precomputed.q_m();
        let q_c = input.precomputed.q_c();
        let q_memory = input.precomputed.q_memory();

        /*
         * MEMORY
         *
         * A RAM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * t: `timestamp` of memory cell being accessed (used for RAM, set to 0 for ROM)
         *  * v: `value` of memory cell being accessed
         *  * a: `access` type of record. read: 0 = read, 1 = write
         *  * r: `record` of memory cell. record = access + index * eta + timestamp * η₂ + value * η₃
         *
         * A ROM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * v: `value1` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * v2:`value2` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * r: `record` of memory cell. record = index * eta + value2 * η₂ + value1 * η₃
         *
         *  When performing a read/write access, the values of i, t, v, v2, a, r are stored in the following wires +
         * selectors, depending on whether the gate is a RAM read/write or a ROM read
         *
         *  | gate type | i  | v2/t  |  v | a  | r  |
         *  | --------- | -- | ----- | -- | -- | -- |
         *  | ROM       | w1 | w2    | w3 | -- | w4 |
         *  | RAM       | w1 | w2    | w3 | qc | w4 |
         *
         * (for accesses where `index` is a circuit constant, it is assumed the circuit will apply a copy constraint on
         * `w2` to fix its value)
         *
         **/

        /*
         * Memory Record Check
         * Partial degree: 1
         * Total degree: 2
         *
         * A ROM/RAM access gate can be evaluated with the `memory_record_check` identity:
         *
         * qc + w1 \eta + w2 η₂ + w3 η₃ - w4 = 0
         *
         * For ROM gates, qc = 0
         * Here, informally, w4 is the "record" (a.k.a. fingerprint) of the access gate.
         */

        // memory_record_check and partial_record_check_m have either deg 1 or 2 (the latter refers to the
        // functional univariate degree when we use PG as opposed to sumcheck.)
        let mut memory_record_check = w_3.to_owned() * eta_three;
        memory_record_check += w_2.to_owned() * eta_two;
        memory_record_check += w_1.to_owned() * eta;
        memory_record_check += q_c;
        let partial_record_check = memory_record_check.to_owned(); // used later in RAM consistency check
        memory_record_check -= w_4;

        /*
         * ROM Consistency Check
         * Partial degree: 1
         * Total degree: 4
         *
         * For every ROM read, we require a multiset check applied between the record witnesses and a
         * second set of records that are sorted. (See the Plookup paper.)
         * In fact, due to our implementation, this is automatic; we implicitly have copy-constraints realizing the
         * multiset equality. In other words, the multiset check will be instantiated by a permutation check.
         *
         * We apply the following checks for the sorted records:
         *
         * 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
         * 2. index values for adjacent records are monotonically increasing
         * 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
         *
         */
        let neg_index_delta = w_1.to_owned() - w_1_shift;
        let index_delta_is_zero = neg_index_delta.to_owned() + &F::one(); // deg 1
        let record_delta = w_4_shift.to_owned() - w_4;

        let index_is_monotonically_increasing = neg_index_delta.to_owned().sqr() + &neg_index_delta; // check if next index minus current index is
        // 0 or 1. deg 2
        let adjacent_values_match_if_adjacent_indices_match =
            index_delta_is_zero.to_owned() * &record_delta; // deg 2

        let q_memory_by_scaling = q_memory.to_owned() * scaling_factor; // deg 1
        let q_one_by_two = q_1.to_owned() * q_2; // deg 2
        let q_one_by_two_by_memory_by_scaling = q_one_by_two.to_owned() * &q_memory_by_scaling; // deg 3

        let tmp =
            adjacent_values_match_if_adjacent_indices_match * &q_one_by_two_by_memory_by_scaling; // deg 5
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        let tmp = index_is_monotonically_increasing.to_owned() * &q_one_by_two_by_memory_by_scaling; // deg 5
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        let rom_consistency_check_identity = memory_record_check.to_owned() * &q_one_by_two; // deg 3 or 4

        /*
         * RAM Consistency Check
         *
         * The 'access' type of the record is extracted with the expression `w_4 - partial_record_check`
         * (i.e. for an honest Prover `w1 * η + w2 * η₂ + w3 * η₃ - w4 = access`.
         * This is validated by requiring `access` to be boolean
         *
         * For two adjacent entries in the sorted list if _both_
         *  A) index values match
         *  B) adjacent access value is 0 (i.e. next gate is a READ)
         * then
         *  C) both values must match.
         * The gate boolean check is
         * (A && B) => C  === !(A && B) || C ===  !A || !B || C
         *
         * N.B. it is the responsibility of the circuit writer to ensure that every RAM cell is initialized
         * with a WRITE operation.
         */
        let neg_access_type = partial_record_check.to_owned() - w_4; // will be 0 or 1 for honest Prover; deg 1 or 2
        let access_check = neg_access_type.to_owned().sqr() + &neg_access_type; // check value is 0 or 1; deg 2 or 4

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta) deg 1 or 2
        let mut neg_next_gate_access_type = w_3_shift.to_owned() * eta_three;
        neg_next_gate_access_type += w_2_shift.to_owned() * eta_two;
        neg_next_gate_access_type += w_1_shift.to_owned() * eta;
        neg_next_gate_access_type -= w_4_shift;
        let value_delta = w_3_shift.to_owned() - w_3;
        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            (index_delta_is_zero.to_owned() * value_delta)
                * (neg_next_gate_access_type.to_owned() + &F::one()); // deg 3 or 4

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        let next_gate_access_type_is_boolean =
            neg_next_gate_access_type.to_owned().sqr() + &neg_next_gate_access_type;

        let q_3_by_memory_and_scaling = q_3.to_owned() * &q_memory_by_scaling;
        // Putting it all together...
        let tmp =
            adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
                * &q_3_by_memory_and_scaling; // deg 5 or 6
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }

        let tmp = index_is_monotonically_increasing * &q_3_by_memory_and_scaling; // deg 4
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
        }

        let tmp = next_gate_access_type_is_boolean * &q_3_by_memory_and_scaling; // deg 4 or 6
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
        }

        let ram_consistency_check_identity = access_check * &q_3_by_memory_and_scaling; // deg 3 or 5

        /*
         * RAM Timestamp Consistency Check
         *
         * | w1 | w2 | w3 | w4 |
         * | index | timestamp | timestamp_check | -- |
         *
         * Let delta_index = index_{i + 1} - index_{i}
         *
         * Iff delta_index == 0, timestamp_check = timestamp_{i + 1} - timestamp_i
         * Else timestamp_check = 0
         */
        let timestamp_delta = w_2_shift.to_owned() - w_2; // deg 1
        let ram_timestamp_check_identity = index_delta_is_zero.to_owned() * timestamp_delta - w_3; // deg 2

        /*
         * The complete RAM/ROM memory identity
         * Partial degree:
         */
        let mut memory_identity = rom_consistency_check_identity; // deg 3 or 4
        memory_identity += ram_timestamp_check_identity * (q_4.to_owned() * q_1); // deg 4
        memory_identity += memory_record_check * (q_m.to_owned() * q_1); // deg 4 ( = deg 4 + (deg 3 or deg 4))

        // (deg 4) + (deg 4) + (deg 3)
        memory_identity *= &q_memory_by_scaling; // deg 5
        memory_identity += ram_consistency_check_identity; // deg 5 ( = deg 5 + (deg 3 or deg 5))

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += memory_identity.evaluations[i];
        } // deg 5
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate MemoryRelation");
        let eta = &relation_parameters.eta_1;
        let eta_two = &relation_parameters.eta_2;
        let eta_three = &relation_parameters.eta_3;

        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let q_1 = input.precomputed.q_l();
        let q_2 = input.precomputed.q_r();
        let q_3 = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_m = input.precomputed.q_m();
        let q_c = input.precomputed.q_c();
        let q_memory = input.precomputed.q_memory();

        /*
         * MEMORY
         *
         * A RAM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * t: `timestamp` of memory cell being accessed (used for RAM, set to 0 for ROM)
         *  * v: `value` of memory cell being accessed
         *  * a: `access` type of record. read: 0 = read, 1 = write
         *  * r: `record` of memory cell. record = access + index * eta + timestamp * η₂ + value * η₃
         *
         * A ROM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * v: `value1` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * v2:`value2` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * r: `record` of memory cell. record = index * eta + value2 * η₂ + value1 * η₃
         *
         *  When performing a read/write access, the values of i, t, v, v2, a, r are stored in the following wires +
         * selectors, depending on whether the gate is a RAM read/write or a ROM read
         *
         *  | gate type | i  | v2/t  |  v | a  | r  |
         *  | --------- | -- | ----- | -- | -- | -- |
         *  | ROM       | w1 | w2    | w3 | -- | w4 |
         *  | RAM       | w1 | w2    | w3 | qc | w4 |
         *
         * (for accesses where `index` is a circuit constant, it is assumed the circuit will apply a copy constraint on
         * `w2` to fix its value)
         *
         **/

        /*
         * Memory Record Check
         * Partial degree: 1
         * Total degree: 2
         *
         * A ROM/RAM access gate can be evaluated with the `memory_record_check` identity:
         *
         * qc + w1 \eta + w2 η₂ + w3 η₃ - w4 = 0
         *
         * For ROM gates, qc = 0
         * Here, informally, w4 is the "record" (a.k.a. fingerprint) of the access gate.
         */

        // memory_record_check and partial_record_check_m have either deg 1 or 2 (the latter refers to the
        // functional univariate degree when we use PG as opposed to sumcheck.)
        let mut memory_record_check = w_3.to_owned() * eta_three;
        memory_record_check += w_2.to_owned() * eta_two;
        memory_record_check += w_1.to_owned() * eta;
        memory_record_check += q_c;
        let partial_record_check = memory_record_check.to_owned(); // used later in RAM consistency check
        memory_record_check -= w_4;

        /*
         * ROM Consistency Check
         * Partial degree: 1
         * Total degree: 4
         *
         * For every ROM read, we require a multiset check applied between the record witnesses and a
         * second set of records that are sorted. (See the Plookup paper.)
         * In fact, due to our implementation, this is automatic; we implicitly have copy-constraints realizing the
         * multiset equality. In other words, the multiset check will be instantiated by a permutation check.
         *
         * We apply the following checks for the sorted records:
         *
         * 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
         * 2. index values for adjacent records are monotonically increasing
         * 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
         *
         */
        let neg_index_delta = w_1.to_owned() - w_1_shift;
        let index_delta_is_zero = neg_index_delta.to_owned() + F::one(); // deg 1
        let record_delta = w_4_shift.to_owned() - w_4;

        let index_is_monotonically_increasing = neg_index_delta.square() + neg_index_delta; // check if next index minus current index is
        // 0 or 1. deg 2
        let adjacent_values_match_if_adjacent_indices_match =
            index_delta_is_zero.to_owned() * record_delta; // deg 2

        let q_memory_by_scaling = q_memory.to_owned() * scaling_factor; // deg 1
        let q_one_by_two = q_1.to_owned() * q_2; // deg 2
        let q_one_by_two_by_memory_by_scaling = q_one_by_two.to_owned() * q_memory_by_scaling; // deg 3

        let tmp =
            adjacent_values_match_if_adjacent_indices_match * q_one_by_two_by_memory_by_scaling; // deg 5
        univariate_accumulator.r1 += tmp;

        let tmp = index_is_monotonically_increasing.to_owned() * q_one_by_two_by_memory_by_scaling; // deg 5
        univariate_accumulator.r2 += tmp;

        let rom_consistency_check_identity = memory_record_check.to_owned() * q_one_by_two; // deg 3 or 4

        /*
         * RAM Consistency Check
         *
         * The 'access' type of the record is extracted with the expression `w_4 - partial_record_check`
         * (i.e. for an honest Prover `w1 * η + w2 * η₂ + w3 * η₃ - w4 = access`.
         * This is validated by requiring `access` to be boolean
         *
         * For two adjacent entries in the sorted list if _both_
         *  A) index values match
         *  B) adjacent access value is 0 (i.e. next gate is a READ)
         * then
         *  C) both values must match.
         * The gate boolean check is
         * (A && B) => C  === !(A && B) || C ===  !A || !B || C
         *
         * N.B. it is the responsibility of the circuit writer to ensure that every RAM cell is initialized
         * with a WRITE operation.
         */
        let neg_access_type = partial_record_check.to_owned() - w_4; // will be 0 or 1 for honest Prover; deg 1 or 2
        let access_check = neg_access_type.to_owned().square() + neg_access_type; // check value is 0 or 1; deg 2 or 4

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta) deg 1 or 2
        let mut neg_next_gate_access_type = w_3_shift.to_owned() * eta_three;
        neg_next_gate_access_type += w_2_shift.to_owned() * eta_two;
        neg_next_gate_access_type += w_1_shift.to_owned() * eta;
        neg_next_gate_access_type -= w_4_shift;
        let value_delta_m = w_3_shift.to_owned() - w_3;
        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            (index_delta_is_zero.to_owned() * value_delta_m)
                * (neg_next_gate_access_type.to_owned() + F::one()); // deg 3 or 4

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        let next_gate_access_type_is_boolean =
            neg_next_gate_access_type.to_owned().square() + neg_next_gate_access_type;

        let q_3_by_memory_and_scaling = q_3.to_owned() * q_memory_by_scaling;
        // Putting it all together...
        let tmp =
            adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
                * q_3_by_memory_and_scaling; // deg 5 or 6
        univariate_accumulator.r3 += tmp;

        let tmp = index_is_monotonically_increasing * q_3_by_memory_and_scaling; // deg 4
        univariate_accumulator.r4 += tmp;

        let tmp = next_gate_access_type_is_boolean * q_3_by_memory_and_scaling; // deg 4 or 6
        univariate_accumulator.r5 += tmp;

        let ram_consistency_check_identity = access_check * q_3_by_memory_and_scaling; // deg 3 or 5

        /*
         * RAM Timestamp Consistency Check
         *
         * | w1 | w2 | w3 | w4 |
         * | index | timestamp | timestamp_check | -- |
         *
         * Let delta_index = index_{i + 1} - index_{i}
         *
         * Iff delta_index == 0, timestamp_check = timestamp_{i + 1} - timestamp_i
         * Else timestamp_check = 0
         */
        let timestamp_delta = w_2_shift.to_owned() - w_2; // deg 1
        let ram_timestamp_check_identity = index_delta_is_zero.to_owned() * timestamp_delta - w_3; // deg 2

        /*
         * The complete RAM/ROM memory identity
         * Partial degree:
         */
        let mut memory_identity = rom_consistency_check_identity; // deg 3 or 4
        memory_identity += ram_timestamp_check_identity * (q_4.to_owned() * q_1); // deg 4
        memory_identity += memory_record_check * (q_m.to_owned() * q_1); // deg 4 ( = deg 4 + (deg 3 or deg 4))

        // (deg 4) + (deg 4) + (deg 3)
        memory_identity *= &q_memory_by_scaling; // deg 5
        memory_identity += ram_consistency_check_identity; // deg 5 ( = deg 5 + (deg 3 or deg 5))

        univariate_accumulator.r0 += memory_identity; // deg 5
    }
}
