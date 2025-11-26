use super::{ProverUnivariatesBatch, Relation};
use crate::co_decider::{relations::fold_accumulator, univariates::SharedUnivariate};
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::Zero;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
};
use itertools::Itertools as _;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct MemoryRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 6>,
    pub(crate) r2: SharedUnivariate<T, P, 6>,
    pub(crate) r3: SharedUnivariate<T, P, 6>,
    pub(crate) r4: SharedUnivariate<T, P, 6>,
    pub(crate) r5: SharedUnivariate<T, P, 6>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for MemoryRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
            r1: Default::default(),
            r2: Default::default(),
            r3: Default::default(),
            r4: Default::default(),
            r5: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> MemoryRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == MemoryRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
        self.r2.scale_inplace(elements[2]);
        self.r3.scale_inplace(elements[3]);
        self.r4.scale_inplace(elements[4]);
        self.r5.scale_inplace(elements[5]);
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

pub(crate) struct MemoryRelation {}

impl MemoryRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 7;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for MemoryRelation
{
    type Acc = MemoryRelationAcc<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P>) -> bool {
        entity.precomputed.q_memory().is_zero()
    }

    fn add_entites(
        entity: &super::ProverUnivariates<T, P>,
        batch: &mut ProverUnivariatesBatch<T, P>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_q_l(entity);
        batch.add_q_r(entity);
        batch.add_q_o(entity);
        batch.add_q_4(entity);
        batch.add_q_m(entity);
        batch.add_q_c(entity);
        batch.add_q_memory(entity);
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
    fn accumulate<N: Network>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let id = state.id();

        let eta = relation_parameters.eta_1;
        let eta_two = relation_parameters.eta_2;
        let eta_three = relation_parameters.eta_3;

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
        let mut memory_record_check = T::scale_many(w_3, eta_three);
        T::add_assign_many(&mut memory_record_check, &T::scale_many(w_2, eta_two));
        T::add_assign_many(&mut memory_record_check, &T::scale_many(w_1, eta));
        T::add_assign_public_many(&mut memory_record_check, q_c, id);
        let partial_record_check = memory_record_check.to_owned(); // used later in RAM consistency check
        T::sub_assign_many(&mut memory_record_check, w_4);

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
        let neg_index_delta = T::sub_many(w_1, w_1_shift);
        let index_delta_is_zero = T::add_scalar(&neg_index_delta, P::ScalarField::one(), id); // deg 1
        let record_delta = T::sub_many(w_4_shift, w_4);

        let capacity = neg_index_delta.len() * 6;
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(neg_index_delta.clone());
        rhs.extend(neg_index_delta.clone());
        lhs.extend(index_delta_is_zero.clone());
        rhs.extend(record_delta);

        let q_memory_by_scaling = scaling_factors
            .iter()
            .zip_eq(q_memory.iter())
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>();
        // deg 1
        let q_one_by_two = q_1
            .iter()
            .zip_eq(q_2.iter())
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>(); // deg 2
        let q_one_by_two_by_memory_by_scaling = q_one_by_two
            .iter()
            .zip_eq(q_memory_by_scaling.iter())
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>(); // deg 3
        let q_3_by_memory_and_scaling = q_3
            .iter()
            .zip_eq(q_memory_by_scaling.iter())
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>();

        let rom_consistency_check_identity =
            T::mul_with_public_many(&q_one_by_two, &memory_record_check); // deg 3 or 4

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
        let neg_access_type = T::sub_many(&partial_record_check, w_4); // will be 0 or 1 for honest Prover; deg 1 or 2

        lhs.extend(neg_access_type.clone());
        rhs.extend(neg_access_type.clone());

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta) deg 1 or 2
        let mut neg_next_gate_access_type = T::scale_many(w_3_shift, eta_three);
        T::add_assign_many(
            &mut neg_next_gate_access_type,
            &T::scale_many(w_2_shift, eta_two),
        );
        T::add_assign_many(
            &mut neg_next_gate_access_type,
            &T::scale_many(w_1_shift, eta),
        );
        T::sub_assign_many(&mut neg_next_gate_access_type, w_4_shift);
        let value_delta = T::sub_many(w_3_shift, w_3);
        lhs.extend(index_delta_is_zero.clone());
        rhs.extend(value_delta);
        lhs.extend(neg_next_gate_access_type.clone());
        rhs.extend(neg_next_gate_access_type.clone());

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
        let timestamp_delta = T::sub_many(w_2_shift, w_2); // deg 1
        lhs.extend(index_delta_is_zero);
        rhs.extend(timestamp_delta);

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 6).collect_vec();
        debug_assert_eq!(mul.len(), 6);

        let neg_index_delta_sqr = mul[0];
        let adjacent_values_match_if_adjacent_indices_match = mul[1]; // index_delta_is_zero * record_delta 
        let neg_access_type_sqr = mul[2];
        let index_delta_is_zero_by_value_delta = mul[3];
        let neg_next_gate_access_type_sqr = mul[4];
        let index_delta_is_zero_by_timestamp_delta = mul[5];

        let access_check = T::add_many(neg_access_type_sqr, &neg_access_type); // check value is 0 or 1; deg 2 or 4

        let index_is_monotonically_increasing = T::add_many(neg_index_delta_sqr, &neg_index_delta); // check if next index minus current index is
        // 0 or 1. deg 2

        let tmp = T::mul_with_public_many(
            &q_one_by_two_by_memory_by_scaling,
            adjacent_values_match_if_adjacent_indices_match,
        ); // deg 5
        fold_accumulator!(univariate_accumulator.r1, tmp);

        let tmp = T::mul_with_public_many(
            &q_one_by_two_by_memory_by_scaling,
            &index_is_monotonically_increasing,
        ); // deg 5
        fold_accumulator!(univariate_accumulator.r2, tmp);

        let tmp = T::mul_with_public_many(
            &q_3_by_memory_and_scaling,
            &index_is_monotonically_increasing,
        ); // deg 4
        fold_accumulator!(univariate_accumulator.r4, tmp);

        let ram_timestamp_check_identity = T::sub_many(index_delta_is_zero_by_timestamp_delta, w_3); // deg 2

        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            T::mul_many(
                index_delta_is_zero_by_value_delta,
                &T::add_scalar(&neg_next_gate_access_type, P::ScalarField::one(), id),
                net,
                state,
            )?; // deg 3 or 4

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        let next_gate_access_type_is_boolean =
            T::add_many(neg_next_gate_access_type_sqr, &neg_next_gate_access_type);

        // Putting it all together...
        let tmp = T::mul_with_public_many(
            &q_3_by_memory_and_scaling,
            &adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation,
        ); // deg 5 or 6
        fold_accumulator!(univariate_accumulator.r3, tmp);

        let tmp = T::mul_with_public_many(
            &q_3_by_memory_and_scaling,
            &next_gate_access_type_is_boolean,
        ); // deg 4 or 6
        fold_accumulator!(univariate_accumulator.r5, tmp);

        let ram_consistency_check_identity =
            T::mul_with_public_many(&q_3_by_memory_and_scaling, &access_check); // deg 3 or 5

        /*
         * The complete RAM/ROM memory identity
         * Partial degree:
         */
        let q_4_by_q_1 = q_4
            .iter()
            .zip_eq(q_1.iter())
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>();
        let q_m_by_q_1 = q_m
            .iter()
            .zip_eq(q_1.iter())
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>();
        let mut memory_identity = rom_consistency_check_identity; // deg 3 or 4
        T::add_assign_many(
            &mut memory_identity,
            &T::mul_with_public_many(&q_4_by_q_1, &ram_timestamp_check_identity),
        ); // deg 4
        T::add_assign_many(
            &mut memory_identity,
            &T::mul_with_public_many(&q_m_by_q_1, &memory_record_check),
        ); // deg 4 ( = deg 4 + (deg 3 or deg 4))

        // (deg 4) + (deg 4) + (deg 3)
        T::mul_assign_with_public_many(&mut memory_identity, &q_memory_by_scaling); // deg 5
        T::add_assign_many(&mut memory_identity, &ram_consistency_check_identity); // deg 5 ( = deg 5 + (deg 3 or deg 5))

        fold_accumulator!(univariate_accumulator.r0, memory_identity); // deg 5
        Ok(())
    }
}
