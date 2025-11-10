use super::Relation;
use crate::honk_verifier::verifier_relations::VerifyAccGetter;
use crate::impl_relation_evals;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::field_ct::FieldCT;
use ark_ff::One;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

#[derive(Clone, Debug)]
pub(crate) struct MemoryRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
    pub(crate) r4: FieldCT<F>,
    pub(crate) r5: FieldCT<F>,
}

impl_relation_evals!(MemoryRelationEvals, r0, r1, r2, r3, r4, r5);
pub(crate) struct MemoryRelation;

impl MemoryRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for MemoryRelation {
    type VerifyAcc = MemoryRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
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
        let tmp1 = w_2.to_owned().multiply(eta_two, builder, driver)?;
        let tmp2 = w_1.to_owned().multiply(eta, builder, driver)?;
        let partial_record_check = w_3
            .to_owned()
            .multiply(eta_three, builder, driver)?
            .add(&tmp1, builder, driver)
            .add(&tmp2, builder, driver)
            .add(q_c, builder, driver);
        let memory_record_check = partial_record_check.sub(w_4, builder, driver);

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
        let one = FieldCT::from(C::ScalarField::one());
        let neg_index_delta = w_1.to_owned().sub(w_1_shift, builder, driver);
        let index_delta_is_zero = neg_index_delta.add(&one, builder, driver);
        let record_delta = w_4_shift.to_owned().sub(w_4, builder, driver);

        let q_memory_by_scaling = q_memory
            .to_owned()
            .multiply(scaling_factor, builder, driver)?;

        let q_one_by_two = q_1.to_owned().multiply(q_2, builder, driver)?;
        let q_one_by_two_by_memory_by_scaling =
            q_one_by_two.multiply(&q_memory_by_scaling, builder, driver)?;
        let q_3_by_memory_by_scaling =
            q_3.to_owned()
                .multiply(&q_memory_by_scaling, builder, driver)?;
        let rom_consistency_check_identity =
            memory_record_check.multiply(&q_one_by_two, builder, driver)?;

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

        let neg_access_type = partial_record_check.to_owned().sub(w_4, builder, driver);

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta)
        let tmp1 = w_2_shift.to_owned().multiply(eta_two, builder, driver)?;
        let tmp2 = w_1_shift.to_owned().multiply(eta, builder, driver)?;
        let mut neg_next_gate_access_type =
            w_3_shift.to_owned().multiply(eta_three, builder, driver)?;
        neg_next_gate_access_type = neg_next_gate_access_type
            .add(&tmp1, builder, driver)
            .add(&tmp2, builder, driver);
        neg_next_gate_access_type = neg_next_gate_access_type
            .to_owned()
            .sub(w_4_shift, builder, driver);
        let value_delta = w_3_shift.to_owned().sub(w_3, builder, driver);
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
        let timestamp_delta = w_2_shift.to_owned().sub(w_2, builder, driver);
        let lhs = vec![
            neg_index_delta.to_owned(),
            index_delta_is_zero.to_owned(),
            neg_access_type.to_owned(),
            index_delta_is_zero.to_owned(),
            neg_next_gate_access_type.to_owned(),
            index_delta_is_zero.to_owned(),
        ];
        let rhs = vec![
            neg_index_delta.to_owned(),
            record_delta.to_owned(),
            neg_access_type.to_owned(),
            value_delta.to_owned(),
            neg_next_gate_access_type.to_owned(),
            timestamp_delta,
        ];

        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;
        let neg_index_delta_sqr = &mul[0];
        let adjacent_values_match_if_adjacent_indices_match = &mul[1]; // index_delta_is_zero * record_delta 
        let neg_access_type_sqr = &mul[2];
        let index_delta_is_zero_by_value_delta = &mul[3];
        let neg_next_gate_access_type_sqr = &mul[4];
        let index_delta_is_zero_by_timestamp_delta = &mul[5];

        let access_check = neg_access_type_sqr.add(&neg_access_type, builder, driver);

        let index_is_monotonically_increasing =
            neg_index_delta_sqr.add(&neg_index_delta, builder, driver); // check if next index minus current index is
        // 0 or 1. deg 2

        let tmp = adjacent_values_match_if_adjacent_indices_match.multiply(
            &q_one_by_two_by_memory_by_scaling,
            builder,
            driver,
        )?;
        accumulator.r1 = accumulator.r1.add(&tmp, builder, driver);

        let tmp = index_is_monotonically_increasing.multiply(
            &q_one_by_two_by_memory_by_scaling,
            builder,
            driver,
        )?;
        accumulator.r2 = accumulator.r2.add(&tmp, builder, driver);

        let tmp = index_is_monotonically_increasing.multiply(
            &q_3_by_memory_by_scaling,
            builder,
            driver,
        )?;
        accumulator.r4 = accumulator.r4.add(&tmp, builder, driver);

        let ram_timestamp_check_identity =
            index_delta_is_zero_by_timestamp_delta.sub(w_3, builder, driver);

        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            index_delta_is_zero_by_value_delta.multiply(
                &neg_next_gate_access_type.add(&one, builder, driver),
                builder,
                driver,
            )?; // deg 3 or 4

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        let next_gate_access_type_is_boolean = neg_next_gate_access_type_sqr.to_owned().add(
            &neg_next_gate_access_type,
            builder,
            driver,
        );

        // Putting it all together...
        let tmp = q_3_by_memory_by_scaling.multiply(
            &adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation,
            builder,
            driver,
        )?;
        accumulator.r3 = accumulator.r3.add(&tmp, builder, driver);

        let tmp = q_3_by_memory_by_scaling.multiply(
            &next_gate_access_type_is_boolean,
            builder,
            driver,
        )?;
        accumulator.r5 = accumulator.r5.add(&tmp, builder, driver);

        let ram_consistency_check_identity =
            q_3_by_memory_by_scaling.multiply(&access_check, builder, driver)?;

        /*
         * The complete RAM/ROM memory identity
         * Partial degree:
         */
        let q_4_by_q_1 = q_4.to_owned().multiply(q_1, builder, driver)?;
        let q_m_by_q_1 = q_m.to_owned().multiply(q_1, builder, driver)?;
        let memory_identity = rom_consistency_check_identity
            .add(
                &q_4_by_q_1.multiply(&ram_timestamp_check_identity, builder, driver)?,
                builder,
                driver,
            )
            .add(
                &q_m_by_q_1.multiply(&memory_record_check, builder, driver)?,
                builder,
                driver,
            )
            .multiply(&q_memory_by_scaling, builder, driver)?
            .add(&ram_consistency_check_identity, builder, driver);
        accumulator.r0 = accumulator.r0.add(&memory_identity, builder, driver);

        Ok(())
    }
}
