use crate::impl_relation_evals;
use crate::verifier_relations::VerifyAccGetter;

use super::Relation;
use ark_ff::One;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::prelude::GenericUltraCircuitBuilder;
use co_builder::types::field_ct::FieldCT;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::types::AllEntities;
use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub(crate) struct AuxiliaryRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
    pub(crate) r4: FieldCT<F>,
    pub(crate) r5: FieldCT<F>,
}

impl_relation_evals!(AuxiliaryRelationEvals, r0, r1, r2, r3, r4, r5);
pub(crate) struct AuxiliaryRelation;

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for AuxiliaryRelation {
    type VerifyAcc = AuxiliaryRelationEvals<C::ScalarField>;

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
        let q_arith = input.precomputed.q_arith();
        let q_aux = input.precomputed.q_aux();

        let limb_size =
            FieldCT::from_witness(C::ScalarField::from(BigUint::one() << 68).into(), builder);
        let sublimb_shift = FieldCT::from_witness(C::ScalarField::from(1u64 << 14).into(), builder);

        /*
         * Non native field arithmetic gate 2
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         **/

        let lhs = vec![
            w_1.clone(),
            w_2.clone(),
            w_1.clone(),
            w_2.clone(),
            w_1_shift.clone(),
        ];
        let rhs = vec![
            w_2_shift.clone(),
            w_1_shift.clone(),
            w_4.clone(),
            w_3.clone(),
            w_2_shift.clone(),
        ];
        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        let mut limb_subproduct = mul[0].add(&mul[1], builder, driver);
        let non_native_field_gate_2 = mul[2]
            .add(&mul[3], builder, driver)
            .sub(w_3_shift, builder, driver)
            .multiply(&limb_size, builder, driver)?
            .sub(w_4_shift, builder, driver)
            .add(&limb_subproduct, builder, driver)
            .multiply(q_4, builder, driver)?;

        limb_subproduct = limb_subproduct
            .multiply(&limb_size, builder, driver)?
            .add(&mul[4], builder, driver);

        let non_native_field_gate_1 = limb_subproduct
            .sub(w_3, builder, driver)
            .sub(w_4, builder, driver)
            .multiply(q_3, builder, driver)?;

        let non_native_field_gate_3 = limb_subproduct
            .add(w_4, builder, driver)
            .sub(w_3_shift, builder, driver)
            .sub(w_4_shift, builder, driver)
            .multiply(q_m, builder, driver)?;

        let non_native_field_identity = non_native_field_gate_1
            .add(&non_native_field_gate_2, builder, driver)
            .add(&non_native_field_gate_3, builder, driver)
            .multiply(q_2, builder, driver)?;

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
        let limb_accumulator_1 = w_2_shift
            .to_owned()
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_1_shift, builder, driver)
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_3, builder, driver)
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_2, builder, driver)
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_1, builder, driver)
            .sub(w_4, builder, driver)
            .multiply(q_4, builder, driver)?;

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
        let limb_accumulator_2 = w_3_shift
            .to_owned()
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_2_shift, builder, driver)
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_1_shift, builder, driver)
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_4, builder, driver)
            .multiply(&sublimb_shift, builder, driver)?
            .add(w_3, builder, driver)
            .sub(w_4_shift, builder, driver)
            .multiply(q_m, builder, driver)?;

        let limb_accumulator_identity = limb_accumulator_1
            .add(&limb_accumulator_2, builder, driver)
            .multiply(q_3, builder, driver)?;

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
         *
         * A ROM/ROM access gate can be evaluated with the identity:
         *
         * qc + w1 \eta + w2 η₂ + w3 η₃ - w4 = 0
         *
         * For ROM gates, qc = 0
         */
        let tmp1 = w_2.to_owned().multiply(eta_two, builder, driver)?;
        let tmp2 = w_1.to_owned().multiply(eta, builder, driver)?;
        let partial_record_check = w_3
            .to_owned()
            .multiply(eta_three, builder, driver)?
            .add(&tmp1, builder, driver)
            .add(&tmp2, builder, driver)
            .add(q_c, builder, driver);
        let mut memory_record_check = partial_record_check.sub(w_4, builder, driver);

        /*
         * ROM Consistency Check
         *
         * For every ROM read, a set equivalence check is applied between the record witnesses, and a second set of
         * records that are sorted.
         *
         * We apply the following checks for the sorted records:
         *
         * 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
         * 2. index values for adjacent records are monotonically increasing
         * 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
         *
         */
        let index_delta = w_1_shift.to_owned().sub(w_1, builder, driver);
        let record_delta = w_4_shift.to_owned().sub(w_4, builder, driver);

        let index_delta_one = index_delta.neg().add(
            &FieldCT::from_witness(C::ScalarField::one().into(), builder),
            builder,
            driver,
        );

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
        // RAM Consistency Check

        let access_type = w_4.to_owned().sub(&partial_record_check, builder, driver);
        let value_delta = w_3_shift.to_owned().sub(w_3, builder, driver);
        let lhs = vec![
            index_delta.to_owned(),
            record_delta.to_owned(),
            access_type.to_owned(),
            value_delta,
        ];
        let rhs = vec![
            index_delta.to_owned(),
            index_delta_one.to_owned(),
            access_type.to_owned(),
            index_delta_one.to_owned(),
        ];

        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;
        let index_is_monotonically_increasing = mul[0].sub(&index_delta, builder, driver);
        let adjacent_values_match_if_adjacent_indices_match = &mul[1];
        let q_aux_by_scaling = q_aux.to_owned().multiply(scaling_factor, builder, driver)?;

        let q_one_by_two = q_1.to_owned().multiply(q_2, builder, driver)?;
        let q_one_by_two_by_aux_by_scaling =
            q_one_by_two.multiply(&q_aux_by_scaling, builder, driver)?;

        let tmp = adjacent_values_match_if_adjacent_indices_match.multiply(
            &q_one_by_two_by_aux_by_scaling,
            builder,
            driver,
        )?;
        accumulator.r1 = accumulator.r1.add(&tmp, builder, driver);

        let tmp = index_is_monotonically_increasing.multiply(
            &q_one_by_two_by_aux_by_scaling,
            builder,
            driver,
        )?;
        accumulator.r2 = accumulator.r2.add(&tmp, builder, driver);

        let rom_consistency_check_identity =
            memory_record_check.multiply(&q_one_by_two, builder, driver)?;

        // Continue with RAM access check
        let mut ram_consistency_check_identity = mul[2].sub(&access_type, builder, driver);

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta)
        let tmp1 = w_2_shift.to_owned().multiply(eta_two, builder, driver)?;
        let tmp2 = w_1_shift.to_owned().multiply(eta, builder, driver)?;
        let mut next_gate_access_type =
            w_3_shift.to_owned().multiply(eta_three, builder, driver)?;
        next_gate_access_type = next_gate_access_type
            .add(&tmp1, builder, driver)
            .add(&tmp2, builder, driver);
        let next_gate_access_type =
            w_4_shift
                .to_owned()
                .sub(&next_gate_access_type, builder, driver);

        let mut tmp = next_gate_access_type.to_owned().neg();
        tmp = tmp.add(
            &FieldCT::from_witness(C::ScalarField::one().into(), builder),
            builder,
            driver,
        );

        let timestamp_delta = w_2_shift.to_owned().sub(w_2, builder, driver);
        let lhs = vec![
            mul[3].to_owned(),
            next_gate_access_type.to_owned(),
            index_delta_one.to_owned(),
        ];
        let rhs = vec![
            tmp.to_owned(),
            next_gate_access_type.to_owned(),
            timestamp_delta,
        ];

        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            &mul[0];

        // Next gate's access type is boolean
        let next_gate_access_type_is_boolean = mul[1].sub(&next_gate_access_type, builder, driver);
        let q_arith_by_aux_and_scaling =
            q_arith
                .to_owned()
                .multiply(&q_aux_by_scaling, builder, driver)?;
        let tmp =
            adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
                .multiply(&q_arith_by_aux_and_scaling, builder, driver)?;

        accumulator.r3 = accumulator.r3.add(&tmp, builder, driver);

        let tmp = index_is_monotonically_increasing.multiply(
            &q_arith_by_aux_and_scaling,
            builder,
            driver,
        )?;
        accumulator.r4 = accumulator.r4.add(&tmp, builder, driver);

        let tmp = next_gate_access_type_is_boolean.multiply(
            &q_arith_by_aux_and_scaling,
            builder,
            driver,
        )?;
        accumulator.r5 = accumulator.r5.add(&tmp, builder, driver);

        ram_consistency_check_identity =
            ram_consistency_check_identity.multiply(q_arith, builder, driver)?;

        // RAM Timestamp Consistency Check
        let mut ram_timestamp_check_identity = mul[2].sub(w_3, builder, driver);

        // The complete RAM/ROM memory identity
        let q_4_q_1 = q_4.to_owned().multiply(q_1, builder, driver)?;
        let q_m_q_1 = q_m.to_owned().multiply(q_1, builder, driver)?;
        ram_timestamp_check_identity =
            ram_timestamp_check_identity.multiply(&q_4_q_1, builder, driver)?;
        memory_record_check = memory_record_check.multiply(&q_m_q_1, builder, driver)?;
        let memory_identity = rom_consistency_check_identity
            .add(&ram_timestamp_check_identity, builder, driver)
            .add(&memory_record_check, builder, driver)
            .add(&ram_consistency_check_identity, builder, driver)
            .add(&non_native_field_identity, builder, driver)
            .add(&limb_accumulator_identity, builder, driver)
            .multiply(&q_aux_by_scaling, builder, driver)?;

        accumulator.r0 = accumulator.r0.add(&memory_identity, builder, driver);
        Ok(())
    }
}
