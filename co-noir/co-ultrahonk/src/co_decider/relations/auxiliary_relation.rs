use super::Relation;
use crate::{
    co_decider::{
        types::{ProverUnivariates, RelationParameters, MAX_PARTIAL_RELATION_LENGTH},
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
};
use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use co_builder::prelude::HonkCurve;
use co_builder::HonkProofResult;
use itertools::Itertools as _;
use num_bigint::BigUint;
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

/**
 * AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): Investigate optimizations.
 * It seems that we could have:
 *     static constexpr std::array<size_t, 6> SUBRELATION_PARTIAL_LENGTHS{
 *     5 // auxiliary sub-relation;
 *     6 // ROM consistency sub-relation 1
 *     6 // ROM consistency sub-relation 2
 *     6 // RAM consistency sub-relation 1
 *     5 // RAM consistency sub-relation 2
 *     5 // RAM consistency sub-relation 3
 * };
 */
#[derive(Clone, Debug)]
pub(crate) struct AuxiliaryRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
    pub(crate) r1: SharedUnivariate<T, P, 6>,
    pub(crate) r2: SharedUnivariate<T, P, 6>,
    pub(crate) r3: SharedUnivariate<T, P, 6>,
    pub(crate) r4: SharedUnivariate<T, P, 6>,
    pub(crate) r5: SharedUnivariate<T, P, 6>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for AuxiliaryRelationAcc<T, P> {
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

impl<T: NoirUltraHonkProver<P>, P: Pairing> AuxiliaryRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == AuxiliaryRelation::NUM_RELATIONS);
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

pub(crate) struct AuxiliaryRelation {}

impl AuxiliaryRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 12;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for AuxiliaryRelation
{
    type Acc = AuxiliaryRelationAcc<T, P>;
    const SKIPPABLE: bool = false;

    fn skip(input: &ProverUnivariates<T, P>) -> bool {
        <Self as Relation<T, P>>::check_skippable();
        input.precomputed.q_aux().is_zero()
    }

    /**
     * @brief Expression for the generalized permutation sort gate.
     * @details The following explanation is reproduced from the Plonk analog 'plookup_auxiliary_widget':
     * Adds contributions for identities associated with several custom gates:
     *  * RAM/ROM read-write consistency check
     *  * RAM timestamp difference consistency check
     *  * RAM/ROM index difference consistency check
     *  * Bigfield product evaluation (3 in total)
     *  * Bigfield limb accumulation (2 in total)
     *
     * Multiple selectors are used to 'switch' aux gates on/off according to the following pattern:
     *
     * | gate type                    | q_aux | q_1 | q_2 | q_3 | q_4 | q_m | q_c | q_arith |
     * | ---------------------------- | ----- | --- | --- | --- | --- | --- | --- | ------  |
     * | Bigfield Limb Accumulation 1 | 1     | 0   | 0   | 1   | 1   | 0   | --- | 0       |
     * | Bigfield Limb Accumulation 2 | 1     | 0   | 0   | 1   | 0   | 1   | --- | 0       |
     * | Bigfield Product 1           | 1     | 0   | 1   | 1   | 0   | 0   | --- | 0       |
     * | Bigfield Product 2           | 1     | 0   | 1   | 0   | 1   | 0   | --- | 0       |
     * | Bigfield Product 3           | 1     | 0   | 1   | 0   | 0   | 1   | --- | 0       |
     * | RAM/ROM access gate          | 1     | 1   | 0   | 0   | 0   | 1   | --- | 0       |
     * | RAM timestamp check          | 1     | 1   | 0   | 0   | 1   | 0   | --- | 0       |
     * | ROM consistency check        | 1     | 1   | 1   | 0   | 0   | 0   | --- | 0       |
     * | RAM consistency check        | 1     | 0   | 0   | 0   | 0   | 0   | 0   | 1       |
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
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate AuxiliaryRelation");
        let party_id = driver.get_party_id();

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

        let limb_size = P::ScalarField::from(BigUint::one() << 68);
        let sublimb_shift = P::ScalarField::from(1u64 << 14);

        /*
         * Non native field arithmetic gate 2
         * deg 4
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         **/

        let lhs = SharedUnivariate::univariates_to_vec(&[
            w_1.to_owned(),
            w_2.to_owned(),
            w_1.to_owned(),
            w_2.to_owned(),
            w_1_shift.to_owned(),
        ]);
        let rhs = SharedUnivariate::univariates_to_vec(&[
            w_2_shift.to_owned(),
            w_1_shift.to_owned(),
            w_4.to_owned(),
            w_3.to_owned(),
            w_2_shift.to_owned(),
        ]);
        let mul = driver.mul_many(&lhs, &rhs)?;
        let mul = SharedUnivariate::vec_to_univariates(&mul);

        let mut limb_subproduct = mul[0].add(&mul[1]);
        let tmp = mul[2].add(&mul[3]);
        let mut non_native_field_gate_2 = tmp.sub(w_3_shift);
        non_native_field_gate_2.scale_inplace(limb_size);
        let non_native_field_gate_2 = non_native_field_gate_2
            .sub(w_4_shift)
            .add(&limb_subproduct)
            .mul_public(q_4);

        limb_subproduct.scale_inplace(limb_size);
        let limb_subproduct = limb_subproduct.add(&mul[4]);
        let non_native_field_gate_1 = limb_subproduct.sub(w_3).sub(w_4).mul_public(q_3);

        let non_native_field_gate_3 = limb_subproduct
            .add(w_4)
            .sub(w_3_shift)
            .sub(w_4_shift)
            .mul_public(q_m);

        let non_native_field_identity = non_native_field_gate_1
            .add(&non_native_field_gate_2)
            .add(&non_native_field_gate_3)
            .mul_public(q_2);

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
        // deg 2

        let mut limb_accumulator_1 = w_2_shift.scale(sublimb_shift).add(w_1_shift);
        limb_accumulator_1.scale_inplace(sublimb_shift);
        let mut limb_accumulator_1 = limb_accumulator_1.add(w_3);
        limb_accumulator_1.scale_inplace(sublimb_shift);
        let mut limb_accumulator_1 = limb_accumulator_1.add(w_2);
        limb_accumulator_1.scale_inplace(sublimb_shift);
        let limb_accumulator_1 = limb_accumulator_1.add(w_1).sub(w_4).mul_public(q_4);

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
        // deg 2
        let mut limb_accumulator_2 = w_3_shift.scale(sublimb_shift).add(w_2_shift);
        limb_accumulator_2.scale_inplace(sublimb_shift);
        let mut limb_accumulator_2 = limb_accumulator_2.add(w_1_shift);
        limb_accumulator_2.scale_inplace(sublimb_shift);
        let mut limb_accumulator_2 = limb_accumulator_2.add(w_4);
        limb_accumulator_2.scale_inplace(sublimb_shift);
        let limb_accumulator_2 = limb_accumulator_2.add(w_3).sub(w_4_shift).mul_public(q_m);

        let limb_accumulator_identity = limb_accumulator_1.add(&limb_accumulator_2).mul_public(q_3); // deg 3

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
         * A ROM/ROM access gate can be evaluated with the identity:
         *
         * qc + w1 \eta + w2 η₂ + w3 η₃ - w4 = 0
         *
         * For ROM gates, qc = 0
         */
        let tmp1 = w_2.scale(*eta_two);
        let tmp2 = w_1.scale(*eta);
        let memory_record_check = w_3
            .scale(*eta_three)
            .add(&tmp1)
            .add(&tmp2)
            .add_public(q_c, party_id);
        let partial_record_check = memory_record_check.to_owned(); // used in RAM consistency check; deg 1 or 2
        let memory_record_check = memory_record_check.sub(w_4);

        /*
         * ROM Consistency Check
         * Partial degree: 1
         * Total degree: 4
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
        let index_delta = w_1_shift.sub(w_1);
        let record_delta = w_4_shift.sub(w_4);

        let index_delta_one = index_delta
            .neg()
            .add_scalar(P::ScalarField::one(), party_id);

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
        let access_type = w_4.sub(&partial_record_check); // deg 1 or 2

        let value_delta = w_3_shift.sub(w_3);

        let lhs = SharedUnivariate::univariates_to_vec(&[
            index_delta.to_owned(),
            record_delta,
            access_type.to_owned(),
            value_delta,
        ]);
        let rhs = SharedUnivariate::univariates_to_vec(&[
            index_delta.to_owned(),
            index_delta_one.to_owned(),
            access_type.to_owned(),
            index_delta_one.to_owned(),
        ]);
        let mul = driver.mul_many(&lhs, &rhs)?;
        let mul = SharedUnivariate::vec_to_univariates(&mul);

        let index_is_monotonically_increasing = mul[0].sub(&index_delta); // deg 2
        let adjacent_values_match_if_adjacent_indices_match = &mul[1]; // deg 2

        let q_aux_by_scaling = q_aux.to_owned() * scaling_factor;
        let q_one_by_two = q_1.to_owned() * q_2;
        let q_one_by_two_by_aux_by_scaling = q_one_by_two.to_owned() * &q_aux_by_scaling;

        let tmp = adjacent_values_match_if_adjacent_indices_match
            .mul_public(&q_one_by_two_by_aux_by_scaling); // deg 5
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] =
                T::add(univariate_accumulator.r1.evaluations[i], tmp.evaluations[i]);
        }

        let tmp = index_is_monotonically_increasing.mul_public(&q_one_by_two_by_aux_by_scaling); // deg 5
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] =
                T::add(univariate_accumulator.r2.evaluations[i], tmp.evaluations[i]);
        }

        let rom_consistency_check_identity = memory_record_check.mul_public(&q_one_by_two); // deg 3 or 4

        // Continue with RAM access check

        let access_check = &mul[2].sub(&access_type); // check value is 0 or 1; deg 2 or 4

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta) deg 1 or 2
        let tmp1 = w_2_shift.scale(*eta_two);
        let tmp2 = w_1_shift.scale(*eta);
        let next_gate_access_type = w_3_shift.scale(*eta_three).add(&tmp1).add(&tmp2);
        let next_gate_access_type = w_4_shift.sub(&next_gate_access_type);

        let tmp = next_gate_access_type
            .neg()
            .add_scalar(P::ScalarField::one(), party_id); // deg 3 or 4

        let timestamp_delta = w_2_shift.sub(w_2);

        let lhs = SharedUnivariate::univariates_to_vec(&[
            mul[3].to_owned(),
            next_gate_access_type.to_owned(),
            index_delta_one,
        ]);
        let rhs = SharedUnivariate::univariates_to_vec(&[
            tmp,
            next_gate_access_type.to_owned(),
            timestamp_delta,
        ]);
        let mul = driver.mul_many(&lhs, &rhs)?;
        let mul = SharedUnivariate::vec_to_univariates(&mul);

        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            &mul[0];

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        let next_gate_access_type_is_boolean = mul[1].sub(&next_gate_access_type);

        let q_arith_by_aux_and_scaling = q_arith.to_owned() * &q_aux_by_scaling;
        // Putting it all together...

        let tmp =
            adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
                .mul_public(&q_arith_by_aux_and_scaling); // deg 5 or 6
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] =
                T::add(univariate_accumulator.r3.evaluations[i], tmp.evaluations[i]);
        }

        let tmp = index_is_monotonically_increasing.mul_public(&q_arith_by_aux_and_scaling); // deg 4
        for i in 0..univariate_accumulator.r4.evaluations.len() {
            univariate_accumulator.r4.evaluations[i] =
                T::add(univariate_accumulator.r4.evaluations[i], tmp.evaluations[i]);
        }

        let tmp = next_gate_access_type_is_boolean.mul_public(&q_arith_by_aux_and_scaling); // deg 4 or 6
        for i in 0..univariate_accumulator.r5.evaluations.len() {
            univariate_accumulator.r5.evaluations[i] =
                T::add(univariate_accumulator.r5.evaluations[i], tmp.evaluations[i]);
        }

        let ram_consistency_check_identity = access_check.mul_public(q_arith); // deg 3 or 5

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
        let ram_timestamp_check_identity = &mul[2].sub(w_3); // deg 3

        /*
         * The complete RAM/ROM memory identity
         * Partial degree:
         */
        let tmp1 = ram_timestamp_check_identity.mul_public(&(q_4.to_owned() * q_1));
        let tmp2 = memory_record_check.mul_public(&(q_m.to_owned() * q_1));
        let memory_identity = rom_consistency_check_identity // deg 3 or 4
            .add(&tmp1) // deg_4
            .add(&tmp2) // deg 3 or 4
            .add(&ram_consistency_check_identity); // deg 3 or 5
                                                   //

        // (deg 3 or 5) + (deg 4) + (deg 3)
        let tmp = memory_identity.add(&non_native_field_identity);
        let auxiliary_identity = tmp
            .add(&limb_accumulator_identity)
            .mul_public(&q_aux_by_scaling); // deg 5 or 6
                                            //

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] = T::add(
                univariate_accumulator.r0.evaluations[i],
                auxiliary_identity.evaluations[i],
            );
        }

        Ok(())
    }

    fn accumulate_batch(
        driver: &mut T,
        univariate_accumulator: &mut Self::Acc,
        input: &super::ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        let party_id = driver.get_party_id();

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

        let limb_size = P::ScalarField::from(BigUint::one() << 68);
        let sublimb_shift = P::ScalarField::from(1u64 << 14);

        /*
         * Non native field arithmetic gate 2
         * deg 4
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         **/

        let mut lhs =
            Vec::with_capacity(w_1.len() + w_2.len() + w_1.len() + w_2.len() + w_1_shift.len());
        lhs.extend(w_1);
        lhs.extend(w_2);
        lhs.extend(w_1);
        lhs.extend(w_2);
        lhs.extend(w_1_shift);
        let mut rhs = Vec::with_capacity(lhs.len());
        rhs.extend(w_2_shift);
        rhs.extend(w_1_shift);
        rhs.extend(w_4);
        rhs.extend(w_3);
        rhs.extend(w_2_shift);
        let mul = driver.mul_many(&lhs, &rhs)?;
        let mul = mul.chunks_exact(mul.len() / 5).collect_vec();
        debug_assert_eq!(mul.len(), 5);

        let mut limb_subproduct = T::add_many(mul[0], mul[1]);
        let mut non_native_field_gate_2 = T::add_many(mul[2], mul[3]);
        T::sub_assign_many(&mut non_native_field_gate_2, w_3_shift);
        T::scale_many_in_place(&mut non_native_field_gate_2, limb_size);
        T::sub_assign_many(&mut non_native_field_gate_2, w_4_shift);
        T::add_assign_many(&mut non_native_field_gate_2, &limb_subproduct);
        T::mul_assign_with_public_many(&mut non_native_field_gate_2, q_4);

        T::scale_many_in_place(&mut limb_subproduct, limb_size);
        T::add_assign_many(&mut limb_subproduct, mul[4]);
        let mut non_native_field_gate_1 = T::sub_many(&limb_subproduct, w_3);
        T::sub_assign_many(&mut non_native_field_gate_1, w_4);
        T::mul_assign_with_public_many(&mut non_native_field_gate_1, q_3);

        let mut non_native_field_gate_3 = limb_subproduct;
        T::add_assign_many(&mut non_native_field_gate_3, w_4);
        T::sub_assign_many(&mut non_native_field_gate_3, w_3_shift);
        T::sub_assign_many(&mut non_native_field_gate_3, w_4_shift);
        T::mul_assign_with_public_many(&mut non_native_field_gate_3, q_m);

        let mut non_native_field_identity = non_native_field_gate_1;
        T::add_assign_many(&mut non_native_field_identity, &non_native_field_gate_2);
        T::add_assign_many(&mut non_native_field_identity, &non_native_field_gate_3);
        T::mul_assign_with_public_many(&mut non_native_field_identity, q_2);

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
        // deg 2

        let mut limb_accumulator_1 = w_2_shift.to_owned();
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_1_shift);
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_3);
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_2);
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_1);
        T::sub_assign_many(&mut limb_accumulator_1, w_4);
        T::mul_assign_with_public_many(&mut limb_accumulator_1, q_4);

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
        // deg 2
        let mut limb_accumulator_2 = w_3_shift.to_owned();
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_2_shift);
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_1_shift);
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_4);
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_3);
        T::sub_assign_many(&mut limb_accumulator_2, w_4_shift);
        T::mul_assign_with_public_many(&mut limb_accumulator_2, q_m);

        let mut limb_accumulator_identity = limb_accumulator_1;
        T::add_assign_many(&mut limb_accumulator_identity, &limb_accumulator_2);
        T::mul_assign_with_public_many(&mut limb_accumulator_identity, q_3);

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
         * A ROM/ROM access gate can be evaluated with the identity:
         *
         * qc + w1 \eta + w2 η₂ + w3 η₃ - w4 = 0
         *
         * For ROM gates, qc = 0
         */
        let mut tmp1 = w_2.to_owned();
        let mut tmp2 = w_1.to_owned();
        let mut memory_record_check = w_3.to_owned();
        T::scale_many_in_place(&mut tmp1, *eta_two);
        T::scale_many_in_place(&mut tmp2, *eta);
        T::scale_many_in_place(&mut memory_record_check, *eta_three);
        T::add_assign_many(&mut memory_record_check, &tmp1);
        T::add_assign_many(&mut memory_record_check, &tmp2);
        T::add_assign_public_many(&mut memory_record_check, q_c, party_id);
        let partial_record_check = memory_record_check.clone();
        let mut memory_record_check = T::sub_many(&partial_record_check, w_4);

        /*
         * ROM Consistency Check
         * Partial degree: 1
         * Total degree: 4
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
        let index_delta = T::sub_many(w_1_shift, w_1);
        let record_delta = T::sub_many(w_4_shift, w_4);

        let mut index_delta_one = index_delta.clone();
        T::neg_many(&mut index_delta_one);
        T::add_scalar_in_place(&mut index_delta_one, P::ScalarField::one(), party_id);

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
        let access_type = T::sub_many(w_4, &partial_record_check); // deg 1 or 2
        let value_delta = T::sub_many(w_3_shift, w_3);
        let mut lhs = Vec::with_capacity(
            index_delta_one.len() + record_delta.len() + access_type.len() + value_delta.len(),
        );
        lhs.extend(index_delta.clone());
        lhs.extend(record_delta);
        lhs.extend(access_type.clone());
        lhs.extend(value_delta);

        let mut rhs = Vec::with_capacity(lhs.len());
        rhs.extend(index_delta.clone());
        rhs.extend(index_delta_one.clone());
        rhs.extend(access_type.clone());
        rhs.extend(index_delta_one.clone());

        let mul = driver.mul_many(&lhs, &rhs)?;
        let mul = mul.chunks_exact(mul.len() / 4).collect_vec();
        debug_assert_eq!(mul.len(), 4);
        let index_is_monotonically_increasing = T::sub_many(mul[0], &index_delta); // deg 2
        let adjacent_values_match_if_adjacent_indices_match = &mul[1]; // deg 2
        let q_aux_by_scaling = q_aux
            .iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| *a * *b)
            .collect_vec();

        let q_one_by_two = q_1.iter().zip_eq(q_2).map(|(a, b)| *a * *b).collect_vec();
        let q_one_by_two_by_aux_by_scaling = q_one_by_two
            .iter()
            .zip_eq(q_aux_by_scaling.iter())
            .map(|(a, b)| *a * *b)
            .collect_vec();

        let tmp = T::mul_with_public_many(
            &q_one_by_two_by_aux_by_scaling,
            adjacent_values_match_if_adjacent_indices_match,
        ); // deg 5

        let evaluations_len = univariate_accumulator.r1.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r1
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);

        let tmp = T::mul_with_public_many(
            &q_one_by_two_by_aux_by_scaling,
            &index_is_monotonically_increasing,
        ); // deg 5

        let evaluations_len = univariate_accumulator.r2.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r2
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);

        let rom_consistency_check_identity =
            T::mul_with_public_many(&q_one_by_two, &memory_record_check); // deg 3 or 4

        // Continue with RAM access check

        let mut ram_consistency_check_identity = T::sub_many(mul[2], &access_type); // check value is 0 or 1; deg 2 or 4

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/757): If we sorted in
        // reverse order we could re-use `partial_record_check`  1 -  (w3' * eta_three + w2' * eta_two + w1' *
        // eta) deg 1 or 2
        let mut tmp1 = w_2_shift.to_owned();
        let mut tmp2 = w_1_shift.to_owned();
        T::scale_many_in_place(&mut tmp1, *eta_two);
        T::scale_many_in_place(&mut tmp2, *eta);
        let mut next_gate_access_type = w_3_shift.to_owned();
        T::scale_many_in_place(&mut next_gate_access_type, *eta_three);
        T::add_assign_many(&mut next_gate_access_type, &tmp1);
        T::add_assign_many(&mut next_gate_access_type, &tmp2);
        let next_gate_access_type = T::sub_many(w_4_shift, &next_gate_access_type);
        let mut tmp = next_gate_access_type.clone();
        T::neg_many(&mut tmp);
        T::add_scalar_in_place(&mut tmp, P::ScalarField::one(), party_id);

        let timestamp_delta = T::sub_many(w_2_shift, w_2);
        let mut lhs =
            Vec::with_capacity(mul[3].len() + next_gate_access_type.len() + index_delta_one.len());
        lhs.extend(mul[3]);
        lhs.extend(next_gate_access_type.to_owned());
        lhs.extend(index_delta_one);

        let mut rhs = Vec::with_capacity(lhs.len());
        rhs.extend(tmp);
        rhs.extend(next_gate_access_type.clone());
        rhs.extend(timestamp_delta);

        let mul = driver.mul_many(&lhs, &rhs)?;
        let mul = mul.chunks_exact(mul.len() / 3).collect_vec();
        debug_assert_eq!(mul.len(), 3);

        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            &mul[0];

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        let next_gate_access_type_is_boolean = T::sub_many(mul[1], &next_gate_access_type);
        let q_arith_by_aux_and_scaling = q_arith
            .iter()
            .zip_eq(q_aux_by_scaling.iter())
            .map(|(a, b)| *a * *b)
            .collect_vec();
        let tmp = T::mul_with_public_many(
            &q_arith_by_aux_and_scaling,
            adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation,
        );

        let evaluations_len = univariate_accumulator.r3.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r3
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);

        let tmp = T::mul_with_public_many(
            &q_arith_by_aux_and_scaling,
            &index_is_monotonically_increasing,
        );

        let evaluations_len = univariate_accumulator.r4.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r4
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);

        let tmp = T::mul_with_public_many(
            &q_arith_by_aux_and_scaling,
            &next_gate_access_type_is_boolean,
        );

        let evaluations_len = univariate_accumulator.r5.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in tmp.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r5
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);

        T::mul_assign_with_public_many(&mut ram_consistency_check_identity, q_arith);
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
        let mut ram_timestamp_check_identity = T::sub_many(mul[2], w_3); // deg 3
                                                                         /*
                                                                          * The complete RAM/ROM memory identity
                                                                          * Partial degree:
                                                                          */
        let q_4_q_1 = q_4
            .iter()
            .zip_eq(q_1.iter())
            .map(|(a, b)| *a * *b)
            .collect_vec();

        let q_m_q_1 = q_m
            .iter()
            .zip_eq(q_1.iter())
            .map(|(a, b)| *a * *b)
            .collect_vec();
        T::mul_assign_with_public_many(&mut ram_timestamp_check_identity, &q_4_q_1);
        T::mul_assign_with_public_many(&mut memory_record_check, &q_m_q_1);
        let mut memory_identity = rom_consistency_check_identity;
        T::add_assign_many(&mut memory_identity, &ram_timestamp_check_identity);
        T::add_assign_many(&mut memory_identity, &memory_record_check);
        T::add_assign_many(&mut memory_identity, &ram_consistency_check_identity);

        T::add_assign_many(&mut memory_identity, &non_native_field_identity);
        T::add_assign_many(&mut memory_identity, &limb_accumulator_identity);
        T::mul_assign_with_public_many(&mut memory_identity, &q_aux_by_scaling);

        let evaluations_len = univariate_accumulator.r0.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        for (idx, b) in memory_identity.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
            T::add_assign(a, *b);
        }
        univariate_accumulator
            .r0
            .evaluations
            .clone_from_slice(&acc[..evaluations_len]);
        Ok(())
    }
}
