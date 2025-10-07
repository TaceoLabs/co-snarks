use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::mega_builder::MegaCircuitBuilder;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ShiftedWitnessEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::types::field_ct::FieldCT;
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::types::AllEntities;
use common::honk_curve::HonkCurve;
use common::honk_proof::{HonkProofResult, TranscriptFieldType};
use common::mpc::NoirUltraHonkProver;

use crate::impl_relation_evals;
use crate::verifier_relations::Relation;
use crate::verifier_relations::VerifyAccGetter;

#[derive(Clone, Debug)]
pub(crate) struct EccOpQueueRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
    pub(crate) r4: FieldCT<F>,
    pub(crate) r5: FieldCT<F>,
    pub(crate) r6: FieldCT<F>,
    pub(crate) r7: FieldCT<F>,
}

impl_relation_evals!(EccOpQueueRelationEvals, r0, r1, r2, r3, r4, r5, r6, r7);

pub(crate) struct EccOpQueueRelation;

impl EccOpQueueRelation {
    pub(crate) const NUM_RELATIONS: usize = 8;
    // pub(crate) const CRAND_PAIRS_FACTOR: usize = 0;
}

impl<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> Relation<C>
    for EccOpQueueRelation
{
    type VerifyAcc = EccOpQueueRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // using Accumulator = std::tuple_element_t<0, ContainerOverSubrelations>;
        // using CoefficientAccumulator = typename Accumulator::CoefficientAccumulator;
        // We skip using the CoefficientAccumulator type in this relation, as the overall relation degree is low (deg
        // 3). To do a degree-1 multiplication in the coefficient basis requires 3 Fp muls and 4 Fp adds (karatsuba
        // multiplication). But a multiplication of a degree-3 Univariate only requires 3 Fp muls.
        // We still cast to CoefficientAccumulator so that the degree is extended to degree-3 from degree-1

        let w_1_shift = input.shifted_witness.w_l().to_owned();
        let w_2_shift = input.shifted_witness.w_r().to_owned();
        let w_3_shift = input.shifted_witness.w_o().to_owned();
        let w_4_shift = input.shifted_witness.w_4().to_owned();

        let op_wire_1 = input.witness.ecc_op_wire_1().to_owned();
        let op_wire_2 = input.witness.ecc_op_wire_2().to_owned();
        let op_wire_3 = input.witness.ecc_op_wire_3().to_owned();
        let op_wire_4 = input.witness.ecc_op_wire_4().to_owned();
        let lagrange_ecc_op = input.precomputed.lagrange_ecc_op().to_owned();

        // If lagrange_ecc_op is the indicator for ecc_op_gates, this is the indicator for the complement

        let lagrange_by_scaling = lagrange_ecc_op.multiply(scaling_factor, builder, driver)?;
        let complement_ecc_op_by_scaling = lagrange_by_scaling.sub(scaling_factor, builder, driver);

        // Contribution (1)
        let tmp = op_wire_1.sub(&w_1_shift, builder, driver);
        let prod = lagrange_by_scaling.multiply(&tmp, builder, driver)?;
        accumulator.r0 = accumulator.r0.add(&prod, builder, driver);

        // Contribution (2)
        let tmp = op_wire_2.sub(&w_2_shift, builder, driver);
        let prod = lagrange_by_scaling.multiply(&tmp, builder, driver)?;
        accumulator.r1 = accumulator.r1.add(&prod, builder, driver);

        // Contribution (3)
        let tmp = op_wire_3.sub(&w_3_shift, builder, driver);
        let prod = lagrange_by_scaling.multiply(&tmp, builder, driver)?;
        accumulator.r2 = accumulator.r2.add(&prod, builder, driver);

        // Contribution (4)
        let tmp = op_wire_4.sub(&w_4_shift, builder, driver);
        let prod = lagrange_by_scaling.multiply(&tmp, builder, driver)?;
        accumulator.r3 = accumulator.r3.add(&prod, builder, driver);

        // Contribution (5)
        let prod = complement_ecc_op_by_scaling.multiply(&op_wire_1, builder, driver)?;
        accumulator.r4 = accumulator.r4.add(&prod, builder, driver);

        // Contribution (6)
        let prod = complement_ecc_op_by_scaling.multiply(&op_wire_2, builder, driver)?;
        accumulator.r5 = accumulator.r5.add(&prod, builder, driver);

        // Contribution (7)
        let prod = complement_ecc_op_by_scaling.multiply(&op_wire_3, builder, driver)?;
        accumulator.r6 = accumulator.r6.add(&prod, builder, driver);

        // Contribution (8)
        let prod = complement_ecc_op_by_scaling.multiply(&op_wire_4, builder, driver)?;
        accumulator.r7 = accumulator.r7.add(&prod, builder, driver);

        Ok(())
    }
}
