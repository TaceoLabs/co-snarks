use super::Relation;
use crate::honk_verifier::verifier_relations::VerifyAccGetter;
use crate::impl_relation_evals;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::field_ct::FieldCT;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

#[derive(Clone, Debug)]
pub(crate) struct DeltaRangeConstraintRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
}

impl_relation_evals!(DeltaRangeConstraintRelationEvals, r0, r1, r2, r3);

pub(crate) struct DeltaRangeConstraintRelation;

impl DeltaRangeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for DeltaRangeConstraintRelation {
    type VerifyAcc = DeltaRangeConstraintRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l().to_owned();
        let w_2 = input.witness.w_r().to_owned();
        let w_3 = input.witness.w_o().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let w_1_shift = input.shifted_witness.w_l().to_owned();
        let q_delta_range = input.precomputed.q_delta_range().to_owned();
        let two = FieldCT::from(C::ScalarField::from(2u64));
        let minus_three = FieldCT::from(-C::ScalarField::from(3u64));

        //TACEO TODO: Batch the multiplications here

        let q_delta_range_scaled = q_delta_range.multiply(scaling_factor, builder, driver)?;

        // Compute wire differences
        let delta_1 = w_2.sub(&w_1, builder, driver);
        let delta_2 = w_3.sub(&w_2, builder, driver);
        let delta_3 = w_4.sub(&w_3, builder, driver);
        let delta_4 = w_1_shift.sub(&w_4, builder, driver);
        let delta_1_minus_3 = delta_1.add(&minus_three, builder, driver);
        let delta_2_minus_3 = delta_2.add(&minus_three, builder, driver);
        let delta_3_minus_3 = delta_3.add(&minus_three, builder, driver);
        let delta_4_minus_3 = delta_4.add(&minus_three, builder, driver);

        // Contribution (1)
        let mut tmp_1 = delta_1_minus_3.multiply(&delta_1, builder, driver)?;
        tmp_1 = tmp_1.multiply(&tmp_1.add(&two, builder, driver), builder, driver)?;
        tmp_1 = tmp_1.multiply(&q_delta_range_scaled, builder, driver)?;
        accumulator.r0.add_assign(&tmp_1, builder, driver);

        // Contribution (2)
        let mut tmp_2 = delta_2_minus_3.multiply(&delta_2, builder, driver)?;
        tmp_2 = tmp_2.multiply(&tmp_2.add(&two, builder, driver), builder, driver)?;
        tmp_2 = tmp_2.multiply(&q_delta_range_scaled, builder, driver)?;
        accumulator.r1.add_assign(&tmp_2, builder, driver);

        // Contribution (3)
        let mut tmp_3 = delta_3_minus_3.multiply(&delta_3, builder, driver)?;
        tmp_3 = tmp_3.multiply(&tmp_3.add(&two, builder, driver), builder, driver)?;
        tmp_3 = tmp_3.multiply(&q_delta_range_scaled, builder, driver)?;
        accumulator.r2.add_assign(&tmp_3, builder, driver);

        // Contribution (4)
        let mut tmp_4 = delta_4_minus_3.multiply(&delta_4, builder, driver)?;
        tmp_4 = tmp_4.multiply(&tmp_4.add(&two, builder, driver), builder, driver)?;
        tmp_4 = tmp_4.multiply(&q_delta_range_scaled, builder, driver)?;
        accumulator.r3.add_assign(&tmp_4, builder, driver);
        Ok(())
    }
}
