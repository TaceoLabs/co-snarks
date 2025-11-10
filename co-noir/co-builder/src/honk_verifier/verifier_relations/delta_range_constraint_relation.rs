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
use itertools::Itertools;

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
        let minus_one = FieldCT::from(-C::ScalarField::one());
        let minus_two = FieldCT::from(-C::ScalarField::from(2u64));

        // Compute wire differences
        let delta_1 = w_2.sub(&w_1, builder, driver);
        let delta_2 = w_3.sub(&w_2, builder, driver);
        let delta_3 = w_4.sub(&w_3, builder, driver);
        let delta_4 = w_1_shift.sub(&w_4, builder, driver);

        let tmp_1 = minus_one.add(&delta_1, builder, driver);
        let tmp_2 = minus_one.add(&delta_2, builder, driver);
        let tmp_3 = minus_one.add(&delta_3, builder, driver);
        let tmp_4 = minus_one.add(&delta_4, builder, driver);
        let tmp_1_2 = minus_two.add(&delta_1, builder, driver);
        let tmp_2_2 = minus_two.add(&delta_2, builder, driver);
        let tmp_3_2 = minus_two.add(&delta_3, builder, driver);
        let tmp_4_2 = minus_two.add(&delta_4, builder, driver);

        let lhs = vec![
            tmp_1, tmp_2, tmp_3, tmp_4, tmp_1_2, tmp_2_2, tmp_3_2, tmp_4_2,
        ];

        let mut sqr = FieldCT::multiply_many(&lhs, &lhs, builder, driver)?;

        for el in sqr.iter_mut() {
            *el = el.add(&minus_one, builder, driver);
        }

        let (lhs, rhs) = sqr.split_at(sqr.len() >> 1);
        let mul = FieldCT::multiply_many(lhs, rhs, builder, driver)?;
        let mul_q_delta = FieldCT::multiply_many(
            &mul,
            &std::iter::repeat_n(q_delta_range, 4).collect_vec(),
            builder,
            driver,
        )?;
        let mul_q_delta_q_scaling = FieldCT::multiply_many(
            &mul_q_delta,
            &std::iter::repeat_n(scaling_factor.clone(), 4).collect_vec(),
            builder,
            driver,
        )?;

        accumulator.r0 = accumulator
            .r0
            .add(&mul_q_delta_q_scaling[0], builder, driver);
        accumulator.r1 = accumulator
            .r1
            .add(&mul_q_delta_q_scaling[1], builder, driver);
        accumulator.r2 = accumulator
            .r2
            .add(&mul_q_delta_q_scaling[2], builder, driver);
        accumulator.r3 = accumulator
            .r3
            .add(&mul_q_delta_q_scaling[3], builder, driver);
        Ok(())
    }
}
