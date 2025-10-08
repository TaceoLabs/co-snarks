use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_ultrahonk::types::AllEntities;

use ark_ff::One;
use ark_ff::PrimeField;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{
    flavours::mega_flavour::MegaFlavour, mega_builder::MegaCircuitBuilder,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour, types::field_ct::FieldCT,
};
use co_ultrahonk::co_decider::types::RelationParameters;
use common::honk_curve::HonkCurve;
use common::honk_proof::{HonkProofResult, TranscriptFieldType};
use itertools::Itertools as _;

use crate::impl_relation_evals;
use crate::verifier_relations::Relation;
use crate::verifier_relations::VerifyAccGetter;

#[derive(Clone, Debug)]
pub(crate) struct DeltaRangeConstraintRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
}

impl_relation_evals!(DeltaRangeConstraintRelationEvals, r0, r1, r2, r3);

pub(crate) struct DeltaRangeConstraintRelation;

impl<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> Relation<C>
    for DeltaRangeConstraintRelation
{
    type VerifyAcc = DeltaRangeConstraintRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l().to_owned();
        let w_2 = input.witness.w_r().to_owned();
        let w_3 = input.witness.w_o().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let w_1_shift = input.shifted_witness.w_l().to_owned();
        let q_delta_range = input.precomputed.q_delta_range().to_owned();
        let minus_one = FieldCT::from_witness((-C::ScalarField::one()).into(), builder);
        let minus_two = FieldCT::from_witness((-C::ScalarField::from(2u64)).into(), builder);

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
        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?
            .into_iter()
            .map(|x| {
                x.multiply(&q_delta_range, builder, driver)
                    .expect("public mul failed")
                    .multiply(scaling_factor, builder, driver)
                    .expect("public mul failed")
            })
            .collect_vec();
        //let mut tmp = T::mul_with_public(*q_delta_range, mul[0]);
        //tmp.scale_inplace(*scaling_factor);

        accumulator.r0 = accumulator.r0.add(&mul[0], builder, driver);
        accumulator.r1 = accumulator.r1.add(&mul[1], builder, driver);
        accumulator.r2 = accumulator.r2.add(&mul[2], builder, driver);
        accumulator.r3 = accumulator.r3.add(&mul[3], builder, driver);
        Ok(())
    }
}
