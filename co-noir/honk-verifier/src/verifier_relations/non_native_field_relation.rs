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
pub(crate) struct NonNativeFieldRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
}

impl_relation_evals!(NonNativeFieldRelationEvals, r0);
pub(crate) struct NonNativeFieldRelation;

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for NonNativeFieldRelation {
    type VerifyAcc = NonNativeFieldRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let q_2 = input.precomputed.q_r();
        let q_3 = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_m = input.precomputed.q_m();
        let q_nnf = input.precomputed.q_nnf();

        let limb_size = FieldCT::from(C::ScalarField::from(BigUint::one() << 68));
        let sublimb_shift = FieldCT::from(C::ScalarField::from(1u64 << 14));

        /*
         * Non native field arithmetic gate 2
         * deg 4
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         */
        let lhs = vec![
            w_1.clone(),
            w_2.clone(),
            w_4.clone(),
            w_3.clone(),
            w_1_shift.clone(),
        ];
        let rhs = vec![
            w_2_shift.clone(),
            w_1_shift.clone(),
            w_1.clone(),
            w_2.clone(),
            w_2_shift.clone(),
        ];
        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        // Non native field arithmetic gate 2
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

        let nnf_identity = non_native_field_identity
            .add(&limb_accumulator_identity, builder, driver)
            .multiply(q_nnf, builder, driver)?
            .multiply(scaling_factor, builder, driver)?;

        accumulator.r0 = accumulator.r0.add(&nnf_identity, builder, driver);

        Ok(())
    }
}
