use crate::impl_relation_evals;
use crate::verifier_relations::VerifyAccGetter;

use super::Relation;
use ark_ff::{Field, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::prelude::GenericUltraCircuitBuilder;
use co_builder::types::field_ct::FieldCT;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::types::AllEntities;

#[derive(Clone, Debug)]
pub(crate) struct UltraArithmeticRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
}

impl_relation_evals!(UltraArithmeticRelationEvals, r0, r1);

pub(crate) struct UltraArithmeticRelation;

impl UltraArithmeticRelation {
    fn compute_r0_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        r0: &mut FieldCT<C::ScalarField>,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_l = input.witness.w_l().to_owned();
        let w_r = input.witness.w_r().to_owned();
        let w_o = input.witness.w_o().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let q_m = input.precomputed.q_m().to_owned();
        let q_l = input.precomputed.q_l().to_owned();
        let q_r = input.precomputed.q_r().to_owned();
        let q_o = input.precomputed.q_o().to_owned();
        let q_4 = input.precomputed.q_4().to_owned();
        let q_c = input.precomputed.q_c().to_owned();
        let q_arith = input.precomputed.q_arith().to_owned();
        let w_4_shift = input.shifted_witness.w_4().to_owned();

        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let neg_half = FieldCT::from_witness(
            T::AcvmType::from(-C::ScalarField::from(2u64).inverse().unwrap()),
            builder,
        );
        let three = FieldCT::from_witness(C::ScalarField::from(3_u64).into(), builder);

        let lhs = [w_l.clone(), q_l, q_r, q_o, q_4];
        let rhs = [w_r.clone(), w_l, w_r, w_o, w_4];

        let [w_l_w_r, tmp_l, tmp_r, tmp_o, tmp_4] =
            FieldCT::multiply_many(&lhs, &rhs, builder, driver)?
                .try_into()
                .expect("We checked lengths match");

        let [q_m_w_l_w_r, q_arith_sub_1_w_4_shift, q_arith_scaling] = FieldCT::multiply_many(
            &[
                q_m.clone(),
                q_arith.sub(&one, builder, driver),
                q_arith.clone(),
            ],
            &[w_l_w_r, w_4_shift, scaling_factor.clone()],
            builder,
            driver,
        )?
        .try_into()
        .expect("We checked lengths match");

        let tmp = q_m_w_l_w_r
            .multiply(&q_arith.sub(&three, builder, driver), builder, driver)?
            .multiply(&neg_half, builder, driver)?;

        let mut tmp = [tmp, tmp_l, tmp_r, tmp_o, tmp_4, q_c]
            .into_iter()
            .reduce(|acc, x| acc.add(&x, builder, driver))
            .unwrap();

        tmp = tmp
            .add(&q_arith_sub_1_w_4_shift, builder, driver)
            .multiply(&q_arith_scaling, builder, driver)?;
        *r0 = r0.add(&tmp, builder, driver);

        Ok(())
    }

    fn compute_r1_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        r1: &mut FieldCT<C::ScalarField>,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_l = input.witness.w_l().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let q_m = input.precomputed.q_m().to_owned();
        let q_arith = input.precomputed.q_arith().to_owned();
        let w_l_shift = input.shifted_witness.w_l().to_owned();

        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let two = FieldCT::from_witness(C::ScalarField::from(2_u64).into(), builder);

        let [q_arith_sub_1_q_arith_sub_2, q_arith_scaling] = FieldCT::multiply_many(
            &[q_arith.sub(&one, builder, driver), q_arith.clone()],
            &[q_arith.sub(&two, builder, driver), scaling_factor.clone()],
            builder,
            driver,
        )?
        .try_into()
        .expect("We checked lengths match");

        let tmp = w_l
            .add(&w_4, builder, driver)
            .sub(&w_l_shift, builder, driver)
            .add(&q_m, builder, driver)
            .multiply(&q_arith_sub_1_q_arith_sub_2, builder, driver)?
            .multiply(&q_arith_scaling, builder, driver)?;

        *r1 = r1.add(&tmp, builder, driver);
        Ok(())
    }
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for UltraArithmeticRelation {
    type VerifyAcc = UltraArithmeticRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        Self::compute_r0_verifier(&mut accumulator.r0, input, scaling_factor, builder, driver)?;
        Self::compute_r1_verifier(&mut accumulator.r1, input, scaling_factor, builder, driver)?;
        Ok(())
    }
}
