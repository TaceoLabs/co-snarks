use super::Relation;
use crate::honk_verifier::verifier_relations::VerifyAccGetter;
use crate::impl_relation_evals;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::field_ct::FieldCT;
use ark_ff::{Field, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

#[derive(Clone, Debug)]
pub(crate) struct UltraArithmeticRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
}

impl_relation_evals!(UltraArithmeticRelationEvals, r0, r1);

pub(crate) struct UltraArithmeticRelation;

impl UltraArithmeticRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    fn compute_r0_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        r0: &mut FieldCT<C::ScalarField>,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
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

        let one = FieldCT::from(C::ScalarField::ONE);
        let neg_half = FieldCT::from(-C::ScalarField::from(2u64).inverse().unwrap());
        let three = FieldCT::from(C::ScalarField::from(3_u64));

        let q_arith_sub_1 = q_arith.sub(&one, builder, driver);
        let q_arith_sub_3 = q_arith.sub(&three, builder, driver);

        let lhs = [
            q_arith,
            w_r.clone(),
            q_arith_sub_3,
            q_l,
            q_r,
            q_o,
            q_4,
            q_arith_sub_1,
        ];
        let rhs = [
            scaling_factor.clone(),
            w_l.clone(),
            q_m,
            w_l.clone(),
            w_r.clone(),
            w_o.clone(),
            w_4.clone(),
            w_4_shift,
        ];

        let mut mul_raw_data = FieldCT::multiply_many_raw(&lhs, &rhs, builder, driver)?;

        let scaled_q_arith = FieldCT::commit_mul(&mut mul_raw_data[0], builder)?;

        let w_r_w_l = FieldCT::commit_mul(&mut mul_raw_data[1], builder)?;

        let w_r_w_l_half = w_r_w_l.multiply(&neg_half, builder, driver)?;

        let q_arith_sub_3_q_m = FieldCT::commit_mul(&mut mul_raw_data[2], builder)?;

        let tmp_0 = w_r_w_l_half.multiply(&q_arith_sub_3_q_m, builder, driver)?;

        let q_l_w_l = FieldCT::commit_mul(&mut mul_raw_data[3], builder)?;
        let q_r_w_r = FieldCT::commit_mul(&mut mul_raw_data[4], builder)?;
        let mut tmp_1 = q_l_w_l.add(&q_r_w_r, builder, driver);
        let q_o_w_o = FieldCT::commit_mul(&mut mul_raw_data[5], builder)?;
        tmp_1.add_assign(&q_o_w_o, builder, driver);
        let q_4_w_4 = FieldCT::commit_mul(&mut mul_raw_data[6], builder)?;
        tmp_1.add_assign(&q_4_w_4, builder, driver);
        tmp_1.add_assign(&q_c, builder, driver);
        let q_arith_sub_1_w_4_shift = FieldCT::commit_mul(&mut mul_raw_data[7], builder)?;
        tmp_1.add_assign(&q_arith_sub_1_w_4_shift, builder, driver);

        let tmp = tmp_0
            .add(&tmp_1, builder, driver)
            .multiply(&scaled_q_arith, builder, driver)?;
        *r0 = r0.add(&tmp, builder, driver);

        Ok(scaled_q_arith)
    }

    fn compute_r1_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        r1: &mut FieldCT<C::ScalarField>,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        scaled_q_arith: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_l = input.witness.w_l().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let q_m = input.precomputed.q_m().to_owned();
        let q_arith = input.precomputed.q_arith().to_owned();
        let w_l_shift = input.shifted_witness.w_l().to_owned();

        let one = FieldCT::from(C::ScalarField::ONE);
        let two = FieldCT::from(C::ScalarField::from(2_u64));

        let q_arith_sub_1 = q_arith.sub(&one, builder, driver);

        let tmp = w_l
            .add(&w_4, builder, driver)
            .sub(&w_l_shift, builder, driver)
            .add(&q_m, builder, driver)
            .multiply(&q_arith.sub(&two, builder, driver), builder, driver)?;

        let tmp2 = q_arith_sub_1.multiply(scaled_q_arith, builder, driver)?;

        let tmp = tmp.multiply(&tmp2, builder, driver)?;
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
        let scaled_q_arith =
            Self::compute_r0_verifier(&mut accumulator.r0, input, scaling_factor, builder, driver)?;
        Self::compute_r1_verifier(&mut accumulator.r1, input, &scaled_q_arith, builder, driver)?;
        Ok(())
    }
}
