use crate::impl_relation_evals;
use crate::verifier_relations::VerifyAccGetter;

use super::Relation;
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

#[derive(Clone, Debug)]
pub(crate) struct EllipticRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
}

impl_relation_evals!(EllipticRelationEvals, r0, r1);

pub(crate) struct EllipticRelation;

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for EllipticRelation {
    type VerifyAcc = EllipticRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // AZTEC TODO(@zac - williamson #2608 when Pedersen refactor is completed,
        // replace old addition relations with these ones and
        // remove endomorphism coefficient in ecc add gate(not used))

        let x_1 = input.witness.w_r().to_owned();
        let y_1 = input.witness.w_o().to_owned();

        let x_2 = input.shifted_witness.w_l().to_owned();
        let y_2 = input.shifted_witness.w_4().to_owned();
        let y_3 = input.shifted_witness.w_o().to_owned();
        let x_3 = input.shifted_witness.w_r().to_owned();

        let q_sign = input.precomputed.q_l().to_owned();
        let q_elliptic = input.precomputed.q_elliptic().to_owned();
        let q_is_double = input.precomputed.q_m().to_owned();

        // First round of multiplications
        let x_diff = x_2.sub(&x_1, builder, driver);
        let y1_plus_y3 = y_1.add(&y_3, builder, driver);
        let y_diff = q_sign
            .multiply(&y_2, builder, driver)?
            .sub(&y_1, builder, driver);

        let x1_mul_3 = x_1.add(&x_1, builder, driver).add(&x_1, builder, driver);
        let x3_sub_x1 = x_3.sub(&x_1, builder, driver);
        let lhs = vec![
            y_1.clone(),
            y_2.clone(),
            y_1.clone(),
            x_diff.clone(),
            y1_plus_y3.clone(),
            y_diff.clone(),
            x1_mul_3.clone(),
        ];

        let rhs = vec![
            y_1.clone(),
            y_2.clone(),
            y_2.clone(),
            x_diff.clone(),
            x_diff.clone(),
            x3_sub_x1.clone(),
            x_1.clone(),
        ];

        let mul1 = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        // Second round of multiplications
        let curve_b = C::get_curve_b(); // here we need the extra constraint on the Curve
        let y1_sqr = mul1[0].clone();
        let y1_sqr_mul_4 = y1_sqr.add(&y1_sqr, builder, driver);
        let y1_sqr_mul_4 = y1_sqr_mul_4.add(&y1_sqr_mul_4, builder, driver);
        let x1_sqr_mul_3 = mul1[6].clone();

        let lhs = vec![
            x_3.add(&x_2, builder, driver).add(&x_1, builder, driver),
            y1_sqr.add(
                &FieldCT::from_witness((-curve_b).into(), builder),
                builder,
                driver,
            ),
            x_3.add(&x_1, builder, driver).add(&x_1, builder, driver),
            x1_sqr_mul_3,
            y_1.add(&y_1, builder, driver),
        ];

        let rhs = vec![
            mul1[3].clone(),
            x1_mul_3,
            y1_sqr_mul_4,
            x_1.sub(&x_3, builder, driver),
            y1_plus_y3,
        ];

        let mul2 = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        // Contribution (1) point addition, x-coordinate check
        // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
        let y2_sqr = mul1[1].clone();
        let y1y2 = q_sign.multiply(&mul1[2], builder, driver)?;
        let x_add_identity = mul2[0]
            .sub(&y2_sqr, builder, driver)
            .sub(&y1_sqr, builder, driver)
            .add(&y1y2, builder, driver)
            .add(&y1y2, builder, driver);

        let q_elliptic_by_scaling = q_elliptic.multiply(scaling_factor, builder, driver)?;
        let q_elliptic_q_double_scaling =
            q_elliptic_by_scaling.multiply(&q_is_double, builder, driver)?;
        let q_elliptic_not_double_scaling =
            q_elliptic_by_scaling.sub(&q_elliptic_q_double_scaling, builder, driver);

        let mut tmp_1 = q_elliptic_not_double_scaling.multiply(&x_add_identity, builder, driver)?;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2) point addition, x-coordinate check
        // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
        let y_add_identity = mul1[4].add(&mul1[5], builder, driver);
        let mut tmp_2 = q_elliptic_not_double_scaling.multiply(&y_add_identity, builder, driver)?;

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3) point doubling, x-coordinate check
        // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
        // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1
        let x_pow_4_mul_3 = mul2[1].clone();
        let x1_pow_4_mul_9 =
            x_pow_4_mul_3
                .add(&x_pow_4_mul_3, builder, driver)
                .add(&x_pow_4_mul_3, builder, driver);
        let x_double_identity = mul2[2].sub(&x1_pow_4_mul_9, builder, driver);

        let tmp = q_elliptic_q_double_scaling.multiply(&x_double_identity, builder, driver)?;
        tmp_1 = tmp_1.add(&tmp, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4) point doubling, y-coordinate check
        // (y1 + y3) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
        let y_double_identity = mul2[3].sub(&mul2[4], builder, driver);
        let tmp = q_elliptic_q_double_scaling.multiply(&y_double_identity, builder, driver)?;
        tmp_2 = tmp_2.add(&tmp, builder, driver);

        accumulator.r0 = accumulator.r0.add(&tmp_1, builder, driver);
        accumulator.r1 = accumulator.r1.add(&tmp_2, builder, driver);
        Ok(())
    }
}
