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
pub(crate) struct EllipticRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
}

impl_relation_evals!(EllipticRelationEvals, r0, r1);

pub(crate) struct EllipticRelation;

impl EllipticRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
}

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
        let x_3 = input.shifted_witness.w_r().to_owned();
        let y_1 = input.witness.w_o().to_owned();
        let y_2 = input.shifted_witness.w_4().to_owned();

        let x_1 = input.witness.w_r().to_owned();
        let x_2 = input.shifted_witness.w_l().to_owned();
        let y_3 = input.shifted_witness.w_o().to_owned();
        let q_elliptic = input.precomputed.q_elliptic().to_owned();
        let q_is_double = input.precomputed.q_m().to_owned();
        let q_sign = input.precomputed.q_l().to_owned();

        // We efficiently construct the following:
        let x2_sub_x1 = x_2.sub(&x_1, builder, driver); // (x2 - x1)
        let x1_mul_3 = x_1.add(&x_1, builder, driver).add(&x_1, builder, driver); // (3*x1)
        let x3_sub_x1 = x_3.sub(&x_1, builder, driver); // (x3 - x1)
        let x3_plus_two_x1 = x3_sub_x1.add(&x1_mul_3, builder, driver); // (x3 + 2*x1)
        let x3_plus_x2_plus_x1 = x3_plus_two_x1.add(&x2_sub_x1, builder, driver); // (x3 + x2 + x1)

        //TACEO TODO: Batch the multiplications here

        // Contribution (1) point addition, x-coordinate check:
        // q_elliptic * (q_is_double - 1) * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
        let y2_sqr = y_2.multiply(&y_2, builder, driver)?;
        let y1_sqr = y_1.multiply(&y_1, builder, driver)?;
        let y2_mul_q_sign = q_sign.multiply(&y_2, builder, driver)?;
        let x2_sub_x1_sqr = x2_sub_x1.multiply(&x2_sub_x1, builder, driver)?;
        let mut x_add_identity = x3_plus_x2_plus_x1.multiply(&x2_sub_x1_sqr, builder, driver)?;
        x_add_identity = x_add_identity
            .sub(&y2_sqr, builder, driver)
            .sub(&y1_sqr, builder, driver)
            .add(
                &y2_mul_q_sign
                    .add(&y2_mul_q_sign, builder, driver)
                    .multiply(&y_1, builder, driver)?,
                builder,
                driver,
            );

        let q_elliptic_by_scaling = q_elliptic.multiply(scaling_factor, builder, driver)?;
        let q_elliptic_q_double_scaling =
            q_elliptic_by_scaling
                .clone()
                .multiply(&q_is_double, builder, driver)?;
        let neg_q_elliptic_not_double_scaling =
            q_elliptic_q_double_scaling
                .clone()
                .sub(&q_elliptic_by_scaling, builder, driver);

        let tmp_0 = neg_q_elliptic_not_double_scaling.multiply(&x_add_identity, builder, driver)?;

        accumulator.r0 = accumulator.r0.sub(&tmp_0, builder, driver);

        // Contribution (2) point addition, y-coordinate check
        // q_elliptic * (q_is_double - 1) * (y1 + y3)(x2 - x1) + (x3 - x1)(q_sign*y2 - y1) = 0
        let y1_plus_y3 = y_1.add(&y_3, builder, driver);
        let y_diff = y2_mul_q_sign.sub(&y_1, builder, driver);
        let y_add_identity = y1_plus_y3.multiply(&x2_sub_x1, builder, driver)?.add(
            &x3_sub_x1.multiply(&y_diff, builder, driver)?,
            builder,
            driver,
        );

        let tmp_1 = neg_q_elliptic_not_double_scaling.multiply(&y_add_identity, builder, driver)?;

        accumulator.r1 = accumulator.r1.sub(&tmp_1, builder, driver);

        // Contribution (3) point doubling, x-coordinate check
        // (x3 + x1 + x1) (4*y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
        // N.B. we're using the equivalence x1^3 === y1^2 - curve_b to reduce degree by 1
        let curve_b = C::get_curve_b();
        let x_pow_4_mul_3 = y1_sqr
            .add(&FieldCT::from(-curve_b), builder, driver)
            .multiply(&x1_mul_3, builder, driver)?;
        let y1_sqr_mul_4 = {
            let t = y1_sqr.add(&y1_sqr, builder, driver);
            t.add(&t, builder, driver)
        };
        let x1_pow_4_mul_9 = {
            let t = x_pow_4_mul_3.add(&x_pow_4_mul_3, builder, driver);
            t.add(&x_pow_4_mul_3, builder, driver)
        };
        let x_double_identity = x3_plus_two_x1
            .multiply(&y1_sqr_mul_4, builder, driver)?
            .sub(&x1_pow_4_mul_9, builder, driver);

        let tmp_0 = x_double_identity.multiply(scaling_factor, builder, driver)?;
        accumulator.r0 = accumulator.r0.add(&tmp_0, builder, driver);

        // Contribution (4) point doubling, y-coordinate check
        // (y1 + y3) (2*y1) - (3 * x1 * x1)(x1 - x3) = 0
        let x1_sqr_mul_3 = x1_mul_3.multiply(&x_1, builder, driver)?; // (3*x1)*x1
        let neg_y_double_identity = x1_sqr_mul_3.multiply(&x3_sub_x1, builder, driver)?.add(
            &y_1.add(&y_1, builder, driver)
                .multiply(&y1_plus_y3, builder, driver)?,
            builder,
            driver,
        );
        let tmp_1 = neg_y_double_identity.multiply(scaling_factor, builder, driver)?;
        accumulator.r1 = accumulator.r1.sub(&tmp_1, builder, driver);

        Ok(())
    }
}
