use std::iter;

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
pub(crate) struct UltraPermutationRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
}

impl_relation_evals!(UltraPermutationRelationEvals, r0, r1);
pub(crate) struct UltraPermutationRelation;

impl UltraPermutationRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for UltraPermutationRelation {
    type VerifyAcc = UltraPermutationRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let id_1 = input.precomputed.id_1().to_owned();
        let id_2 = input.precomputed.id_2().to_owned();
        let id_3 = input.precomputed.id_3().to_owned();
        let id_4 = input.precomputed.id_4().to_owned();
        let sigma_1 = input.precomputed.sigma_1().to_owned();
        let sigma_2 = input.precomputed.sigma_2().to_owned();
        let sigma_3 = input.precomputed.sigma_3().to_owned();
        let sigma_4 = input.precomputed.sigma_4().to_owned();

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = input.witness.z_perm();
        let z_perm_shift = input.shifted_witness.z_perm().to_owned();
        let lagrange_first = input.precomputed.lagrange_first().to_owned();
        let lagrange_last = input.precomputed.lagrange_last().to_owned();

        let w_1_plus_gamma = w_1.add(gamma, builder, driver);
        let w_2_plus_gamma = w_2.add(gamma, builder, driver);
        let w_3_plus_gamma = w_3.add(gamma, builder, driver);
        let w_4_plus_gamma = w_4.add(gamma, builder, driver);

        let lhs = [id_1, id_2, id_3, id_4, sigma_1, sigma_2, sigma_3, sigma_4];

        let rhs = iter::repeat_n(beta.clone(), 8).collect::<Vec<_>>();

        let mut raw_mul_data = FieldCT::multiply_many_raw(&lhs, &rhs, builder, driver)?;

        let t1 = FieldCT::commit_mul(&mut raw_mul_data[0], builder)?
            .add(&w_1_plus_gamma, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        let t2 = FieldCT::commit_mul(&mut raw_mul_data[1], builder)?.add(
            &w_2_plus_gamma,
            builder,
            driver,
        );
        let t3 = FieldCT::commit_mul(&mut raw_mul_data[2], builder)?.add(
            &w_3_plus_gamma,
            builder,
            driver,
        );
        let t4 = FieldCT::commit_mul(&mut raw_mul_data[3], builder)?.add(
            &w_4_plus_gamma,
            builder,
            driver,
        );

        let t5 = FieldCT::commit_mul(&mut raw_mul_data[4], builder)?
            .add(&w_1_plus_gamma, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        let t6 = FieldCT::commit_mul(&mut raw_mul_data[5], builder)?.add(
            &w_2_plus_gamma,
            builder,
            driver,
        );
        let t7 = FieldCT::commit_mul(&mut raw_mul_data[6], builder)?.add(
            &w_3_plus_gamma,
            builder,
            driver,
        );
        let t8 = FieldCT::commit_mul(&mut raw_mul_data[7], builder)?.add(
            &w_4_plus_gamma,
            builder,
            driver,
        );

        let mut mul_raw_data = FieldCT::multiply_many_raw(
            &[t1, t5, lagrange_last.clone(), lagrange_last.clone()],
            &[t2, t6, public_input_delta.clone(), z_perm_shift.clone()],
            builder,
            driver,
        )?;

        let t1_t2 = FieldCT::commit_mul(&mut mul_raw_data[0], builder)?;
        let numerator = t1_t2
            .multiply(&t3, builder, driver)?
            .multiply(&t4, builder, driver)?;

        let t5_t6 = FieldCT::commit_mul(&mut mul_raw_data[1], builder)?;
        let denominator = t5_t6
            .multiply(&t7, builder, driver)?
            .multiply(&t8, builder, driver)?;

        let lagrange_last_public_input_delta = FieldCT::commit_mul(&mut mul_raw_data[2], builder)?;
        let public_input_term =
            lagrange_last_public_input_delta.add(&z_perm_shift, builder, driver);

        let z_perm_plus_lagrange_first = z_perm.add(&lagrange_first, builder, driver);

        let mut raw_mul_data_2 = FieldCT::multiply_many_raw(
            &[z_perm_plus_lagrange_first, public_input_term],
            &[numerator, denominator],
            builder,
            driver,
        )?;

        let z_perm_lagrange_first_numerator = FieldCT::commit_mul(&mut raw_mul_data_2[0], builder)?;

        let public_input_term_by_denominator =
            FieldCT::commit_mul(&mut raw_mul_data_2[1], builder)?;

        let tmp =
            z_perm_lagrange_first_numerator.sub(&public_input_term_by_denominator, builder, driver);

        accumulator.r0.add_assign(&tmp, builder, driver);

        let lagrange_last_z_perm_shift = FieldCT::commit_mul(&mut mul_raw_data[3], builder)?;

        let lagrange_last_by_z_perm_shift_scaled =
            lagrange_last_z_perm_shift.multiply(scaling_factor, builder, driver)?;

        accumulator
            .r1
            .add_assign(&lagrange_last_by_z_perm_shift_scaled, builder, driver);

        Ok(())
    }
}
