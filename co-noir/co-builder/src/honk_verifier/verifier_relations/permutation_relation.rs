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

        let t1 = id_1
            .multiply(beta, builder, driver)?
            .add(&w_1_plus_gamma, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        let t2 = id_2
            .multiply(beta, builder, driver)?
            .add(&w_2_plus_gamma, builder, driver);
        let t3 = id_3
            .multiply(beta, builder, driver)?
            .add(&w_3_plus_gamma, builder, driver);
        let t4 = id_4
            .multiply(beta, builder, driver)?
            .add(&w_4_plus_gamma, builder, driver);

        let t5 = sigma_1
            .multiply(beta, builder, driver)?
            .add(&w_1_plus_gamma, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        let t6 = sigma_2
            .multiply(beta, builder, driver)?
            .add(&w_2_plus_gamma, builder, driver);
        let t7 = sigma_3
            .multiply(beta, builder, driver)?
            .add(&w_3_plus_gamma, builder, driver);
        let t8 = sigma_4
            .multiply(beta, builder, driver)?
            .add(&w_4_plus_gamma, builder, driver);

        let num_den =
            FieldCT::multiply_many(&[t1, t2, t5, t6], &[t3, t4, t7, t8], builder, driver)?;
        let [numerator, denominator] = FieldCT::multiply_many(
            &[num_den[0].clone(), num_den[2].clone()],
            &[num_den[1].clone(), num_den[3].clone()],
            builder,
            driver,
        )?
        .try_into()
        .unwrap();

        let public_input_term = public_input_delta
            .multiply(&lagrange_last, builder, driver)?
            .add(&z_perm_shift, builder, driver);

        let public_input_term_by_denominator =
            public_input_term.multiply(&denominator, builder, driver)?;
        let z_perm_plus_lagrange_first_by_numerator = lagrange_first
            .add(z_perm, builder, driver)
            .multiply(&numerator, builder, driver)?;

        let tmp = z_perm_plus_lagrange_first_by_numerator.sub(
            &public_input_term_by_denominator,
            builder,
            driver,
        );

        accumulator.r0 = accumulator.r0.add(&tmp, builder, driver);

        let lagrange_last_by_z_perm_shift =
            lagrange_last.multiply(&z_perm_shift, builder, driver)?;
        let tmp = lagrange_last_by_z_perm_shift.multiply(scaling_factor, builder, driver)?;

        accumulator.r1 = accumulator.r1.add(&tmp, builder, driver);

        Ok(())
    }
}
