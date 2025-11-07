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
pub(crate) struct LogDerivLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
}

impl_relation_evals!(LogDerivLookupRelationEvals, r0, r1, r2);
pub(crate) struct LogDerivLookupRelation;

impl LogDerivLookupRelation {
    fn compute_inverse_exists_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let row_has_write = input.witness.lookup_read_tags().to_owned();
        let row_has_read = input.precomputed.q_lookup().to_owned();

        Ok(row_has_read
            .multiply(&row_has_write, builder, driver)?
            .neg()
            .add(&row_has_write, builder, driver)
            .add(&row_has_read, builder, driver))
    }

    fn compute_read_term_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let gamma = &relation_parameters.gamma;
        let eta_1 = &relation_parameters.eta_1;
        let eta_2 = &relation_parameters.eta_2;
        let eta_3 = &relation_parameters.eta_3;
        let w_1 = input.witness.w_l().to_owned();
        let w_2 = input.witness.w_r().to_owned();
        let w_3 = input.witness.w_o().to_owned();
        let w_1_shift = input.shifted_witness.w_l().to_owned();
        let w_2_shift = input.shifted_witness.w_r().to_owned();
        let w_3_shift = input.shifted_witness.w_o().to_owned();
        let table_index = input.precomputed.q_o().to_owned();
        let negative_column_1_step_size = input.precomputed.q_r().to_owned();
        let negative_column_2_step_size = input.precomputed.q_m().to_owned();
        let negative_column_3_step_size = input.precomputed.q_c().to_owned();

        // The wire values for lookup gates are accumulators structured in such a way that the differences w_i -
        // step_size*w_i_shift result in values present in column i of a corresponding table. See the documentation in
        // method get_lookup_accumulators() in  for a detailed explanation.
        let mut derived_table_entry_1 = negative_column_1_step_size
            .multiply(&w_1_shift, builder, driver)?
            .add(&w_1, builder, driver)
            .add(gamma, builder, driver);

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        let derived_table_entry_2 = negative_column_2_step_size
            .multiply(&w_2_shift, builder, driver)?
            .add(&w_2, builder, driver)
            .multiply(eta_1, builder, driver)?;
        let derived_table_entry_3 = negative_column_3_step_size
            .multiply(&w_3_shift, builder, driver)?
            .add(&w_3, builder, driver)
            .multiply(eta_2, builder, driver)?;

        derived_table_entry_1 = derived_table_entry_1
            .add(&derived_table_entry_2, builder, driver)
            .add(&derived_table_entry_3, builder, driver);

        let table_index = table_index.multiply(eta_3, builder, driver)?;
        Ok(derived_table_entry_1.add(&table_index, builder, driver))
    }

    fn compute_write_term_verifier<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let gamma = &relation_parameters.gamma;
        let eta_1 = &relation_parameters.eta_1;
        let eta_2 = &relation_parameters.eta_2;
        let eta_3 = &relation_parameters.eta_3;

        let table_1 = input.precomputed.table_1();
        let table_2 = input.precomputed.table_2();
        let table_3 = input.precomputed.table_3();
        let table_4 = input.precomputed.table_4();

        Ok(table_1
            .to_owned()
            .add(gamma, builder, driver)
            .add(
                &table_2.to_owned().multiply(eta_1, builder, driver)?,
                builder,
                driver,
            )
            .add(
                &table_3.to_owned().multiply(eta_2, builder, driver)?,
                builder,
                driver,
            )
            .add(
                &table_4.to_owned().multiply(eta_3, builder, driver)?,
                builder,
                driver,
            ))
    }
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for LogDerivLookupRelation {
    type VerifyAcc = LogDerivLookupRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let inverses = input.witness.lookup_inverses().to_owned();
        let read_counts = input.witness.lookup_read_counts().to_owned();
        let read_selector = input.precomputed.q_lookup().to_owned();
        let read_tag = input.witness.lookup_read_tags().to_owned();

        let inverse_exists = Self::compute_inverse_exists_verifier(input, builder, driver)?;
        let read_term =
            Self::compute_read_term_verifier(input, relation_parameters, builder, driver)?;
        let write_term =
            Self::compute_write_term_verifier(input, relation_parameters, builder, driver)?;

        let [write_inverse, read_inverse] = FieldCT::multiply_many(
            &[read_term, write_term.clone()],
            &[inverses.clone(), inverses.clone()],
            builder,
            driver,
        )?
        .try_into()
        .expect("We checked lengths match");

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value is 0
        // if !inverse_exists.
        // Degrees:                     2 (3)       1 (2)        1              1
        let tmp = write_term
            .multiply(&write_inverse, builder, driver)?
            .sub(&inverse_exists, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        accumulator.r0 = accumulator.r0.add(&tmp, builder, driver);

        let mul = FieldCT::multiply_many(
            &[write_inverse, read_tag.clone()],
            &[read_counts.clone(), read_tag.clone()],
            builder,
            driver,
        )?;

        // Establish validity of the read. Note: no scaling factor here since this constraint is 'linearly dependent,
        // i.e. enforced across the entire trace, not on a per-row basis.
        // Degrees:                       1            2 (3)            1            3 (4)
        //
        let tmp = read_selector
            .multiply(&read_inverse, builder, driver)?
            .sub(&mul[0], builder, driver);
        accumulator.r1 = accumulator.r1.add(&tmp, builder, driver);

        // we should make sure that the read_tag is a boolean value
        let tmp =
            mul[1]
                .sub(&read_tag, builder, driver)
                .multiply(scaling_factor, builder, driver)?;
        accumulator.r2 = accumulator.r2.add(&tmp, builder, driver);
        Ok(())
    }
}
