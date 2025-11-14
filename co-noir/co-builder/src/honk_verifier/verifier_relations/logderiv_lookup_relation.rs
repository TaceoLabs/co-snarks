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
    pub(crate) const NUM_RELATIONS: usize = 3;
}

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

        Ok(row_has_write
            .multiply(&row_has_read, builder, driver)?
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
        let eta_1 = relation_parameters.eta_1.to_owned();
        let eta_2 = relation_parameters.eta_2.to_owned();
        let eta_3 = relation_parameters.eta_3.to_owned();
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
        let derived_table_entry_1 = negative_column_1_step_size
            .multiply(&w_1_shift, builder, driver)?
            .add(&(w_1.add(gamma, builder, driver)), builder, driver);

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        let derived_table_entry_2 = negative_column_2_step_size
            .multiply(&w_2_shift, builder, driver)?
            .add(&w_2, builder, driver);

        let derived_table_entry_3 = negative_column_3_step_size
            .multiply(&w_3_shift, builder, driver)?
            .add(&w_3, builder, driver);

        let [
            table_index_entry,
            derived_table_entry_2,
            derived_table_entry_3,
        ] = FieldCT::multiply_many(
            &[table_index, derived_table_entry_2, derived_table_entry_3],
            &[eta_3, eta_1, eta_2],
            builder,
            driver,
        )?
        .try_into()
        .expect("We checked lengths match");

        Ok(derived_table_entry_2
            .add(&derived_table_entry_3, builder, driver)
            .add(
                &derived_table_entry_1.add(&table_index_entry, builder, driver),
                builder,
                driver,
            ))
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
        let eta_1 = relation_parameters.eta_1.to_owned();
        let eta_2 = relation_parameters.eta_2.to_owned();
        let eta_3 = relation_parameters.eta_3.to_owned();

        let table_1 = input.precomputed.table_1().to_owned();
        let table_2 = input.precomputed.table_2().to_owned();
        let table_3 = input.precomputed.table_3().to_owned();
        let table_4 = input.precomputed.table_4().to_owned();

        let mut mul_raw = FieldCT::multiply_many_raw(
            &[table_2, table_3, table_4],
            &[eta_1, eta_2, eta_3],
            builder,
            driver,
        )?;

        Ok(FieldCT::commit_mul(&mut mul_raw[0], builder)?
            .add(
                &FieldCT::commit_mul(&mut mul_raw[1], builder)?,
                builder,
                driver,
            )
            .add(
                &FieldCT::commit_mul(&mut mul_raw[2], builder)?,
                builder,
                driver,
            )
            .add(&table_1, builder, driver)
            .add(gamma, builder, driver))
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

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value is 0
        // if !inverse_exists.
        // Degrees:                     2 (3)       1 (2)        1              1
        let logderiv_first_term = read_term
            .multiply(&write_term, builder, driver)?
            .multiply(&inverses, builder, driver)?
            .sub(&inverse_exists, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        accumulator
            .r0
            .add_assign(&logderiv_first_term, builder, driver);

        let mut mul_raw = FieldCT::multiply_many_raw(
            &[read_selector, read_counts, read_tag.clone()],
            &[write_term, read_term, read_tag.clone()],
            builder,
            driver,
        )?;

        // Establish validity of the read. Note: no scaling factor here since this constraint is 'linearly dependent,
        // i.e. enforced across the entire trace, not on a per-row basis.
        // Degrees:                       1            2 (3)            1            3 (4)
        //
        let tmp = FieldCT::commit_mul(&mut mul_raw[0], builder)?
            .sub(
                &FieldCT::commit_mul(&mut mul_raw[1], builder)?,
                builder,
                driver,
            )
            .multiply(&inverses, builder, driver)?;
        accumulator.r1.add_assign(&tmp, builder, driver);
        // we should make sure that the read_tag is a boolean value
        let tmp = FieldCT::commit_mul(&mut mul_raw[2], builder)?
            .sub(&read_tag, builder, driver)
            .multiply(scaling_factor, builder, driver)?;
        accumulator.r2.add_assign(&tmp, builder, driver);
        Ok(())
    }
}
