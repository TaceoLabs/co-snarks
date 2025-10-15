use crate::impl_relation_evals;

use super::Relation;
use crate::verifier_relations::VerifyAccGetter;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::mega_builder::MegaCircuitBuilder;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::types::field_ct::FieldCT;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::types::AllEntities;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusData {
    BusIdx0,
    BusIdx1,
    BusIdx2,
}

impl From<usize> for BusData {
    fn from(idx: usize) -> Self {
        match idx {
            0 => BusData::BusIdx0,
            1 => BusData::BusIdx1,
            2 => BusData::BusIdx2,
            _ => panic!("Invalid bus index: {idx}"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DataBusLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
    pub(crate) r4: FieldCT<F>,
    pub(crate) r5: FieldCT<F>,
}

impl_relation_evals!(DataBusLookupRelationEvals, r0, r1, r2, r3, r4, r5);

pub(crate) struct DataBusLookupRelation;
impl DataBusLookupRelation {
    const NUM_BUS_COLUMNS: usize = 3; // calldata, return data

    fn values_verifier<F: PrimeField>(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<F>, FieldCT<F>, MegaFlavour>,
    ) -> FieldCT<F> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata(),
            BusData::BusIdx1 => input.witness.secondary_calldata(),
            BusData::BusIdx2 => input.witness.return_data(),
        }
        .clone()
    }
    fn selector_verifier<F: PrimeField>(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<F>, FieldCT<F>, MegaFlavour>,
    ) -> FieldCT<F> {
        match bus_idx {
            BusData::BusIdx0 => input.precomputed.q_l(),
            BusData::BusIdx1 => input.precomputed.q_r(),
            BusData::BusIdx2 => input.precomputed.q_o(),
        }
        .clone()
    }

    fn inverses_verifier<F: PrimeField>(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<F>, FieldCT<F>, MegaFlavour>,
    ) -> FieldCT<F> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_inverses(),
            BusData::BusIdx1 => input.witness.secondary_calldata_inverses(),
            BusData::BusIdx2 => input.witness.return_data_inverses(),
        }
        .clone()
    }
    fn read_counts_verifier<F: PrimeField>(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<F>, FieldCT<F>, MegaFlavour>,
    ) -> FieldCT<F> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_read_counts(),
            BusData::BusIdx1 => input.witness.secondary_calldata_read_counts(),
            BusData::BusIdx2 => input.witness.return_data_read_counts(),
        }
        .clone()
    }

    fn read_tags_verifier<F: PrimeField>(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<F>, FieldCT<F>, MegaFlavour>,
    ) -> FieldCT<F> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_read_tags(),
            BusData::BusIdx1 => input.witness.secondary_calldata_read_tags(),
            BusData::BusIdx2 => input.witness.return_data_read_tags(),
        }
        .clone()
    }

    fn compute_inverse_exists_verifier<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let is_read_gate =
            DataBusLookupRelation::get_read_selector_verifier(bus_idx, input, builder, driver)?;
        let read_tag = DataBusLookupRelation::read_tags_verifier(bus_idx, input);
        let add = is_read_gate.add(&read_tag, builder, driver);
        let mul = is_read_gate.multiply(&read_tag, builder, driver)?;
        Ok(add.sub(&mul, builder, driver))
    }

    fn get_read_selector_verifier<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let q_busread = input.precomputed.q_busread();
        let column_selector = DataBusLookupRelation::selector_verifier(bus_idx, input);
        Ok(q_busread.multiply(&column_selector, builder, driver)?)
    }

    fn compute_write_term_verifier<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        bus_idx: BusData,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        params: &RelationParameters<FieldCT<C::ScalarField>>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let id = input.precomputed.databus_id();
        let value = DataBusLookupRelation::values_verifier(bus_idx, input);
        let gamma = &params.gamma;
        let beta = &params.beta;

        let res = id.multiply(beta, builder, driver)?;

        // value_i + idx_i * beta + gamma
        Ok(res.add(&value, builder, driver).add(gamma, builder, driver))
    }

    fn compute_read_term_verifier<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        params: &RelationParameters<FieldCT<C::ScalarField>>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        // Bus value stored in w_l, index into bus column stored in w_r
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let gamma = &params.gamma;
        let beta = &params.beta;

        // value + index * beta + gamma
        let res = w_2.multiply(beta, builder, driver)?;
        Ok(res.add(gamma, builder, driver).add(w_1, builder, driver))
    }

    fn accumulate_evaluations_subrelation_contributions<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        accumulator: &mut DataBusLookupRelationEvals<C::ScalarField>,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        params: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        bus_idx: BusData,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let inverses = Self::inverses_verifier(bus_idx, input);
        let read_counts_m = Self::read_counts_verifier(bus_idx, input);
        let read_term = Self::compute_read_term_verifier(input, params, builder, driver)?;
        let write_term =
            Self::compute_write_term_verifier(bus_idx, input, params, builder, driver)?;
        let inverse_exists =
            Self::compute_inverse_exists_verifier(bus_idx, input, builder, driver)?;
        let read_selector = Self::get_read_selector_verifier(bus_idx, input, builder, driver)?;

        // Determine which pair of subrelations to update based on which bus column is being read
        let subrel_idx_1: u32 = 2u32 * (bus_idx as u32);
        let subrel_idx_2: u32 = 2u32 * (bus_idx as u32) + 1u32;
        let lhs = [read_term.clone(), read_counts_m];
        let rhs = [write_term.clone(), read_term];
        let mul = FieldCT::multiply_many(&lhs, &rhs, builder, driver)?;

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value
        // is 0 if !inverse_exists. Degree 3 (5)
        let mul_2 = mul[0].multiply(&inverses, builder, driver)?; //TACEO TODO: combine this mul into the mul above by writing a custom multiplication function
        let tmp = mul_2.sub(&inverse_exists, builder, driver);
        let tmp = scaling_factor.multiply(&tmp, builder, driver)?;
        match subrel_idx_1 {
            0 => {
                accumulator.r0 = accumulator.r0.add(&tmp, builder, driver);
            }
            2 => {
                accumulator.r2 = accumulator.r2.add(&tmp, builder, driver);
            }
            4 => {
                accumulator.r4 = accumulator.r4.add(&tmp, builder, driver);
            }
            _ => panic!("unexpected subrel_idx_1"),
        }

        // Establish validity of the read. Note: no scaling factor here since this constraint is enforced across the
        // entire trace, not on a per-row basis.
        let tmp = read_selector
            .multiply(&write_term, builder, driver)?
            .sub(&mul[1], builder, driver)
            .multiply(&inverses, builder, driver)?;
        match subrel_idx_2 {
            1 => {
                accumulator.r1 = accumulator.r1.add(&tmp, builder, driver);
            }
            3 => {
                accumulator.r3 = accumulator.r3.add(&tmp, builder, driver);
            }
            5 => {
                accumulator.r5 = accumulator.r5.add(&tmp, builder, driver);
            }
            _ => panic!("unexpected subrel_idx_2"),
        } // Deg 4 (5)
        Ok(())
    }
}

impl<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> Relation<C>
    for DataBusLookupRelation
{
    type VerifyAcc = DataBusLookupRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // Accumulate the subrelation contributions for each column of the databus
        // TODO this can be parallelized
        for bus_idx in 0..Self::NUM_BUS_COLUMNS {
            DataBusLookupRelation::accumulate_evaluations_subrelation_contributions(
                accumulator,
                input,
                relation_parameters,
                scaling_factor,
                BusData::from(bus_idx),
                builder,
                driver,
            )?;
        }
        Ok(())
    }
}
