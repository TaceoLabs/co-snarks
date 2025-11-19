pub(crate) mod auxiliary_relation;
pub(crate) mod databus_lookup_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod ecc_op_queue_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use crate::accumulate_all_relations;
use crate::scale_and_batch_all;
use crate::verifier_relations::{
    auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationEvals},
    databus_lookup_relation::{DataBusLookupRelation, DataBusLookupRelationEvals},
    delta_range_constraint_relation::{
        DeltaRangeConstraintRelation, DeltaRangeConstraintRelationEvals,
    },
    ecc_op_queue_relation::{EccOpQueueRelation, EccOpQueueRelationEvals},
    elliptic_relation::{EllipticRelation, EllipticRelationEvals},
    logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationEvals},
    permutation_relation::{UltraPermutationRelation, UltraPermutationRelationEvals},
    poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationEvals},
    poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationEvals},
    ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationEvals},
};
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::mega_builder::MegaCircuitBuilder;
use co_builder::types::field_ct::FieldCT;
use co_builder::types::gate_separator::GateSeparatorPolynomial;
use co_builder::{flavours::mega_flavour::MegaFlavour, transcript::TranscriptFieldType};
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use co_ultrahonk::{co_decider::types::RelationParameters, types::AllEntities};

#[derive(Default)]
pub struct AllRelationsEvals<F: PrimeField> {
    r_arith: UltraArithmeticRelationEvals<F>,
    r_perm: UltraPermutationRelationEvals<F>,
    r_lookup: LogDerivLookupRelationEvals<F>,
    r_delta: DeltaRangeConstraintRelationEvals<F>,
    r_elliptic: EllipticRelationEvals<F>,
    r_aux: AuxiliaryRelationEvals<F>,
    r_ecc_op_queue: EccOpQueueRelationEvals<F>,
    r_databus: DataBusLookupRelationEvals<F>,
    r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    r_pos_int: Poseidon2InternalRelationEvals<F>,
}

pub(crate) trait VerifyAccGetter<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
>
{
    fn get_accumulators(&self) -> Vec<FieldCT<C::ScalarField>>;
    fn scale_by_challenge_and_accumulate<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &self,
        result: &mut FieldCT<C::ScalarField>,
        challenges: &[FieldCT<C::ScalarField>],
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        for (entry, challenge) in self.get_accumulators().iter().zip(challenges) {
            *result = entry.madd(challenge, result, builder, driver)?;
        }
        Ok(())
    }
}

pub(crate) trait Relation<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> {
    type VerifyAcc: Default + VerifyAccGetter<C> + Send + Sync;
    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        _scaling_factor: &FieldCT<C::ScalarField>,
        _builder: &mut MegaCircuitBuilder<C, T>,
        _driver: &mut T,
    ) -> HonkProofResult<()> {
        panic!("accumulate_evaluations is not implemented for this relation");
    }
}

pub(crate) fn compute_full_relation_purported_value<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    purported_evaluations: &AllEntities<
        FieldCT<C::ScalarField>,
        FieldCT<C::ScalarField>,
        MegaFlavour,
    >,
    univariate_accumulators: &mut AllRelationsEvals<C::ScalarField>,
    relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
    gate_separators: GateSeparatorPolynomial<C>,
    alphas: &[FieldCT<C::ScalarField>],
    builder: &mut MegaCircuitBuilder<C, T>,
    driver: &mut T,
) -> HonkProofResult<FieldCT<C::ScalarField>> {
    accumulate_all_relations!(
        univariate_accumulators,
        purported_evaluations,
        relation_parameters,
        &gate_separators.partial_evaluation_result,
        builder,
        driver
    )?;

    let mut output = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
    let first_scalar = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
    scale_and_batch_all!(
        &mut output,
        &univariate_accumulators,
        first_scalar,
        alphas,
        builder,
        driver
    )?;

    Ok(output)
}

#[macro_export]
macro_rules! accumulate_all_relations {
    ($univariate_accumulators:expr, $input:expr, $relation_parameters:expr, $scaling_factor:expr, $builder:expr, $driver:expr) => {{
        // Helper macro to process each relation
        macro_rules! process_relation {
            ($relation:ident, $relation_accumulator:ident) => {
                $relation::accumulate_evaluations(
                    &mut $univariate_accumulators.$relation_accumulator,
                    $input,
                    $relation_parameters,
                    $scaling_factor,
                    $builder,
                    $driver,
                )?;
            };
        }

        // Apply to all relations
        process_relation!(UltraArithmeticRelation, r_arith);
        process_relation!(UltraPermutationRelation, r_perm);
        process_relation!(LogDerivLookupRelation, r_lookup);
        process_relation!(DeltaRangeConstraintRelation, r_delta);
        process_relation!(EllipticRelation, r_elliptic);
        process_relation!(AuxiliaryRelation, r_aux);
        process_relation!(EccOpQueueRelation, r_ecc_op_queue);
        process_relation!(DataBusLookupRelation, r_databus);
        process_relation!(Poseidon2ExternalRelation, r_pos_ext);
        process_relation!(Poseidon2InternalRelation, r_pos_int);

        HonkProofResult::Ok(())
    }};
}

#[macro_export]
macro_rules! scale_and_batch_all {
    ($output:expr, $univariate_accumulators:expr, $first_scalar:expr, $challenges:ident, $builder:expr, $driver:expr) => {{
        // Helper macro to process each relation
        macro_rules! process_relation {
            ($relation_accumulator:ident, $relevant_challenges:expr) => {
                $univariate_accumulators
                    .$relation_accumulator
                    .scale_by_challenge_and_accumulate(
                        $output,
                        $relevant_challenges,
                        $builder,
                        $driver,
                    )?;
            };
        }

        // Apply to all relations
        process_relation!(r_arith, &[$first_scalar, $challenges[0].clone()]);
        process_relation!(r_perm, &$challenges[1..3]);
        process_relation!(r_lookup, &$challenges[3..5]);
        process_relation!(r_delta, &$challenges[5..9]);
        process_relation!(r_elliptic, &$challenges[9..11]);
        process_relation!(r_aux, &$challenges[11..17]);
        process_relation!(r_ecc_op_queue, &$challenges[17..25]);
        process_relation!(r_databus, &$challenges[25..31]);
        process_relation!(r_pos_ext, &$challenges[31..35]);
        process_relation!(r_pos_int, &$challenges[35..]);

        HonkProofResult::Ok(())
    }};
}

#[macro_export]
macro_rules! impl_relation_evals {
    ($struct_name:ident, $($field_name:ident),*) => {
        impl<F: PrimeField> Default
            for $struct_name<F>
        {
            fn default() -> Self {
                Self {
                    $($field_name: Default::default(),)*
                }
            }
        }

        impl<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> VerifyAccGetter<C>
            for $struct_name<C::ScalarField>
        {
            fn get_accumulators(&self) -> Vec<FieldCT<C::ScalarField>> {
                vec![
                    $(self.$field_name.clone(),)*
                ]
            }
        }
    }
}
