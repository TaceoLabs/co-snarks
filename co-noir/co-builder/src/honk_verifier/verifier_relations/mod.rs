pub(crate) mod delta_range_constraint_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod memory_relation;
pub(crate) mod non_native_field_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use crate::accumulate_all_relations;
use crate::honk_verifier::sumcheck::SumcheckVerifier;
use crate::honk_verifier::verifier_relations::memory_relation::MemoryRelation;
use crate::honk_verifier::verifier_relations::memory_relation::MemoryRelationEvals;
use crate::honk_verifier::verifier_relations::non_native_field_relation::NonNativeFieldRelation;
use crate::honk_verifier::verifier_relations::non_native_field_relation::NonNativeFieldRelationEvals;
use crate::honk_verifier::verifier_relations::{
    delta_range_constraint_relation::{
        DeltaRangeConstraintRelation, DeltaRangeConstraintRelationEvals,
    },
    elliptic_relation::{EllipticRelation, EllipticRelationEvals},
    logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationEvals},
    permutation_relation::{UltraPermutationRelation, UltraPermutationRelationEvals},
    poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationEvals},
    poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationEvals},
    ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationEvals},
};
use crate::prelude::GenericUltraCircuitBuilder;
use crate::scale_and_batch_all;
use crate::types::field_ct::FieldCT;
use crate::types::gate_separator::GateSeparatorPolynomial;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use itertools::izip;

#[derive(Default)]
pub struct AllRelationsEvals<F: PrimeField> {
    r_arith: UltraArithmeticRelationEvals<F>,
    r_perm: UltraPermutationRelationEvals<F>,
    r_lookup: LogDerivLookupRelationEvals<F>,
    r_delta: DeltaRangeConstraintRelationEvals<F>,
    r_elliptic: EllipticRelationEvals<F>,
    r_memory: MemoryRelationEvals<F>,
    r_nnf: NonNativeFieldRelationEvals<F>,
    r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    r_pos_int: Poseidon2InternalRelationEvals<F>,
}

pub(crate) const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
    + UltraPermutationRelation::NUM_RELATIONS
    + DeltaRangeConstraintRelation::NUM_RELATIONS
    + EllipticRelation::NUM_RELATIONS
    + MemoryRelation::NUM_RELATIONS
    + NonNativeFieldRelation::NUM_RELATIONS
    + LogDerivLookupRelation::NUM_RELATIONS
    + Poseidon2ExternalRelation::NUM_RELATIONS
    + Poseidon2InternalRelation::NUM_RELATIONS;

pub(crate) trait VerifyAccGetter<C: HonkCurve<TranscriptFieldType>> {
    fn get_accumulators(&self) -> Vec<FieldCT<C::ScalarField>>;
}

/// Adds `sum_j entry_j * challenge_j * rd_factor` to `result`, where `rd_factor` is the optional row-disabling
/// factor (used in ZK flavors).
///
/// All multiplications are batched into (at most) two `mul_many` calls, but the gates are created in the same
/// order as the sequential `entry * challenge`, `* rd_factor`, `+=` evaluation, so the circuit is unchanged.
fn scale_by_challenge_and_accumulate<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    result: &mut FieldCT<C::ScalarField>,
    entries: &[FieldCT<C::ScalarField>],
    challenges: &[FieldCT<C::ScalarField>],
    rd_factor: Option<&FieldCT<C::ScalarField>>,
    builder: &mut GenericUltraCircuitBuilder<C, T>,
    driver: &mut T,
) -> HonkProofResult<()> {
    debug_assert_eq!(entries.len(), challenges.len());
    // A constant challenge of one marks the first subrelation, which is not scaled and overwrites the result
    let is_first = challenges
        .iter()
        .map(|challenge| {
            challenge.is_constant()
                && challenge.get_value(builder, driver) == C::ScalarField::ONE.into()
        })
        .collect::<Vec<_>>();
    // The first subrelation is not multiplied by its challenge, so we use the constant one instead
    let challenges = izip!(challenges, &is_first)
        .map(|(challenge, is_first)| {
            if *is_first {
                FieldCT::from(C::ScalarField::ONE)
            } else {
                challenge.clone()
            }
        })
        .collect::<Vec<_>>();

    let mut scaled = FieldCT::multiply_many_raw(entries, &challenges, builder, driver)?;

    let Some(rd_factor) = rd_factor else {
        for (mut scaled, is_first) in izip!(scaled, is_first) {
            let tmp = FieldCT::commit_mul(&mut scaled, builder)?;
            if is_first {
                *result = tmp;
            } else {
                result.add_assign(&tmp, builder, driver);
            }
        }
        return Ok(());
    };

    // The second batch of multiplications needs the products of the first one as inputs, so we create their
    // variables now and defer only their gates
    let scaled_values = scaled
        .iter_mut()
        .map(|(raw, res)| match (raw, res) {
            (Some((poly_triple, out_value)), _) => {
                poly_triple.c = builder.add_variable(out_value.clone());
                Ok(FieldCT::from_witness_index(poly_triple.c))
            }
            (None, Some(res)) => Ok(res.clone()),
            (None, None) => eyre::bail!("Invalid mul_raw_data: both fields are None"),
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    let rd_factors = vec![rd_factor.clone(); scaled_values.len()];
    let mut rd_scaled = FieldCT::multiply_many_raw(&scaled_values, &rd_factors, builder, driver)?;

    for (scaled, rd_scaled, is_first) in izip!(scaled, rd_scaled.iter_mut(), is_first) {
        if let Some((poly_triple, _)) = scaled.0 {
            builder.create_arithmetic_gate(&poly_triple);
        }
        let tmp = FieldCT::commit_mul(rd_scaled, builder)?;
        if is_first {
            *result = tmp;
        } else {
            result.add_assign(&tmp, builder, driver);
        }
    }
    Ok(())
}

pub(crate) trait Relation<C: HonkCurve<TranscriptFieldType>> {
    type VerifyAcc: Default + VerifyAccGetter<C> + Send + Sync;
    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        _scaling_factor: &FieldCT<C::ScalarField>,
        _builder: &mut GenericUltraCircuitBuilder<C, T>,
        _driver: &mut T,
    ) -> HonkProofResult<()> {
        panic!("accumulate_evaluations is not implemented for this relation");
    }
}

/// Evaluates the full Honk relation at the sumcheck challenge. For ZK flavors, `multivariate_challenge` is
/// provided and every relation is scaled by the row-disabling factor `(1 - L)(u)`.
#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_full_relation_purported_value<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    purported_evaluations: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
    univariate_accumulators: &mut AllRelationsEvals<C::ScalarField>,
    relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
    gate_separators: GateSeparatorPolynomial<C>,
    alphas: &[FieldCT<C::ScalarField>],
    multivariate_challenge: Option<&[FieldCT<C::ScalarField>]>,
    builder: &mut GenericUltraCircuitBuilder<C, T>,
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

    let rd_factor = multivariate_challenge
        .map(|challenge| {
            SumcheckVerifier::evaluate_at_challenge_with_padding(challenge, builder, driver)
        })
        .transpose()?;

    let mut output = FieldCT::from(C::ScalarField::ZERO);
    let first_scalar = FieldCT::from(C::ScalarField::ONE);
    scale_and_batch_all!(
        &mut output,
        &univariate_accumulators,
        first_scalar,
        alphas,
        rd_factor.as_ref(),
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
        process_relation!(UltraPermutationRelation, r_perm);
        process_relation!(LogDerivLookupRelation, r_lookup);
        process_relation!(UltraArithmeticRelation, r_arith);
        process_relation!(DeltaRangeConstraintRelation, r_delta);
        process_relation!(EllipticRelation, r_elliptic);
        process_relation!(MemoryRelation, r_memory);
        process_relation!(NonNativeFieldRelation, r_nnf);
        process_relation!(Poseidon2ExternalRelation, r_pos_ext);
        process_relation!(Poseidon2InternalRelation, r_pos_int);

        HonkProofResult::Ok(())
    }};
}

#[macro_export]
macro_rules! scale_and_batch_all {
    ($output:expr, $univariate_accumulators:expr, $first_scalar:expr, $challenges:ident, $rd_factor:expr, $builder:expr, $driver:expr) => {{
        // Collect the entries and challenges of all relations, so that they can be scaled in one batch
        let mut entries = Vec::with_capacity(NUM_SUBRELATIONS);
        let mut scaling_challenges = Vec::with_capacity(NUM_SUBRELATIONS);
        macro_rules! process_relation {
            ($relation_accumulator:ident, $relevant_challenges:expr) => {
                let accumulators = VerifyAccGetter::<C>::get_accumulators(
                    &$univariate_accumulators.$relation_accumulator,
                );
                let relevant_challenges: &[FieldCT<_>] = $relevant_challenges;
                assert_eq!(accumulators.len(), relevant_challenges.len());
                entries.extend(accumulators);
                scaling_challenges.extend_from_slice(relevant_challenges);
            };
        }

        // Apply to all relations
        process_relation!(
            r_perm,
            &[
                $first_scalar,
                $challenges[0].clone(),
                $challenges[1].clone()
            ]
        );
        process_relation!(r_lookup, &$challenges[2..5]);
        process_relation!(r_arith, &$challenges[5..7]);
        process_relation!(r_delta, &$challenges[7..11]);
        process_relation!(r_elliptic, &$challenges[11..13]);
        process_relation!(r_memory, &$challenges[13..19]);
        process_relation!(r_nnf, &$challenges[19..20]);
        process_relation!(r_pos_ext, &$challenges[20..24]);
        process_relation!(r_pos_int, &$challenges[24..]);

        scale_by_challenge_and_accumulate(
            $output,
            &entries,
            &scaling_challenges,
            $rd_factor,
            $builder,
            $driver,
        )
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

        impl<C: HonkCurve<TranscriptFieldType>> VerifyAccGetter<C>
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
