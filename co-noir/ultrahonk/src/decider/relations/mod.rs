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

use super::types::{ClaimedEvaluations, ProverUnivariates, RelationParameters};
use crate::decider::types::ProverUnivariatesSized;
use crate::{plain_prover_flavour::PlainProverFlavour, prelude::Univariate};
use ark_ff::PrimeField;
use auxiliary_relation::AuxiliaryRelation;
use co_builder::prelude::Polynomial;
use co_builder::prover_flavour::ProverFlavour;
use databus_lookup_relation::DataBusLookupRelation;
use delta_range_constraint_relation::DeltaRangeConstraintRelation;
use ecc_op_queue_relation::EccOpQueueRelation;
use elliptic_relation::EllipticRelation;
use logderiv_lookup_relation::LogDerivLookupRelation;
use permutation_relation::UltraPermutationRelation;
use poseidon2_external_relation::Poseidon2ExternalRelation;
use poseidon2_internal_relation::Poseidon2InternalRelation;
use ultra_arithmetic_relation::UltraArithmeticRelation;

pub(crate) trait Relation<F: PrimeField, L: PlainProverFlavour> {
    type Acc: Default;
    type VerifyAcc: Default;

    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool;
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    );

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    );
}

// // TODO FLORIN: THIS IS MEGA FN
// pub(crate) const NUM_SUBRELATIONS_ONLY_VERIFIER: usize = UltraArithmeticRelation::NUM_RELATIONS
//     + UltraPermutationRelation::NUM_RELATIONS
//     + DeltaRangeConstraintRelation::NUM_RELATIONS
//     + EllipticRelation::NUM_RELATIONS
//     + AuxiliaryRelation::NUM_RELATIONS
//     + LogDerivLookupRelation::NUM_RELATIONS
//     + EccOpQueueRelation::NUM_RELATIONS
//     + DataBusLookupRelation::NUM_RELATIONS
//     + Poseidon2ExternalRelation::NUM_RELATIONS
//     + Poseidon2InternalRelation::NUM_RELATIONS;
