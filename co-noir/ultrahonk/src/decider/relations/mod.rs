pub(crate) mod auxiliary_relation;
pub(crate) mod databus_lookup_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod ecc_op_queue_relation;
pub(crate) mod eccvm_relations;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod translator_relations;
pub(crate) mod ultra_arithmetic_relation;

use super::types::{ClaimedEvaluations, RelationParameters};
use crate::decider::types::ProverUnivariatesSized;
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::prelude::Univariate;
use ark_ff::PrimeField;

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
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );

    fn accumulate_with_extended_parameters<const SIZE: usize>(
        _univariate_accumulator: &mut Self::Acc,
        _input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<Univariate<F, SIZE>>,
        _scaling_factor: &F,
    ) {
        unimplemented!("accumulate_with_extended_parameters is not implemented for this relation");
    }

    fn verify_accumulate(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &ClaimedEvaluations<F, L>,
        _relation_parameters: &RelationParameters<F>,
        _scaling_factor: &F,
    ) {
        unimplemented!("verify_accumulate is not implemented for this relation");
    }
}

#[macro_export]
macro_rules! impl_relation_acc_type_methods {
    ($acc_type:ident<$f:ident>) => {
        impl<$f: PrimeField> Default for $acc_type<$f> {
            fn default() -> Self {
                $acc_type::Partial(Default::default())
            }
        }

        impl<$f: PrimeField> $acc_type<$f> {
            pub(crate) fn default_total() -> Self {
                $acc_type::Total(Default::default())
            }

            pub(crate) fn scale(&mut self, elements: &[$f]) {
                match self {
                    $acc_type::Partial(acc) => acc.scale(elements),
                    $acc_type::Total(acc) => acc.scale(elements),
                }
            }

            pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
                &self,
                result: &mut Univariate<$f, SIZE>,
                extended_random_poly: &Univariate<$f, SIZE>,
                partial_evaluation_result: &$f,
            ) {
                match self {
                    $acc_type::Partial(acc) => acc.extend_and_batch_univariates(
                        result,
                        extended_random_poly,
                        partial_evaluation_result,
                    ),
                    $acc_type::Total(acc) => acc.extend_and_batch_univariates(
                        result,
                        extended_random_poly,
                        partial_evaluation_result,
                    ),
                }
            }

            pub(crate) fn extend_and_batch_univariates_with_distinct_challenges<
                const SIZE: usize,
            >(
                &self,
                result: &mut Univariate<$f, SIZE>,
                running_challenge: &[Univariate<$f, SIZE>],
            ) {
                match self {
                    $acc_type::Partial(acc) => acc
                        .extend_and_batch_univariates_with_distinct_challenges(
                            result,
                            running_challenge,
                        ),
                    $acc_type::Total(acc) => acc
                        .extend_and_batch_univariates_with_distinct_challenges(
                            result,
                            running_challenge,
                        ),
                }
            }
        }
    };
}

#[macro_export]
macro_rules! assign_subrelation_evals {
    ($acc_type:ident, $accumulator:expr, $subrelation:ident, $value:expr) => {
        match $accumulator {
            $acc_type::Partial(acc) => {
                for i in 0..acc.$subrelation.evaluations.len() {
                    acc.$subrelation.evaluations[i] += $value[i];
                }
            }
            $acc_type::Total(acc) => {
                for i in 0..acc.$subrelation.evaluations.len() {
                    acc.$subrelation.evaluations[i] += $value[i];
                }
            }
        }
    };
}
