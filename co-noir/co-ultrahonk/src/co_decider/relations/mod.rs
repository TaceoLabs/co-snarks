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
pub(crate) mod ultra_arithmetic_relation;

use super::types::{ProverUnivariates, ProverUnivariatesBatch, RelationParameters};
use crate::types::AllEntities;
use crate::{mpc_prover_flavour::MPCProverFlavour, types_batch::SumCheckDataForRelation};
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_noir_common::mpc::NoirUltraHonkProver;
use mpc_net::Network;

macro_rules! fold_accumulator {
    ($acc: expr, $elements: expr, $size: expr) => {
        let evaluations_len = $acc.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); $size];
        acc[..evaluations_len].clone_from_slice(&$acc.evaluations);
        for (idx, b) in $elements.iter().enumerate() {
            let i = idx % $size;
            let a = &mut acc[i];
            T::add_assign(a, *b);
        }
        $acc.evaluations.clone_from_slice(&acc[..evaluations_len]);
    };
}

#[macro_export]
macro_rules! fold_type_accumulator {
    ($acc_type:ident, $accumulator:expr, $subrelation:ident, $value:expr, $size:expr) => {
        match $accumulator {
            $acc_type::Partial(acc) => {
                fold_accumulator!(acc.$subrelation, $value, $size);
            }
            $acc_type::Total(acc) => {
                fold_accumulator!(acc.$subrelation, $value, $size);
            }
        }
    };
}

pub(crate) use fold_accumulator;
use ultrahonk::prelude::Univariate;

// This will be used inside the relations for with_min_len for rayons par_iter.
// 0xThemis TODO We may want to have this configurable by environment or remove it as a whole.
// We need bench marks for this when everything is done.
const MIN_RAYON_ITER: usize = 1024;

pub(crate) trait Relation<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    L: MPCProverFlavour,
>
{
    type Acc: Default;
    type VerifyAcc: Default;

    fn add_edge(
        entity: &ProverUnivariates<T, P, L>,
        scaling_factor: P::ScalarField,
        data: &mut SumCheckDataForRelation<T, P, L>,
    ) {
        if !Self::can_skip(entity) {
            data.can_skip = false;
            Self::add_entities(entity, &mut data.all_entities);
            for _ in 0..L::MAX_PARTIAL_RELATION_LENGTH {
                data.scaling_factors.push(scaling_factor);
            }
        }
    }

    fn can_skip(entity: &ProverUnivariates<T, P, L>) -> bool;

    fn add_entities(
        entity: &ProverUnivariates<T, P, L>,
        batch: &mut ProverUnivariatesBatch<T, P, L>,
    );

    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, L>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()>;

    fn accumulate_with_extended_parameters<N: Network, const SIZE: usize>(
        _net: &N,
        _state: &mut T::State,
        _univariate_accumulator: &mut Self::Acc,
        _input: &ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<Univariate<P::ScalarField, SIZE>>,
        _scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        panic!("accumulate_with_extended_parameters is not implemented for this relation");
    }

    fn accumulate_evaluations<N: Network>(
        _net: &N,
        _state: &mut T::State,
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &AllEntities<T::ArithmeticShare, P::ScalarField, L>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        _scaling_factor: &P::ScalarField,
    ) -> HonkProofResult<()> {
        panic!("accumulate_evaluations is not implemented for this relation");
    }
}

#[macro_export]
macro_rules! impl_relation_acc_type_methods {
    ($acc_type:ident) => {
        impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for $acc_type<T, P> {
            fn default() -> Self {
                $acc_type::Partial(Default::default())
            }
        }

        impl<T: NoirUltraHonkProver<P>, P: CurveGroup> $acc_type<T, P> {
            pub(crate) fn default_total() -> Self {
                $acc_type::Total(Default::default())
            }

            pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
                match self {
                    $acc_type::Partial(acc) => acc.scale(elements),
                    $acc_type::Total(acc) => acc.scale(elements),
                }
            }

            pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
                &self,
                result: &mut SharedUnivariate<T, P, SIZE>,
                extended_random_poly: &Univariate<P::ScalarField, SIZE>,
                partial_evaluation_result: &P::ScalarField,
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
                result: &mut SharedUnivariate<T, P, SIZE>,
                running_challenge: &[Univariate<P::ScalarField, SIZE>],
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
