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

use super::types::{ProverUnivariates, ProverUnivariatesBatch, RelationParameters};
use crate::{
    mpc::NoirUltraHonkProver, mpc_prover_flavour::MPCProverFlavour,
    types_batch::SumCheckDataForRelation,
};
use co_builder::prelude::HonkCurve;
use co_builder::{HonkProofResult, TranscriptFieldType};
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

pub(crate) use fold_accumulator;

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

    fn add_edge(
        entity: &ProverUnivariates<T, P, L>,
        scaling_factor: P::ScalarField,
        data: &mut SumCheckDataForRelation<T, P, L>,
    ) {
        if !Self::can_skip(entity) {
            data.can_skip = false;
            Self::add_entities(entity, &mut data.all_entites);
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
        relation_parameters: &RelationParameters<P::ScalarField, L>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()>;
}
