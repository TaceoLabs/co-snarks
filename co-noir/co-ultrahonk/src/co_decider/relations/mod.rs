pub(crate) mod auxiliary_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use super::{
    types::{
        MAX_PARTIAL_RELATION_LENGTH, ProverUnivariates, ProverUnivariatesBatch, RelationParameters,
    },
    univariates::SharedUnivariate,
};
use crate::{mpc::NoirUltraHonkProver, types_batch::SumCheckDataForRelation};
use ark_ec::pairing::Pairing;
use auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc};
use co_builder::HonkProofResult;
use co_builder::prelude::HonkCurve;
use delta_range_constraint_relation::{
    DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
};
use elliptic_relation::{EllipticRelation, EllipticRelationAcc};
use logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationAcc};
use mpc_net::Network;
use permutation_relation::{UltraPermutationRelation, UltraPermutationRelationAcc};
use poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc};
use poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationAcc};
use ultra_arithmetic_relation::{
    UltraArithmeticRelation, UltraArithmeticRelationAcc, UltraArithmeticRelationAccHalfShared,
};
use ultrahonk::prelude::{TranscriptFieldType, Univariate};

macro_rules! fold_accumulator {
    ($acc: expr, $elements: expr) => {
        let evaluations_len = $acc.evaluations.len();
        let mut acc = [T::ArithmeticShare::default(); MAX_PARTIAL_RELATION_LENGTH];
        acc[..evaluations_len].clone_from_slice(&$acc.evaluations);
        for (idx, b) in $elements.iter().enumerate() {
            let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
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

pub(crate) trait Relation<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> {
    type Acc: Default;

    fn add_edge(
        entity: &ProverUnivariates<T, P>,
        scaling_factor: P::ScalarField,
        data: &mut SumCheckDataForRelation<T, P>,
    ) {
        if !Self::can_skip(entity) {
            let scaling_factors = vec![scaling_factor; MAX_PARTIAL_RELATION_LENGTH];
            data.can_skip = false;
            Self::add_entites(entity, &mut data.all_entites);
            data.scaling_factors.extend(scaling_factors);
        }
    }

    fn can_skip(entity: &ProverUnivariates<T, P>) -> bool;

    fn add_entites(entity: &ProverUnivariates<T, P>, batch: &mut ProverUnivariatesBatch<T, P>);

    fn accumulate<N: Network>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()>;
}

pub(crate) const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
    + UltraPermutationRelation::NUM_RELATIONS
    + LogDerivLookupRelation::NUM_RELATIONS
    + DeltaRangeConstraintRelation::NUM_RELATIONS
    + EllipticRelation::NUM_RELATIONS
    + AuxiliaryRelation::NUM_RELATIONS
    + Poseidon2ExternalRelation::NUM_RELATIONS
    + Poseidon2InternalRelation::NUM_RELATIONS;

pub const CRAND_PAIRS_FACTOR: usize = AuxiliaryRelation::CRAND_PAIRS_FACTOR
    + DeltaRangeConstraintRelation::CRAND_PAIRS_FACTOR
    + EllipticRelation::CRAND_PAIRS_FACTOR
    + LogDerivLookupRelation::CRAND_PAIRS_FACTOR
    + UltraPermutationRelation::CRAND_PAIRS_FACTOR
    + Poseidon2ExternalRelation::CRAND_PAIRS_FACTOR
    + Poseidon2InternalRelation::CRAND_PAIRS_FACTOR
    + UltraArithmeticRelation::CRAND_PAIRS_FACTOR;

pub(crate) struct AllRelationAcc<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<T, P>,
    pub(crate) r_perm: UltraPermutationRelationAcc<T, P>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<T, P>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_elliptic: EllipticRelationAcc<T, P>,
    pub(crate) r_aux: AuxiliaryRelationAcc<T, P>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<T, P>,
}

pub(crate) struct AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) r_arith: UltraArithmeticRelationAccHalfShared<T, P>,
    pub(crate) r_perm: UltraPermutationRelationAcc<T, P>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<T, P>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_elliptic: EllipticRelationAcc<T, P>,
    pub(crate) r_aux: AuxiliaryRelationAcc<T, P>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<T, P>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> AllRelationAccHalfShared<T, P> {
    pub(crate) fn reshare<N: Network>(
        self,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<AllRelationAcc<T, P>> {
        let r_arith_r0 = T::reshare(self.r_arith.r0.evaluations.to_vec(), net, state)?;
        Ok(AllRelationAcc {
            r_arith: UltraArithmeticRelationAcc {
                r0: SharedUnivariate::from_vec(r_arith_r0),
                r1: self.r_arith.r1,
            },
            r_perm: self.r_perm,
            r_lookup: self.r_lookup,
            r_delta: self.r_delta,
            r_elliptic: self.r_elliptic,
            r_aux: self.r_aux,
            r_pos_ext: self.r_pos_ext,
            r_pos_int: self.r_pos_int,
        })
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for AllRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r_arith: Default::default(),
            r_perm: Default::default(),
            r_lookup: Default::default(),
            r_delta: Default::default(),
            r_elliptic: Default::default(),
            r_aux: Default::default(),
            r_pos_ext: Default::default(),
            r_pos_int: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Default for AllRelationAccHalfShared<T, P> {
    fn default() -> Self {
        Self {
            r_arith: Default::default(),
            r_perm: Default::default(),
            r_lookup: Default::default(),
            r_delta: Default::default(),
            r_elliptic: Default::default(),
            r_aux: Default::default(),
            r_pos_ext: Default::default(),
            r_pos_int: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> AllRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, first_scalar: P::ScalarField, elements: &[P::ScalarField]) {
        assert!(elements.len() == NUM_SUBRELATIONS - 1);
        self.r_arith.scale(&[first_scalar, elements[0]]);
        self.r_perm.scale(&elements[1..3]);
        self.r_lookup.scale(&elements[3..5]);
        self.r_delta.scale(&elements[5..9]);
        self.r_elliptic.scale(&elements[9..11]);
        self.r_aux.scale(&elements[11..17]);
        self.r_pos_ext.scale(&elements[17..21]);
        self.r_pos_int.scale(&elements[21..]);
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut SharedUnivariate<T, P, SIZE>,
        extended_random_poly: &Univariate<P::ScalarField, SIZE>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        self.r_arith.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_perm.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_lookup.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_delta.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_elliptic.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_aux.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_pos_ext.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_pos_int.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
    }
}
