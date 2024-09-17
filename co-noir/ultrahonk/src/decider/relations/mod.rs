pub(crate) mod auxiliary_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use super::{
    sumcheck::sumcheck_round::SumcheckRoundOutput,
    types::{ProverUnivariates, RelationParameters},
};
use ark_ff::PrimeField;
use auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc};
use delta_range_constraint_relation::{
    DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
};
use elliptic_relation::{EllipticRelation, EllipticRelationAcc};
use logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationAcc};
use permutation_relation::{UltraPermutationRelation, UltraPermutationRelationAcc};
use poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc};
use poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationAcc};
use ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationAcc};

pub(crate) trait Relation<F: PrimeField> {
    type Acc: Default;
    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip(input: &ProverUnivariates<F>) -> bool;
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
}

pub(crate) const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
    + UltraPermutationRelation::NUM_RELATIONS
    + DeltaRangeConstraintRelation::NUM_RELATIONS
    + EllipticRelation::NUM_RELATIONS
    + AuxiliaryRelation::NUM_RELATIONS
    + LogDerivLookupRelation::NUM_RELATIONS
    + Poseidon2ExternalRelation::NUM_RELATIONS
    + Poseidon2InternalRelation::NUM_RELATIONS;

#[derive(Default)]
pub(crate) struct AllRelationAcc<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_aux: AuxiliaryRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
}

impl<F: PrimeField> AllRelationAcc<F> {
    pub fn scale(&mut self, first_scalar: F, elements: &[F]) {
        assert!(elements.len() == NUM_SUBRELATIONS - 1);
        self.r_arith.scale(&[first_scalar, elements[0]]);
        self.r_perm.scale(&elements[1..3]);
        self.r_delta.scale(&elements[3..7]);
        self.r_elliptic.scale(&elements[7..11]);
        self.r_aux.scale(&elements[11..17]);
        self.r_lookup.scale(&elements[17..19]);
        self.r_pos_ext.scale(&elements[19..23]);
        self.r_pos_int.scale(&elements[23..]);
    }

    pub fn extend_and_batch_univariates(
        &self,
        result: &mut SumcheckRoundOutput<F>,
        extended_random_poly: &SumcheckRoundOutput<F>,
        partial_evaluation_result: &F,
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
        self.r_lookup.extend_and_batch_univariates(
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
