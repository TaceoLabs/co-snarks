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
use crate::plain_prover_flavour::PlainProverFlavour;
use ark_ff::PrimeField;
use auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationEvals};
use delta_range_constraint_relation::{
    DeltaRangeConstraintRelation, DeltaRangeConstraintRelationEvals,
};
use elliptic_relation::{EllipticRelation, EllipticRelationEvals};
use logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationEvals};
use permutation_relation::{UltraPermutationRelation, UltraPermutationRelationEvals};
use poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationEvals};
use poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationEvals};
use ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationEvals};

pub(crate) trait Relation<F: PrimeField, L: PlainProverFlavour<F>> {
    type Acc: Default;
    type VerifyAcc: Default;

    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip(input: &ProverUnivariates<F, L, { L::MAX_PARTIAL_RELATION_LENGTH }>) -> bool;
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F, L, { L::MAX_PARTIAL_RELATION_LENGTH }>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, F, L>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
}

pub(crate) const NUM_SUBRELATIONS_ONLY_VERIFIER: usize = UltraArithmeticRelation::NUM_RELATIONS
    + UltraPermutationRelation::NUM_RELATIONS
    + DeltaRangeConstraintRelation::NUM_RELATIONS
    + EllipticRelation::NUM_RELATIONS
    + AuxiliaryRelation::NUM_RELATIONS
    + LogDerivLookupRelation::NUM_RELATIONS
    + Poseidon2ExternalRelation::NUM_RELATIONS
    + Poseidon2InternalRelation::NUM_RELATIONS;

#[derive(Default)]
pub(crate) struct AllRelationEvaluations<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationEvals<F>,
    pub(crate) r_perm: UltraPermutationRelationEvals<F>,
    pub(crate) r_lookup: LogDerivLookupRelationEvals<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_elliptic: EllipticRelationEvals<F>,
    pub(crate) r_aux: AuxiliaryRelationEvals<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationEvals<F>,
}

impl<F: PrimeField> AllRelationEvaluations<F> {
    pub(crate) fn scale_and_batch_elements(&self, first_scalar: F, elements: &[F]) -> F {
        assert!(elements.len() == NUM_SUBRELATIONS_ONLY_VERIFIER - 1);
        let mut output = F::zero();
        self.r_arith
            .scale_and_batch_elements(&[first_scalar, elements[0]], &mut output);
        self.r_perm
            .scale_and_batch_elements(&elements[1..3], &mut output);
        self.r_lookup
            .scale_and_batch_elements(&elements[3..5], &mut output);
        self.r_delta
            .scale_and_batch_elements(&elements[5..9], &mut output);
        self.r_elliptic
            .scale_and_batch_elements(&elements[9..11], &mut output);
        self.r_aux
            .scale_and_batch_elements(&elements[11..17], &mut output);

        self.r_pos_ext
            .scale_and_batch_elements(&elements[17..21], &mut output);
        self.r_pos_int
            .scale_and_batch_elements(&elements[21..], &mut output);

        output
    }
}
