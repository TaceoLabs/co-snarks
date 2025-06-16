use crate::prelude::Univariate;
use ark_ff::PrimeField;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::prelude::Polynomial;

use crate::decider::relations::databus_lookup_relation::DataBusLookupRelationEvals;
use crate::decider::relations::ecc_op_queue_relation::EccOpQueueRelationEvals;
use crate::decider::sumcheck::round_prover::SumcheckProverRound;
use crate::decider::types::{ProverUnivariates, RelationParameters};
use crate::decider::{
    relations::{
        auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc, AuxiliaryRelationEvals},
        databus_lookup_relation::{DataBusLookupRelation, DataBusLookupRelationAcc},
        delta_range_constraint_relation::{
            DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
            DeltaRangeConstraintRelationEvals,
        },
        ecc_op_queue_relation::{EccOpQueueRelation, EccOpQueueRelationAcc},
        elliptic_relation::{EllipticRelation, EllipticRelationAcc, EllipticRelationEvals},
        logderiv_lookup_relation::{
            LogDerivLookupRelation, LogDerivLookupRelationAcc, LogDerivLookupRelationEvals,
        },
        permutation_relation::{
            UltraPermutationRelation, UltraPermutationRelationAcc, UltraPermutationRelationEvals,
        },
        poseidon2_external_relation::{
            Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc, Poseidon2ExternalRelationEvals,
        },
        poseidon2_internal_relation::{
            Poseidon2InternalRelation, Poseidon2InternalRelationAcc, Poseidon2InternalRelationEvals,
        },
        ultra_arithmetic_relation::{
            UltraArithmeticRelation, UltraArithmeticRelationAcc, UltraArithmeticRelationEvals,
        },
    },
    sumcheck::round_verifier::SumcheckVerifierRound,
    types::ClaimedEvaluations,
};
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::transcript::TranscriptFieldType;
use co_builder::prover_flavour::ProverFlavour;

#[derive(Default)]
pub struct AllRelationAccMega<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_aux: AuxiliaryRelationAcc<F>,
    pub(crate) r_ecc_op_queue: EccOpQueueRelationAcc<F>,
    pub(crate) r_databus: DataBusLookupRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
}

#[derive(Default)]
pub struct AllRelationEvaluationsMega<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationEvals<F>,
    pub(crate) r_perm: UltraPermutationRelationEvals<F>,
    pub(crate) r_lookup: LogDerivLookupRelationEvals<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_elliptic: EllipticRelationEvals<F>,
    pub(crate) r_aux: AuxiliaryRelationEvals<F>,
    pub(crate) r_ecc_op_queue: EccOpQueueRelationEvals<F>,
    pub(crate) r_databus: DataBusLookupRelationEvals<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationEvals<F>,
}

impl<F: PrimeField> PlainProverFlavour<F> for MegaFlavour {
    type AllRelationAcc = AllRelationAccMega<F>;
    type AllRelationEvaluations = AllRelationEvaluationsMega<F>;

    const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
        + UltraPermutationRelation::NUM_RELATIONS
        + DeltaRangeConstraintRelation::NUM_RELATIONS
        + EllipticRelation::NUM_RELATIONS
        + AuxiliaryRelation::NUM_RELATIONS
        + LogDerivLookupRelation::NUM_RELATIONS
        + EccOpQueueRelation::NUM_RELATIONS
        + DataBusLookupRelation::NUM_RELATIONS
        + Poseidon2ExternalRelation::NUM_RELATIONS
        + Poseidon2InternalRelation::NUM_RELATIONS;

    fn scale(acc: &mut Self::AllRelationAcc, first_scalar: F, elements: &[F]) {
        tracing::trace!("Prove::Scale");
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        acc.r_arith.scale(&[first_scalar, elements[0]]);
        acc.r_perm.scale(&elements[1..3]);
        acc.r_lookup.scale(&elements[3..5]);
        acc.r_delta.scale(&elements[5..9]);
        acc.r_elliptic.scale(&elements[9..11]);
        acc.r_aux.scale(&elements[11..17]);
        acc.r_ecc_op_queue.scale(&elements[17..25]);
        acc.r_databus.scale(&elements[25..31]);
        acc.r_pos_ext.scale(&elements[31..35]);
        acc.r_pos_int.scale(&elements[35..]);
    }

    fn extend_and_batch_univariates<const SIZE: usize>(
        acc: &Self::AllRelationAcc,
        result: &mut crate::prelude::Univariate<F, SIZE>,
        extended_random_poly: &crate::prelude::Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        tracing::trace!("Prove::Extend and batch univariates");
        acc.r_arith.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_perm.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_lookup.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_delta.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_elliptic.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_aux.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_ecc_op_queue.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_databus.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_pos_ext.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        acc.r_pos_int.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
    }

    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        univariate_accumulators: &mut Self::AllRelationAcc,
        extended_edges: &ProverUnivariates<F, Self, { Self::MAX_PARTIAL_RELATION_LENGTH }>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Prove::Accumulate relations");

        SumcheckProverRound::accumulate_one_relation_univariates::<UltraArithmeticRelation>(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<UltraPermutationRelation>(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<DeltaRangeConstraintRelation>(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_elliptic_curve_relation_univariates::<P>(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<LogDerivLookupRelation>(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<Poseidon2ExternalRelation>(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<Poseidon2InternalRelation>(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<EccOpQueueRelation>(
            &mut univariate_accumulators.r_ecc_op_queue,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<DataBusLookupRelation>(
            &mut univariate_accumulators.r_databus,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType, ScalarField = F>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations,
        extended_edges: &ClaimedEvaluations<F, F, Self>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Verify::Accumulate relations");
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            UltraArithmeticRelation,
        >(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            UltraPermutationRelation,
        >(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            DeltaRangeConstraintRelation,
        >(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_elliptic_curve_relation_evaluations(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            LogDerivLookupRelation,
        >(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            Poseidon2ExternalRelation,
        >(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            Poseidon2InternalRelation,
        >(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<EccOpQueueRelation>(
            &mut univariate_accumulators.r_ecc_op_queue,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckVerifierRound::<P, Self>::accumulate_one_relation_evaluations::<
            DataBusLookupRelation,
        >(
            &mut univariate_accumulators.r_databus,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
    fn scale_and_batch_elements(
        all_rel_evals: &Self::AllRelationEvaluations,
        first_scalar: F,
        elements: &[F],
    ) -> F {
        tracing::trace!("Verify::scale_and_batch_elements");
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        let mut output = F::zero();
        all_rel_evals
            .r_arith
            .scale_and_batch_elements(&[first_scalar, elements[0]], &mut output);
        all_rel_evals
            .r_perm
            .scale_and_batch_elements(&elements[1..3], &mut output);
        all_rel_evals
            .r_lookup
            .scale_and_batch_elements(&elements[3..5], &mut output);
        all_rel_evals
            .r_delta
            .scale_and_batch_elements(&elements[5..9], &mut output);
        all_rel_evals
            .r_elliptic
            .scale_and_batch_elements(&elements[9..11], &mut output);
        all_rel_evals
            .r_aux
            .scale_and_batch_elements(&elements[11..17], &mut output);
        all_rel_evals
            .r_ecc_op_queue
            .scale_and_batch_elements(&elements[17..25], &mut output);
        all_rel_evals
            .r_databus
            .scale_and_batch_elements(&elements[25..31], &mut output);
        all_rel_evals
            .r_pos_ext
            .scale_and_batch_elements(&elements[31..35], &mut output);
        all_rel_evals
            .r_pos_int
            .scale_and_batch_elements(&elements[35..], &mut output);

        output
    }
}
