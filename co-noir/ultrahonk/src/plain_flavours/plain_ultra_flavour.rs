use std::array;

use crate::decider::sumcheck::round_prover::SumcheckProverRound;
use crate::decider::sumcheck::round_verifier::SumcheckVerifierRound;
use crate::decider::types::{ClaimedEvaluations, ProverUnivariates, RelationParameters};
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::prelude::{Barycentric, Univariate};
use ark_ff::PrimeField;
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::prover_flavour::ProverFlavour;

use crate::decider::relations::{
    auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc, AuxiliaryRelationEvals},
    delta_range_constraint_relation::{
        DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
        DeltaRangeConstraintRelationEvals,
    },
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
};
use crate::transcript::TranscriptFieldType;

#[derive(Default)]
pub struct AllRelationAccUltra<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_aux: AuxiliaryRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
}

#[derive(Default)]
pub struct AllRelationEvaluationsUltra<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationEvals<F>,
    pub(crate) r_perm: UltraPermutationRelationEvals<F>,
    pub(crate) r_lookup: LogDerivLookupRelationEvals<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_elliptic: EllipticRelationEvals<F>,
    pub(crate) r_aux: AuxiliaryRelationEvals<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationEvals<F>,
}
type UltraSumcheckRoundOutput<F: PrimeField> =
    Univariate<F, { UltraFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;
type UltraSumcheckRoundOutputZK<F: PrimeField> =
    Univariate<F, { UltraFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

impl PlainProverFlavour for UltraFlavour {
    type AllRelationAcc<F: PrimeField> = AllRelationAccUltra<F>;
    type AllRelationEvaluations<F: PrimeField> = AllRelationEvaluationsUltra<F>;
    type Alphas<F: PrimeField> = [F; Self::NUM_SUBRELATIONS - 1];
    type SumcheckRoundOutput<F: PrimeField> =
        Univariate<F, { UltraFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;
    type SumcheckRoundOutputZK<F: PrimeField> =
        Univariate<F, { UltraFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;
    type ProverUnivariate<F: PrimeField> =
        Univariate<F, { UltraFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
        + UltraPermutationRelation::NUM_RELATIONS
        + DeltaRangeConstraintRelation::NUM_RELATIONS
        + EllipticRelation::NUM_RELATIONS
        + AuxiliaryRelation::NUM_RELATIONS
        + LogDerivLookupRelation::NUM_RELATIONS
        + Poseidon2ExternalRelation::NUM_RELATIONS
        + Poseidon2InternalRelation::NUM_RELATIONS;

    fn scale<F: PrimeField>(
        acc: &mut Self::AllRelationAcc<F>,
        first_scalar: F,
        elements: &Self::Alphas<F>,
    ) {
        tracing::trace!("Prove::Scale");
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        acc.r_arith.scale(&[first_scalar, elements[0]]);
        acc.r_perm.scale(&elements[1..3]);
        acc.r_lookup.scale(&elements[3..5]);
        acc.r_delta.scale(&elements[5..9]);
        acc.r_elliptic.scale(&elements[9..11]);
        acc.r_aux.scale(&elements[11..17]);
        acc.r_pos_ext.scale(&elements[17..21]);
        acc.r_pos_int.scale(&elements[21..]);
    }

    fn extend_and_batch_univariates<F: PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutput<F>,
        extended_random_poly: &Self::SumcheckRoundOutput<F>,
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
    fn extend_and_batch_univariates_zk<F: PrimeField>(
        acc: &Self::AllRelationAcc<F>,
        result: &mut Self::SumcheckRoundOutputZK<F>,
        extended_random_poly: &Self::SumcheckRoundOutputZK<F>,
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
    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Prove::Accumulate relations");

        SumcheckProverRound::accumulate_one_relation_univariates::<
            UltraArithmeticRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            UltraPermutationRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            DeltaRangeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_elliptic_curve_relation_univariates::<
            P,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            AuxiliaryRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            LogDerivLookupRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            Poseidon2ExternalRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        SumcheckProverRound::accumulate_one_relation_univariates::<
            Poseidon2InternalRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
        relation_parameters: &RelationParameters<P::ScalarField, Self>,
        scaling_factor: &P::ScalarField,
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
    }

    fn scale_and_batch_elements<F: PrimeField>(
        all_rel_evals: &Self::AllRelationEvaluations<F>,
        first_scalar: F,
        elements: &Self::Alphas<F>,
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
            .r_pos_ext
            .scale_and_batch_elements(&elements[17..21], &mut output);
        all_rel_evals
            .r_pos_int
            .scale_and_batch_elements(&elements[21..], &mut output);

        output
    }
}

type UltraProverUnivariates<F: PrimeField> =
    Univariate<F, { UltraFlavour::MAX_PARTIAL_RELATION_LENGTH }>;
// impl ProverUnivariatePlainFlavour for UltraFlavour {
//     type ProverUnivariate<F: PrimeField> = UltraProverUnivariates<F>;

//     fn double_in_place<F: PrimeField>(poly: &mut Self::ProverUnivariate<F>) {
//         for i in 0..UltraFlavour::MAX_PARTIAL_RELATION_LENGTH {
//             poly.evaluations[i].double_in_place();
//         }
//     }

//     fn square_in_place<F: PrimeField>(poly: &mut Self::ProverUnivariate<F>) {
//         for i in 0..UltraFlavour::MAX_PARTIAL_RELATION_LENGTH {
//             poly.evaluations[i].square_in_place();
//         }
//     }

//     fn extend_from<F: PrimeField>(poly_to: &mut Self::ProverUnivariate<F>, poly_from: &[F]) {
//         let length = poly_from.len();
//         let extended_length = UltraFlavour::MAX_PARTIAL_RELATION_LENGTH;

//         assert!(length <= extended_length);
//         poly_to.evaluations[..length].copy_from_slice(poly_from);

//         if length == 2 {
//             let delta = poly_from[1] - poly_from[0];
//             for i in length..extended_length {
//                 poly_to.evaluations[i] = poly_to.evaluations[i - 1] + delta;
//             }
//         } else if length == 3 {
//             let inverse_two = F::from(2u64).inverse().unwrap();
//             let a = (poly_from[2] + poly_from[0]) * inverse_two - poly_from[1];
//             let b = poly_from[1] - a - poly_from[0];
//             let a2 = a.double();
//             let mut a_mul = a2.to_owned();
//             for _ in 0..length - 2 {
//                 a_mul += a2;
//             }
//             let mut extra = a_mul + a + b;
//             for i in length..extended_length {
//                 poly_to.evaluations[i] = poly_to.evaluations[i - 1] + extra;
//                 extra += a2;
//             }
//         } else if length == 4 {
//             let inverse_six = F::from(6u64).inverse().unwrap();
//             let zero_times_3 = poly_from[0].double() + poly_from[0];
//             let zero_times_6 = zero_times_3.double();
//             let zero_times_12 = zero_times_6.double();
//             let one_times_3 = poly_from[1].double() + poly_from[1];
//             let one_times_6 = one_times_3.double();
//             let two_times_3 = poly_from[2].double() + poly_from[2];
//             let three_times_2 = poly_from[3].double();
//             let three_times_3 = three_times_2 + poly_from[3];

//             let one_minus_two_times_3 = one_times_3 - two_times_3;
//             let one_minus_two_times_6 = one_minus_two_times_3 + one_minus_two_times_3;
//             let one_minus_two_times_12 = one_minus_two_times_6 + one_minus_two_times_6;
//             let a = (one_minus_two_times_3 + poly_from[3] - poly_from[0]) * inverse_six;
//             let b =
//                 (zero_times_6 - one_minus_two_times_12 - one_times_3 - three_times_3) * inverse_six;
//             let c = (poly_from[0] - zero_times_12
//                 + one_minus_two_times_12
//                 + one_times_6
//                 + two_times_3
//                 + three_times_2)
//                 * inverse_six;
//             let a_plus_b = a + b;
//             let a_plus_b_times_2 = a_plus_b + a_plus_b;
//             let start_idx_sqr = (length - 1) * (length - 1);
//             let idx_sqr_three = start_idx_sqr + start_idx_sqr + start_idx_sqr;
//             let mut idx_sqr_three_times_a = F::from(idx_sqr_three as u64) * a;
//             let mut x_a_term = F::from(6 * (length - 1) as u64) * a;
//             let three_a = a + a + a;
//             let six_a = three_a + three_a;

//             let three_a_plus_two_b = a_plus_b_times_2 + a;
//             let mut linear_term = F::from(length as u64 - 1) * three_a_plus_two_b + (a_plus_b + c);
//             for i in length..extended_length {
//                 poly_to.evaluations[i] =
//                     poly_to.evaluations[i - 1] + idx_sqr_three_times_a + linear_term;

//                 idx_sqr_three_times_a += x_a_term + three_a;
//                 x_a_term += six_a;

//                 linear_term += three_a_plus_two_b;
//             }
//         } else {
//             let big_domain = Barycentric::construct_big_domain(length, extended_length);
//             let lagrange_denominators =
//                 Barycentric::construct_lagrange_denominators(length, &big_domain);
//             let dominator_inverses = Barycentric::construct_denominator_inverses(
//                 extended_length,
//                 &big_domain,
//                 &lagrange_denominators,
//             );
//             let full_numerator_values =
//                 Barycentric::construct_full_numerator_values(length, extended_length, &big_domain);

//             for k in length..extended_length {
//                 poly_to.evaluations[k] = F::zero();
//                 for (j, mut term) in poly_from.iter().cloned().enumerate() {
//                     term *= &dominator_inverses[length * k + j];
//                     poly_to.evaluations[k] += term;
//                 }
//                 poly_to.evaluations[k] *= &full_numerator_values[k];
//             }
//         }
//     }

//     fn evaluate<F: PrimeField>(poly: &Self::ProverUnivariate<F>, u: F) -> F {
//         if u == F::zero() {
//             return poly.evaluations[0];
//         }

//         let mut full_numerator_value = F::one();
//         for i in 0..UltraFlavour::MAX_PARTIAL_RELATION_LENGTH {
//             full_numerator_value *= u - F::from(i as u64);
//         }

//         let big_domain = Barycentric::construct_big_domain(
//             poly.evaluations.len(),
//             UltraFlavour::MAX_PARTIAL_RELATION_LENGTH,
//         );
//         let lagrange_denominators = Barycentric::construct_lagrange_denominators(
//             UltraFlavour::MAX_PARTIAL_RELATION_LENGTH,
//             &big_domain,
//         );

//         let mut denominator_inverses = [F::zero(); UltraFlavour::MAX_PARTIAL_RELATION_LENGTH];
//         for i in 0..UltraFlavour::MAX_PARTIAL_RELATION_LENGTH {
//             let mut inv = lagrange_denominators[i];

//             inv *= u - big_domain[i];
//             inv = F::one() / inv;
//             denominator_inverses[i] = inv;
//         }

//         let mut result = F::zero();
//         for (i, &inverse) in denominator_inverses.iter().enumerate() {
//             let mut term = poly.evaluations[i];
//             term *= inverse;
//             result += term;
//         }
//         result *= full_numerator_value;
//         result
//     }

//     fn get_random<R: rand::Rng + rand::CryptoRng, F: PrimeField>(
//         rng: &mut R,
//     ) -> Self::ProverUnivariate<F> {
//         let evaluations = array::from_fn(|_| F::rand(rng));
//         Self::ProverUnivariate::<F> { evaluations }
//     }

//     fn extend_and_batch_univariates<const SIZE: usize, F: PrimeField>(
//         lhs: &Univariate<F, SIZE>,
//         result: &mut Self::ProverUnivariate<F>,
//         extended_random_poly: &Self::ProverUnivariate<F>,
//         partial_evaluation_result: &F,
//         linear_independent: bool,
//     ) {
//         let mut extended = Self::ProverUnivariate::<F>::default();
//         extended.extend_from(&lhs.evaluations);

//         if linear_independent {
//             *result += extended * extended_random_poly * partial_evaluation_result;
//         } else {
//             *result += extended;
//         }
//     }
// }
