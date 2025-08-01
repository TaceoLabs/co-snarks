use crate::protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, NUM};
use ark_ec::AdditiveGroup;
use ark_ff::Field;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::Polynomial;
use co_builder::{TranscriptFieldType, prelude::HonkCurve};
use ultrahonk::plain_prover_flavour::{PlainProverFlavour, UnivariateTrait};
use ultrahonk::prelude::{GateSeparatorPolynomial, Univariate};

use crate::protogalaxy_prover::{
    CONST_PG_LOG_N, DeciderProverMemory, DeciderProvingKey, ExtendedRelationParameters,
};

pub(crate) fn compute_extended_relation_parameters<
    C: HonkCurve<TranscriptFieldType>,
    L: PlainProverFlavour,
>(
    prover_memory: &Vec<DeciderProverMemory<C, L>>,
) -> ExtendedRelationParameters<C::ScalarField> {
    let mut result = ExtendedRelationParameters::<C::ScalarField>::default();
    result
        .get_params_as_mut()
        .into_iter()
        .enumerate()
        .for_each(|(param_idx, param)| {
            let mut tmp = Univariate {
                evaluations: [C::ScalarField::ZERO; NUM],
            };
            prover_memory
                .iter()
                .enumerate()
                .for_each(|(key_idx, memory)| {
                    tmp.evaluations[key_idx] =
                        memory.relation_parameters.get_params()[param_idx].clone();
                });

            // TODO CESAR: Verify that extend_from is equivalent to extend_to
            // TODO CESAR: This is probably not correct, check skip_count stuff
            param.extend_from(&tmp.evaluations);
        });
    result
}

pub(crate) fn compute_and_extend_alphas<
    C: HonkCurve<TranscriptFieldType>,
    L: PlainProverFlavour<Alpha<C::ScalarField> = C::ScalarField>,
>(
    prover_memory: &Vec<DeciderProverMemory<C, L>>,
) -> Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>> {
    (0..L::NUM_SUBRELATIONS - 1)
        .map(|alpha_idx| {
            let mut tmp = Univariate {
                evaluations: [C::ScalarField::ZERO; NUM],
            };
            prover_memory
                .iter()
                .enumerate()
                .for_each(|(key_idx, memory)| {
                    tmp.evaluations[key_idx] = memory.relation_parameters.alphas[alpha_idx].clone();
                });

            let mut alpha = Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH>::default();
            // TODO CESAR: Verify that extend_from is equivalent to extend_to
            alpha.extend_from(&tmp.evaluations);
            alpha
        })
        .collect()
}

pub(crate) fn compute_combiner_quotient<C: HonkCurve<TranscriptFieldType>>(
    combiner: &Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>,
    perturbator_evaluation: C::ScalarField,
) -> Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM }> {
    // TODO CESAR: Polish and avoid the try_into at the end, besides, should this work for NUM > 2?
    let mut combiner_quotient_evals = vec![C::ScalarField::ZERO; BATCHED_EXTENDED_LENGTH - NUM];
    for point in NUM..combiner.evaluations.len() {
        let idx = point - NUM;
        let point_as_fr = C::ScalarField::from(point as u64);
        let lagrange_0 = C::ScalarField::ONE - point_as_fr;
        let vanishing_polynomial = point_as_fr * (point_as_fr - C::ScalarField::ONE);
        combiner_quotient_evals[idx] = (combiner.evaluations[point]
            - perturbator_evaluation * lagrange_0)
            * vanishing_polynomial.inverse().unwrap();
    }

    Univariate {
        evaluations: combiner_quotient_evals.try_into().unwrap(),
    }
}
// TODO CESAR: test
pub(crate) fn compute_row_evaluations<C: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour>(
    accumulator: &mut DeciderProvingKey<C, L>,
    accumulator_prover_memory: &DeciderProverMemory<C, L>,
) -> Polynomial<C::ScalarField> {
    let DeciderProverMemory {
        polys,
        relation_parameters,
    } = accumulator_prover_memory;

    let polynomial_size = polys.iter().count();
    let mut aggregated_relation_evaluations = vec![C::ScalarField::ZERO; polynomial_size];

    // TODO CESAR: What about all the trace_usage_tracker shenanigans?
    // TODO CESAR: Parallelize this, use the parallel_for stuff
    for i in 0..polynomial_size {
        let row = polys.get_row(i);

        // TODO CESAR: Verify this line makes sense
        let mut evals = L::AllRelationEvaluations::default();
        L::accumulate_relation_evaluations::<C>(
            &mut evals,
            &row,
            &relation_parameters,
            &C::ScalarField::ONE,
        );

        // TODO CESAR: This is not correct, need to handle the case where subrelations are linearly dependent
        aggregated_relation_evaluations[i] =
            L::scale_and_batch_elements(&evals, C::ScalarField::ONE, &relation_parameters.alphas);
    }

    // TODO CESAR: This is not correct, need to handle the case where subrelations are linearly dependent
    aggregated_relation_evaluations[0] += C::ScalarField::ZERO;

    Polynomial {
        coefficients: aggregated_relation_evaluations,
    }
}

pub(crate) fn construct_coefficients_tree<C: HonkCurve<TranscriptFieldType>>(
    betas: &[C::ScalarField],
    deltas: &[C::ScalarField],
    prev_level_coeffs: Vec<Vec<C::ScalarField>>,
    level: usize,
) -> Vec<C::ScalarField> {
    if level == betas.len() {
        return prev_level_coeffs[0].clone();
    }

    let degree = level + 1;
    let prev_level_width = prev_level_coeffs.len();
    let mut level_coeffs = vec![vec![C::ScalarField::ZERO; degree + 1]; prev_level_width / 2];

    // TODO CESAR: Add parallelism here, all the parallel_for stuff
    for parent in 0..prev_level_width / 2 {
        let node = parent * 2;
        level_coeffs[parent][..prev_level_coeffs[node].len()]
            .copy_from_slice(&prev_level_coeffs[node]);
        for d in 0..degree {
            level_coeffs[parent][d] += prev_level_coeffs[node + 1][d] * betas[level];
            level_coeffs[parent][d + 1] += prev_level_coeffs[node + 1][d] * deltas[level];
        }
    }

    return construct_coefficients_tree::<C>(betas, deltas, level_coeffs, level + 1);
}

pub(crate) fn construct_perturbator_coefficients<C: HonkCurve<TranscriptFieldType>>(
    betas: &[C::ScalarField],
    deltas: &[C::ScalarField],
    full_honk_evaluations: Polynomial<C::ScalarField>,
) -> Vec<C::ScalarField> {
    let width = full_honk_evaluations.coefficients.len();
    let mut first_level_coeffs =
        vec![vec![C::ScalarField::from(2u64), C::ScalarField::ZERO]; width / 2];

    // TODO CESAR: Add parallelism here, all the parallel_for stuff
    for parent in 0..first_level_coeffs.len() {
        let node = parent * 2;
        first_level_coeffs[parent][0] = full_honk_evaluations.coefficients[node]
            + full_honk_evaluations.coefficients[node + 1] * betas[0];
        first_level_coeffs[parent][1] = full_honk_evaluations.coefficients[node + 1] * deltas[0];
    }

    construct_coefficients_tree::<C>(betas, deltas, first_level_coeffs, 1)
}

// TODO CESAR: test
pub(crate) fn compute_perturbator<C: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour>(
    accumulator: &mut DeciderProvingKey<C, L>,
    deltas: &Vec<C::ScalarField>,
    accumulator_prover_memory: &DeciderProverMemory<C, L>,
) -> Polynomial<C::ScalarField> {
    let full_honk_evaluations = compute_row_evaluations(accumulator, accumulator_prover_memory);

    // TODO CESAR: This line assumes that the first key is the accumulator, check this
    let betas = &accumulator_prover_memory
        .relation_parameters
        .gate_challenges;

    // TODO CESAR: Check if this log is fine
    let log_circuit_size = accumulator.proving_key.circuit_size.ilog2() as usize;

    // Compute the perturbator using only the first log_circuit_size-many betas/deltas
    let mut perturbator = construct_perturbator_coefficients::<C>(
        &betas[..log_circuit_size],
        &deltas[..log_circuit_size],
        full_honk_evaluations,
    );

    // Populate the remaining coefficients with zeros to reach the required constant size
    // TODO CESAR: replace with extend
    for _ in log_circuit_size..CONST_PG_LOG_N {
        perturbator.push(C::ScalarField::ZERO);
    }

    Polynomial::new(perturbator)
}

// TODO CESAR: test
pub(crate) fn extend_univariates<C: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour>(
    prover_memory: &Vec<DeciderProverMemory<C, L>>,
    row_idx: usize,
) -> Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>> {
    let mut results: Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>> =
        Vec::with_capacity(prover_memory[0].polys.iter().count());

    prover_memory
        .iter()
        .map(|memory| memory.polys.get_row(row_idx))
        .enumerate()
        .for_each(|(pk_idx, row)| {
            row.into_iter().enumerate().for_each(|(col_idx, value)| {
                results[col_idx].evaluations[pk_idx] = value.clone();
            });
        });

    results
}

// TODO CESAR: test
pub(crate) fn batch_over_relations<C: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour>(
    univariate_accumulators: &L::AllRelationAcc<C::ScalarField>,
    alphas: &Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
) -> Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH> {
    todo!()
}

// TODO CESAR: finish/test
pub(crate) fn compute_combiner<C: HonkCurve<TranscriptFieldType>, L: PlainProverFlavour>(
    prover_memory: &Vec<DeciderProverMemory<C, L>>,
    gate_separators: &GateSeparatorPolynomial<C::ScalarField>,
    relation_parameters: &ExtendedRelationParameters<C::ScalarField>,
    alphas: &Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
) -> Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH> {
    // TODO CESAR: In barretenberg there is virtual_size
    let common_polynomial_size = prover_memory[0].polys.witness.w_l().len();
    let mut univariate_accumulators = L::AllRelationAcc::<C::ScalarField>::default();

    for i in 0..common_polynomial_size {
        let extended_univariates = extend_univariates(&prover_memory, i);

        let pow_challenge = gate_separators.beta_products[i];

        // L::accumulate_relation_univariates(
        //     &mut univariate_accumulators,
        //     &extended_univariates,
        //     &relation_parameters,
        //     C::ScalarField::ONE,
        // );
    }

    batch_over_relations::<C, L>(&univariate_accumulators, alphas)
}
