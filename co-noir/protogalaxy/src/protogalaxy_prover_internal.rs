use crate::protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, NUM_KEYS};
use ark_ec::AdditiveGroup;
use ark_ff::Field;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;

use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::polynomials::polynomial::Polynomial;
use ultrahonk::plain_prover_flavour::{PlainProverFlavour, UnivariateTrait};
use ultrahonk::prelude::{AllEntities, GateSeparatorPolynomial, ProvingKey, Univariate};

use crate::protogalaxy_prover::{CONST_PG_LOG_N, DeciderProverMemory, ExtendedRelationParameters};

/**
 * @brief For each parameter, collect the value in each decider proving key in a univariate and extend for use in the
 * combiner compute.
 */
pub(crate) fn compute_extended_relation_parameters<C: HonkCurve<TranscriptFieldType>>(
    prover_memory: &Vec<&mut DeciderProverMemory<C>>,
) -> ExtendedRelationParameters<C::ScalarField> {
    let mut result = ExtendedRelationParameters::<C::ScalarField>::default();
    result
        .get_params_as_mut()
        .into_iter()
        .enumerate()
        .for_each(|(param_idx, param)| {
            let mut tmp = Univariate {
                evaluations: [C::ScalarField::ZERO; NUM_KEYS],
            };
            prover_memory
                .iter()
                .enumerate()
                .for_each(|(key_idx, memory)| {
                    tmp.evaluations[key_idx] = *memory.relation_parameters.get_params()[param_idx];
                });

            param.extend_from(&tmp.evaluations);
        });
    result
}

/**
 * @brief Combine the relation batching parameters (alphas) from each decider proving key into a univariate for
 * using in the combiner computation.
 */
pub(crate) fn compute_and_extend_alphas<C: HonkCurve<TranscriptFieldType>>(
    prover_memory: &Vec<&mut DeciderProverMemory<C>>,
) -> Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>> {
    (0..MegaFlavour::NUM_SUBRELATIONS - 1)
        .map(|alpha_idx| {
            let mut tmp = Univariate {
                evaluations: [C::ScalarField::ZERO; NUM_KEYS],
            };
            prover_memory
                .iter()
                .enumerate()
                .for_each(|(key_idx, memory)| {
                    tmp.evaluations[key_idx] = memory.alphas[alpha_idx];
                });

            let mut alpha = Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH>::default();
            alpha.extend_from(&tmp.evaluations);
            alpha
        })
        .collect()
}

/**
 * @brief Compute the combiner quotient defined as $K$ polynomial in the paper.
 *  This is a simplified version of the one in Barretenberg, which only works with 2 keys.
 */
pub(crate) fn compute_combiner_quotient<C: HonkCurve<TranscriptFieldType>>(
    combiner: &Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>,
    perturbator_evaluation: C::ScalarField,
) -> Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }> {
    let mut combiner_quotient_evals =
        vec![C::ScalarField::ZERO; BATCHED_EXTENDED_LENGTH - NUM_KEYS];
    for point in NUM_KEYS..combiner.evaluations.len() {
        let idx = point - NUM_KEYS;
        let point_as_fr = C::ScalarField::from(point as u64);
        let lagrange_0 = C::ScalarField::ONE - point_as_fr;
        let vanishing_polynomial = point_as_fr * (point_as_fr - C::ScalarField::ONE);
        combiner_quotient_evals[idx] = (combiner.evaluations[point]
            - perturbator_evaluation * lagrange_0)
            * vanishing_polynomial
                .inverse()
                .expect("Vanishing polynomial should not be zero");
    }

    Univariate {
        evaluations: combiner_quotient_evals.try_into().unwrap(),
    }
}

/**
 * @brief Compute the values of the aggregated relation evaluations at each row in the execution trace, representing
 * f_i(ω) in the Protogalaxy paper, given the evaluations of all the prover polynomials and \vec{α} (the batching
 * challenges that help establishing each subrelation is independently valid in Honk - from the Plonk paper, DO NOT
 * confuse with α in Protogalaxy).
 *
 * @details When folding Mega decider proving keys, one of the relations is linearly dependent. We define such
 * relations as acting on the entire execution trace and hence requiring to be accumulated separately as we iterate
 * over each row. At the end of the function, the linearly dependent contribution is accumulated at index 0
 * representing the sum f_0(ω) + α_j*g(ω) where f_0 represents the full honk evaluation at row 0, g(ω) is the
 * linearly dependent subrelation and α_j is its corresponding batching challenge.
 */
pub(crate) fn compute_row_evaluations<C: HonkCurve<TranscriptFieldType>>(
    accumulator_prover_memory: &DeciderProverMemory<C>,
) -> Polynomial<C::ScalarField> {
    let DeciderProverMemory {
        polys,
        relation_parameters,
        alphas,
        ..
    } = accumulator_prover_memory;

    let polynomial_size = polys.witness.w_l().len();
    let mut aggregated_relation_evaluations = vec![C::ScalarField::ZERO; polynomial_size];
    let mut last_coeff = C::ScalarField::ZERO;

    // TACEO TODO: Barretenberg uses balanced parallelization here with the trace_usage_tracker
    for (i, aggregated_relation_evaluations_coeff) in
        aggregated_relation_evaluations.iter_mut().enumerate()
    {
        // TACEO TODO: Avoid cloning the row
        let row = polys.get_row(i);

        let mut evals = <MegaFlavour as PlainProverFlavour>::AllRelationEvaluations::default();
        // Evaluate all subrelations on given row. Separator is 1 since we are not summing across rows here
        MegaFlavour::accumulate_relation_evaluations::<C>(
            &mut evals,
            &row,
            relation_parameters,
            &C::ScalarField::ONE,
        );

        // Sum against challenges alpha
        let (linearly_independent_contributions, linearly_dependent_contributions) =
            MegaFlavour::scale_by_challenge_and_accumulate(&evals, C::ScalarField::ONE, alphas);
        *aggregated_relation_evaluations_coeff = linearly_independent_contributions;
        last_coeff += linearly_dependent_contributions;
    }

    aggregated_relation_evaluations[0] += last_coeff;

    Polynomial {
        coefficients: aggregated_relation_evaluations,
    }
}

/**
 * @brief  Recursively compute the parent nodes of each level in the tree, starting from the leaves. Note that at
 * each level, the resulting parent nodes will be polynomials of degree (level+1) because we multiply by an
 * additional factor of X.
 */
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

    // TACEO TODO: Barretenberg uses parallelization here
    for (parent_idx, parent_node) in level_coeffs
        .iter_mut()
        .take(prev_level_width / 2)
        .enumerate()
    {
        let node = parent_idx * 2;
        parent_node[..prev_level_coeffs[node].len()].copy_from_slice(&prev_level_coeffs[node]);
        for d in 0..degree {
            parent_node[d] += prev_level_coeffs[node + 1][d] * betas[level];
            parent_node[d + 1] += prev_level_coeffs[node + 1][d] * deltas[level];
        }
    }

    construct_coefficients_tree::<C>(betas, deltas, level_coeffs, level + 1)
}

/**
 * @brief We construct the coefficients of the perturbator polynomial in O(n) time following the technique in
 * Claim 4.4. Consider a binary tree whose leaves are the evaluations of the full Honk relation at each row in the
 * execution trace. The subsequent levels in the tree are constructed using the following technique: At level i in
 * the tree, label the branch connecting the left node n_l to its parent by 1 and for the right node n_r by β_i +
 * δ_i X. The value of the parent node n will be constructed as n = n_l + n_r * (β_i + δ_i X). Recurse over each
 * layer until the root is reached which will correspond to the perturbator polynomial F(X).
 * TODO(https://github.com/AztecProtocol/barretenberg/issues/745): make computation of perturbator more memory
 * efficient, operate in-place and use std::resize; add multithreading
 */
pub(crate) fn construct_perturbator_coefficients<C: HonkCurve<TranscriptFieldType>>(
    betas: &[C::ScalarField],
    deltas: &[C::ScalarField],
    full_honk_evaluations: Polynomial<C::ScalarField>,
) -> Vec<C::ScalarField> {
    let width = full_honk_evaluations.coefficients.len();
    let mut first_level_coeffs =
        vec![vec![C::ScalarField::from(2u64), C::ScalarField::ZERO]; width / 2];

    // TACEO TODO: Barretenberg uses parallelization here
    for (parent_idx, parent_node) in first_level_coeffs.iter_mut().enumerate() {
        let node = parent_idx * 2;
        parent_node[0] = full_honk_evaluations.coefficients[node]
            + full_honk_evaluations.coefficients[node + 1] * betas[0];
        parent_node[1] = full_honk_evaluations.coefficients[node + 1] * deltas[0];
    }

    construct_coefficients_tree::<C>(betas, deltas, first_level_coeffs, 1)
}

/**
 * @brief Construct the power perturbator polynomial F(X) in coefficient form from the accumulator
 */
pub(crate) fn compute_perturbator<C: HonkCurve<TranscriptFieldType>>(
    accumulator: &mut ProvingKey<C, MegaFlavour>,
    deltas: &[C::ScalarField],
    accumulator_prover_memory: &DeciderProverMemory<C>,
) -> Polynomial<C::ScalarField> {
    let full_honk_evaluations = compute_row_evaluations(accumulator_prover_memory);

    let betas = &accumulator_prover_memory.gate_challenges;

    let log_circuit_size = accumulator.circuit_size.ilog2() as usize;

    // Compute the perturbator using only the first log_circuit_size-many betas/deltas
    let mut perturbator = construct_perturbator_coefficients::<C>(
        &betas[..log_circuit_size],
        &deltas[..log_circuit_size],
        full_honk_evaluations,
    );

    // Populate the remaining coefficients with zeros to reach the required constant size
    if log_circuit_size < CONST_PG_LOG_N {
        perturbator.resize(CONST_PG_LOG_N + 1, C::ScalarField::ZERO);
    }

    Polynomial::new(perturbator)
}

/**
 * @brief Prepare a univariate polynomial for relation execution in one step of the combiner construction.
 * @details For a fixed prover polynomial index, extract that polynomial from each prover_memory in Vec<DeciderProvingMemory>. From
 * each polynomial, extract the value at row_idx. Use these values to create a univariate polynomial, and then
 * extend (i.e., compute additional evaluations at adjacent domain values) as needed.
 * @todo TODO(https://github.com/AztecProtocol/barretenberg/issues/751) Optimize memory
 */
pub(crate) fn extend_univariates<C: HonkCurve<TranscriptFieldType>>(
    prover_memory: &Vec<&mut DeciderProverMemory<C>>,
    row_idx: usize,
) -> AllEntities<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>, MegaFlavour> {
    let mut coefficients: Vec<[C::ScalarField; NUM_KEYS]> =
        vec![[C::ScalarField::ZERO; NUM_KEYS]; prover_memory[0].polys.iter().count()];

    prover_memory
        .iter()
        .map(|memory| memory.polys.get_row(row_idx))
        .enumerate()
        .for_each(|(pk_idx, row)| {
            row.into_iterator()
                .enumerate()
                .for_each(|(col_idx, value)| {
                    coefficients[col_idx][pk_idx] = value;
                });
        });

    let results = coefficients
        .into_iter()
        .map(|coeffs| {
            let mut univariate = Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH>::default();
            univariate.extend_from(&coeffs);
            univariate
        })
        .collect::<Vec<_>>();

    AllEntities::from_elements(results)
}

/**
 * @brief Compute the combiner polynomial $G$ in the Protogalaxy paper
 * @details We have implemented an optimization that (eg in the case where we fold one instance-witness pair at a
 * time) assumes the value G(1) is 0, which is true in the case where the witness to be folded is valid.
 * @todo (https://github.com/AztecProtocol/barretenberg/issues/968) Make combiner tests better
 *
 * @param prover_memory
 * @param gate_separators
 * @param relation_parameters
 * @param alphas
 * @return Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>
 */
pub(crate) fn compute_combiner<C: HonkCurve<TranscriptFieldType>>(
    prover_memory: &Vec<&mut DeciderProverMemory<C>>,
    gate_separators: &GateSeparatorPolynomial<C::ScalarField>,
    relation_parameters: &ExtendedRelationParameters<C::ScalarField>,
    alphas: &Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
) -> Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH> {
    // TACEO TODO: In barretenberg there is virtual_size
    let common_polynomial_size = prover_memory[0].polys.witness.w_l().len();
    let mut univariate_accumulators = <MegaFlavour as PlainProverFlavour>::AllRelationAcc::<
        C::ScalarField,
    >::default_with_total_lengths();

    // Accumulate the contribution from each sub-relation
    // TACEO TODO: Barretenberg uses balanced parallelization here with the trace_usage_tracker
    for i in 0..common_polynomial_size {
        // Construct extended univariates containers
        let extended_univariates = extend_univariates(prover_memory, i);

        let pow_challenge = gate_separators.beta_products[i];

        // Accumulate the i-th row's univariate contribution. Note that the relation parameters passed to
        // this function have already been folded. Moreover, linear-dependent relations that act over the
        // entire execution trace rather than on rows, will not be multiplied by the pow challenge.
        MegaFlavour::accumulate_relation_univariates_extended_parameters::<
            C,
            BATCHED_EXTENDED_LENGTH,
        >(
            &mut univariate_accumulators,
            &extended_univariates,
            relation_parameters,
            &pow_challenge,
        );
    }

    let mut result = Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH>::default();
    //  Batch the univariate contributions from each sub-relation to obtain the round univariate
    MegaFlavour::extend_and_batch_univariates_with_distinct_challenges::<C::ScalarField, _>(
        &univariate_accumulators,
        &mut result,
        Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH> {
            evaluations: [C::ScalarField::ONE; BATCHED_EXTENDED_LENGTH],
        },
        alphas.as_slice(),
    );
    result
}
