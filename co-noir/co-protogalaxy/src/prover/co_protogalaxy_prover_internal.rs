use crate::prover::co_protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, NUM_KEYS};
use ark_ec::AdditiveGroup;
use ark_ff::Field;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prover_flavour::ProverFlavour;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::polynomials::shared_polynomial::SharedPolynomial;
use co_ultrahonk::co_decider::univariates::SharedUnivariate;
use co_ultrahonk::mpc_prover_flavour::SharedUnivariateTrait;
use co_ultrahonk::prelude::{MPCProverFlavour, ProvingKey};
use co_ultrahonk::types_batch::AllEntitiesBatch;
use mpc_core::MpcState;
use mpc_net::Network;
use rayon::prelude::*;
use ultrahonk::plain_prover_flavour::UnivariateTrait;
use ultrahonk::prelude::{GateSeparatorPolynomial, Univariate};

use crate::prover::co_protogalaxy_prover::{
    CONST_PG_LOG_N, DeciderProverMemory, ExtendedRelationParameters,
};

const LENGTH_PUBLIC: usize = MegaFlavour::PRECOMPUTED_ENTITIES_SIZE;
const LENGTH_SHARED: usize =
    MegaFlavour::WITNESS_ENTITIES_SIZE + MegaFlavour::SHIFTED_WITNESS_ENTITIES_SIZE;

/**
 * @brief For each parameter, collect the value in each decider proving key in a univariate and extend for use in the
 * combiner compute.
 */
pub fn compute_extended_relation_parameters<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
>(
    prover_memory: &Vec<&mut DeciderProverMemory<T, C>>,
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
pub fn compute_and_extend_alphas<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>>(
    prover_memory: &Vec<&mut DeciderProverMemory<T, C>>,
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
pub fn compute_combiner_quotient<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>>(
    state: &T::State,
    combiner: &SharedUnivariate<T, C, BATCHED_EXTENDED_LENGTH>,
    perturbator_evaluation: C::ScalarField,
) -> SharedUnivariate<T, C, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }> {
    let mut combiner_quotient_evals =
        vec![T::ArithmeticShare::default(); BATCHED_EXTENDED_LENGTH - NUM_KEYS];
    for point in NUM_KEYS..combiner.evaluations.len() {
        let idx = point - NUM_KEYS;
        let point_as_fr = C::ScalarField::from(point as u64);
        let lagrange_0 = C::ScalarField::ONE - point_as_fr;
        let vanishing_polynomial = point_as_fr * (point_as_fr - C::ScalarField::ONE);

        let tmp = T::add_with_public(
            -perturbator_evaluation * lagrange_0,
            combiner.evaluations[point],
            state.id(),
        );

        combiner_quotient_evals[idx] = T::mul_with_public(
            vanishing_polynomial
                .inverse()
                .expect("Vanishing polynomial should not be zero"),
            tmp,
        );
    }

    SharedUnivariate {
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
pub fn compute_row_evaluations<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    state: &mut T::State,
    accumulator_prover_memory: &DeciderProverMemory<T, C>,
) -> HonkProofResult<SharedPolynomial<T, C>> {
    let DeciderProverMemory {
        polys,
        relation_parameters,
        alphas,
        ..
    } = accumulator_prover_memory;

    let polynomial_size = polys.witness.w_l().len();
    let mut aggregated_relation_evaluations = vec![T::ArithmeticShare::default(); polynomial_size];
    let mut last_coeff = T::ArithmeticShare::default();

    // TACEO TODO: Barretenberg uses balanced parallelization here with the trace_usage_tracker
    for (i, aggregated_relation_evaluations_coeff) in
        aggregated_relation_evaluations.iter_mut().enumerate()
    {
        // TACEO TODO: Use active ranges
        // TACEO TODO: Avoid cloning the row
        let row = polys.get_row(i);

        let mut evals = <MegaFlavour as MPCProverFlavour>::AllRelationEvaluations::default();

        // Evaluate all subrelations on given row. Separator is 1 since we are not summing across rows here
        <MegaFlavour as MPCProverFlavour>::accumulate_relation_evaluations::<T, C, N>(
            net,
            state,
            &mut evals,
            &row,
            relation_parameters,
            &C::ScalarField::ONE,
        )?;

        // Sum against challenges alpha
        let (linearly_independent_contributions, linearly_dependent_contributions) =
            <MegaFlavour as MPCProverFlavour>::scale_by_challenge_and_accumulate(
                &mut evals,
                C::ScalarField::ONE,
                alphas,
            );

        *aggregated_relation_evaluations_coeff = linearly_independent_contributions;
        T::add_assign(&mut last_coeff, linearly_dependent_contributions);
    }

    T::add_assign(&mut aggregated_relation_evaluations[0], last_coeff);

    Ok(SharedPolynomial {
        coefficients: aggregated_relation_evaluations,
    })
}

/**
 * @brief  Recursively compute the parent nodes of each level in the tree, starting from the leaves. Note that at
 * each level, the resulting parent nodes will be polynomials of degree (level+1) because we multiply by an
 * additional factor of X.
 */
pub(crate) fn construct_coefficients_tree<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
>(
    betas: &[C::ScalarField],
    deltas: &[C::ScalarField],
    prev_level_coeffs: Vec<Vec<T::ArithmeticShare>>,
    level: usize,
) -> Vec<T::ArithmeticShare> {
    if level == betas.len() {
        return prev_level_coeffs[0].clone();
    }

    let degree = level + 1;
    let prev_level_width = prev_level_coeffs.len();
    let mut level_coeffs =
        vec![vec![T::ArithmeticShare::default(); degree + 1]; prev_level_width / 2];

    level_coeffs
        .par_iter_mut()
        .take(prev_level_width / 2)
        .enumerate()
        .for_each(|(parent_idx, parent_node)| {
            let node = parent_idx * 2;
            parent_node[..prev_level_coeffs[node].len()].copy_from_slice(&prev_level_coeffs[node]);
            for d in 0..degree {
                T::add_assign(
                    &mut parent_node[d],
                    T::mul_with_public(betas[level], prev_level_coeffs[node + 1][d]),
                );

                T::add_assign(
                    &mut parent_node[d + 1],
                    T::mul_with_public(deltas[level], prev_level_coeffs[node + 1][d]),
                );
            }
        });

    construct_coefficients_tree::<T, C>(betas, deltas, level_coeffs, level + 1)
}

/**
 * @brief We construct the coefficients of the perturbator polynomial in O(n) time following the technique in
 * Claim 4.4. Consider a binary tree whose leaves are the evaluations of the full Honk relation at each row in the
 * execution trace. The subsequent levels in the tree are constructed using the following technique: At level i in
 * the tree, label the branch connecting the left node n_l to its parent by 1 and for the right node n_r by β_i +
 * δ_i X. The value of the parent node n will be constructed as n = n_l + n_r * (β_i + δ_i X). Recurse over each
 * layer until the root is reached which will correspond to the perturbator polynomial F(X).
 * TODO(<https://github.com/AztecProtocol/barretenberg/issues/745>): make computation of perturbator more memory
 * efficient, operate in-place and use std::resize; add multithreading
 */
pub fn construct_perturbator_coefficients<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
>(
    betas: &[C::ScalarField],
    deltas: &[C::ScalarField],
    full_honk_evaluations: SharedPolynomial<T, C>,
) -> Vec<T::ArithmeticShare> {
    let width = full_honk_evaluations.coefficients.len();
    let mut first_level_coeffs = vec![vec![T::ArithmeticShare::default(); 2]; width / 2];

    first_level_coeffs
        .par_iter_mut()
        .enumerate()
        .for_each(|(parent_idx, parent_node)| {
            let node = parent_idx * 2;

            parent_node[0] = T::add(
                full_honk_evaluations.coefficients[node],
                T::mul_with_public(betas[0], full_honk_evaluations.coefficients[node + 1]),
            );

            parent_node[1] =
                T::mul_with_public(deltas[0], full_honk_evaluations.coefficients[node + 1]);
        });

    construct_coefficients_tree::<T, C>(betas, deltas, first_level_coeffs, 1)
}

/**
 * @brief Construct the power perturbator polynomial F(X) in coefficient form from the accumulator
 */
pub fn compute_perturbator<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    state: &mut T::State,
    accumulator: &mut ProvingKey<T, C, MegaFlavour>,
    deltas: &[C::ScalarField],
    accumulator_prover_memory: &DeciderProverMemory<T, C>,
) -> HonkProofResult<SharedPolynomial<T, C>> {
    let full_honk_evaluations = compute_row_evaluations(net, state, accumulator_prover_memory)?;

    let betas = &accumulator_prover_memory.gate_challenges;

    let log_circuit_size = accumulator.circuit_size.ilog2() as usize;

    // Compute the perturbator using only the first log_circuit_size-many betas/deltas
    let mut perturbator = construct_perturbator_coefficients::<T, C>(
        &betas[..log_circuit_size],
        &deltas[..log_circuit_size],
        full_honk_evaluations,
    );

    // Populate the remaining coefficients with zeros to reach the required constant size
    if log_circuit_size < CONST_PG_LOG_N {
        perturbator.resize(CONST_PG_LOG_N + 1, T::ArithmeticShare::default());
    }

    Ok(SharedPolynomial {
        coefficients: perturbator,
    })
}

/**
 * @brief Prepare a univariate polynomial for relation execution in one step of the combiner construction.
 * @details For a fixed prover polynomial index, extract that polynomial from each prover_memory in Vec<DeciderProvingMemory>. From
 * each polynomial, extract the value at row_idx. Use these values to create a univariate polynomial, and then
 * extend (i.e., compute additional evaluations at adjacent domain values) as needed.
 * @todo TODO(https://github.com/AztecProtocol/barretenberg/issues/751) Optimize memory
 */
pub(crate) fn extend_univariates<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>>(
    prover_memory: &Vec<&mut DeciderProverMemory<T, C>>,
    row_idx: usize,
) -> AllEntitiesBatch<T, C, MegaFlavour> {
    let mut coefficients_public: Vec<[C::ScalarField; NUM_KEYS]> =
        vec![[C::ScalarField::ZERO; NUM_KEYS]; LENGTH_PUBLIC];
    let mut coefficients_shared: Vec<[T::ArithmeticShare; NUM_KEYS]> =
        vec![[T::ArithmeticShare::default(); NUM_KEYS]; LENGTH_SHARED];

    prover_memory
        .iter()
        .enumerate()
        .for_each(|(pk_idx, memory)| {
            memory
                .polys
                .public_iter()
                .enumerate()
                .for_each(|(col_idx, value)| {
                    coefficients_public[col_idx][pk_idx] = value[row_idx];
                });
            memory
                .polys
                .shared_iter()
                .enumerate()
                .for_each(|(col_idx, value)| {
                    coefficients_shared[col_idx][pk_idx] = value[row_idx];
                });
        });

    let shared = coefficients_shared
        .into_iter()
        .map(|coeffs| {
            let mut univariate = SharedUnivariate::<T, C, BATCHED_EXTENDED_LENGTH>::default();
            univariate.extend_from(&coeffs);
            univariate.evaluations.to_vec()
        })
        .collect::<Vec<_>>();

    let public = coefficients_public
        .into_iter()
        .map(|coeffs| {
            let mut univariate = Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH>::default();
            univariate.extend_from(&coeffs);
            univariate.evaluations.to_vec()
        })
        .collect::<Vec<_>>();

    AllEntitiesBatch::from_elements(shared, public)
}

/**
 * @brief Compute the combiner polynomial $G$ in the Protogalaxy paper
 * @details We have implemented an optimization that (eg in the case where we fold one instance-witness pair at a
 * time) assumes the value G(1) is 0, which is true in the case where the witness to be folded is valid.
 * @todo (<https://github.com/AztecProtocol/barretenberg/issues/968>) Make combiner tests better
 *
 * @param prover_memory
 * @param gate_separators
 * @param relation_parameters
 * @param alphas
 * @return Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>
 */
pub fn compute_combiner<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    state: &mut T::State,
    prover_memory: &Vec<&mut DeciderProverMemory<T, C>>,
    gate_separators: &GateSeparatorPolynomial<C::ScalarField>,
    relation_parameters: &ExtendedRelationParameters<C::ScalarField>,
    alphas: &Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
) -> HonkProofResult<SharedUnivariate<T, C, BATCHED_EXTENDED_LENGTH>> {
    // TACEO TODO: In barretenberg there is virtual_size
    let common_polynomial_size = prover_memory[0].polys.witness.w_l().len();
    let mut univariate_accumulators =
        <MegaFlavour as MPCProverFlavour>::AllRelationAccHalfShared::default_with_total_lengths();

    // Accumulate the contribution from each sub-relation
    // TACEO TODO: Barretenberg uses balanced parallelization here with the trace_usage_tracker
    for i in 0..common_polynomial_size {
        // Construct extended univariates containers
        let extended_univariates = extend_univariates(prover_memory, i);

        let pow_challenge = gate_separators.beta_products[i];

        // Accumulate the i-th row's univariate contribution. Note that the relation parameters passed to
        // this function have already been folded. Moreover, linear-dependent relations that act over the
        // entire execution trace rather than on rows, will not be multiplied by the pow challenge.
        <MegaFlavour as MPCProverFlavour>::accumulate_relation_univariates_with_extended_parameters::<
            C, T, N, BATCHED_EXTENDED_LENGTH
        >(
            net,
            state,
            &mut univariate_accumulators,
            &extended_univariates,
            relation_parameters,
            &pow_challenge,
        )?;
    }

    let univariate_accumulators = MegaFlavour::reshare(univariate_accumulators, net, state)?;

    let mut result = SharedUnivariate::<T, C, BATCHED_EXTENDED_LENGTH>::default();
    //  Batch the univariate contributions from each sub-relation to obtain the round univariate
    <MegaFlavour as MPCProverFlavour>::extend_and_batch_univariates_with_distinct_challenges::<
        T,
        C,
        BATCHED_EXTENDED_LENGTH,
    >(
        &univariate_accumulators,
        &mut result,
        Univariate::<C::ScalarField, BATCHED_EXTENDED_LENGTH> {
            evaluations: [C::ScalarField::ONE; BATCHED_EXTENDED_LENGTH],
        },
        alphas.as_slice(),
    );
    Ok(result)
}
