use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::field_ct::FieldCT;
use ark_ff::AdditiveGroup;
use ark_ff::fields::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::barycentric::Barycentric;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;

/**
 * @brief For a small integer N = `virtual_log_n` and a given witness x = `log_n`, compute in-circuit an
 * `indicator_padding_array` of size \f$ N \f$, such that
 * \f{align}{ \text{indicator_padding_array}[i] = \text{"} i < x \text{"}. \f}. To achieve the strict ineqaulity, we
 * evaluate all Lagranges at (x-1) and compute step functions. More concretely
 *
 * 1) Constrain x to be in the range \f$ [1, \ldots, N] \f$ by asserting
 *    \f{align}{ \prod_{i=0}^{N-1} (x - 1 - i) = 0 \f}.
 *
 * 2) For \f$ i = 0, ..., N-1 \f$, evaluate \f$ L_i(x) \f$.
 *    Since \f$ 1 < x <= N \f$, \f$ L_i(x - 1) = 1 \f$ if and only if \f$  x - 1 =  i  \f$.
 *
 * 3) Starting at \f$ b_{N-1} = L_{N-1}(x - 1)\f$, compute the step functions
 *    \f{align}{
 *    b_i(x - 1) = \sum_{i}^{N-1} L_i(x - 1) = L_i(x - 1) + b_{i+1}(x - 1) \f}.
 *
 * We compute the Lagrange coefficients out-of-circuit, since \f$ N \f$ is a circuit constant.
 *
 * The resulting array is being used to pad the number of Verifier rounds in Sumcheck and Shplemini to a fixed constant
 * and turn Recursive Verifier circuits into constant circuits. Note that the number of gates required to compute
 * \f$ [b_0(x-1), \ldots, b_{N-1}(x-1)] \f$ only depends on \f$ N \f$ adding ~\f$ 4\cdot N \f$ gates to the circuit.
 *
 */
pub fn padding_indicator_array<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    const VIRTUAL_LOG_N: usize,
>(
    log_n: &FieldCT<C::ScalarField>,
    builder: &mut GenericUltraCircuitBuilder<C, T>,
    driver: &mut T,
) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
    let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
    let zero = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);

    // Create a domain of size `virtual_log_n` and compute Lagrange denominators
    let big_domain: Vec<C::ScalarField> = Barycentric::construct_big_domain(VIRTUAL_LOG_N, 1);
    let precomputed_denominator_inverses = Barycentric::construct_denominator_inverses_runtime(
        1,
        &big_domain,
        &Barycentric::construct_lagrange_denominators(VIRTUAL_LOG_N, &big_domain),
    );

    let terms = (0..VIRTUAL_LOG_N)
        .map(|i| {
            log_n.sub(&one, builder, driver).sub(
                &FieldCT::from_witness(big_domain[i].into(), builder),
                builder,
                driver,
            )
        })
        .collect::<Vec<_>>();

    let mut result = vec![zero.clone(); VIRTUAL_LOG_N];

    // 1) Build prefix products:
    //    prefix[i] = ∏_{m=0..(i-1)} (x - 1 - big_domain[m]), with prefix[0] = 1.
    let mut prefix = vec![one.clone(); VIRTUAL_LOG_N];
    for i in 1..VIRTUAL_LOG_N {
        prefix[i] = prefix[i - 1].multiply(&terms[i - 1], builder, driver)?;
    }

    // 2) Build suffix products:
    //    suffix[i] = ∏_{m=i..(N-1)} (x - 1 - big_domain[m]),
    //    but we'll store it in reverse:
    //    suffix[virtual_log_n] = 1.
    let mut suffix = vec![one.clone(); VIRTUAL_LOG_N + 1];
    for i in (1..=VIRTUAL_LOG_N).rev() {
        suffix[i - 1] = suffix[i].multiply(&terms[i - 1], builder, driver)?;
    }

    // To ensure 0 < log_n < N, note that suffix[1] = \prod_{i=1}^{N-1} (x - 1 - i), therefore we just need to ensure
    // that this product is 0.
    suffix[0].assert_equal(&zero, builder, driver);

    // 3) Combine prefixes & suffixes to get L_i(x-1):
    //    L_i(x-1) = (1 / lagrange_denominators[i]) * prefix[i] * suffix[i+1].
    //    (We skip factor (x - big_domain[i]) by splitting into prefix & suffix.)
    let prefix_by_suffix = FieldCT::multiply_many(&prefix, &suffix[1..], builder, driver)?;

    for i in 0..VIRTUAL_LOG_N {
        result[i] = prefix_by_suffix[i].multiply(
            &FieldCT::from_witness(precomputed_denominator_inverses[i].into(), builder),
            builder,
            driver,
        )?;
    }

    // Convert result into the array of step function evaluations sums b_i.
    for i in (1..=VIRTUAL_LOG_N - 1).rev() {
        result[i - 1] = result[i - 1].add(&result[i], builder, driver);
    }

    Ok(result)
}

/**
 * @brief Given a witness `n` and a padding indicator array computed from `log_n`, check in-circuit that the latter is
 * indded the logarithm of `n`.
 *
 * @details It is crucial that `log_n` is constrained to be in range [1, virtual_log_n], as it forces the first `log_n`
 * entries of `padding_indicator_array` to be equal to 1 and the rest of the entries to be equal to 0. This implies that
 * `n` can be reconstructed by incrementing each entry in the array and taking their product.
 *
 * @tparam Fr
 * @tparam virtual_log_n
 * @param padding_indicator_array
 * @param n expected = 2^(log_n)
 */
pub fn constrain_log_circuit_size<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    const VIRTUAL_LOG_N: usize,
>(
    padding_indicator_array: &[FieldCT<C::ScalarField>],
    n: &FieldCT<C::ScalarField>,
    builder: &mut GenericUltraCircuitBuilder<C, T>,
    driver: &mut T,
) -> HonkProofResult<()> {
    let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
    let mut accumulated_circuit_size = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

    for indicator in padding_indicator_array {
        accumulated_circuit_size.mul_assign(
            &indicator.add(&one, builder, driver),
            builder,
            driver,
        )?;
    }

    n.assert_equal(&accumulated_circuit_size, builder, driver);
    Ok(())
}
