use ark_ff::AdditiveGroup;
use ark_ff::fields::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::mega_builder::MegaCircuitBuilder;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::transcript::TranscriptCT;
use co_builder::transcript::TranscriptHasherCT;
use co_builder::types::field_ct::FieldCT;
use co_builder::types::goblin_types::GoblinElement;
use co_noir_common::barycentric::Barycentric;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_protogalaxy::RecursiveDeciderVerificationKey;

use crate::claim_batcher::Batch;
use crate::claim_batcher::ClaimBatcher;
use crate::kzg::KZG;
use crate::shplemini::ShpleminiVerifier;
use crate::sumcheck::SumcheckVerifier;

// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
const CONST_PROOF_SIZE_LOG_N: usize = 28;

pub struct DeciderRecursiveVerifier;

impl DeciderRecursiveVerifier {
    pub fn verify_proof<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        proof: Vec<FieldCT<C::ScalarField>>,
        accumulator: &mut RecursiveDeciderVerificationKey<C, T>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<(GoblinElement<C, T>, GoblinElement<C, T>)> {
        let mut transcript = TranscriptCT::<C, H>::new_verifier(proof);

        let padding_indicator_array = Self::padding_indicator_array::<C, T, CONST_PROOF_SIZE_LOG_N>(
            &accumulator.verification_key.log_circuit_size,
            builder,
            driver,
        )?;

        Self::constrain_log_circuit_size::<C, T, CONST_PROOF_SIZE_LOG_N>(
            &padding_indicator_array,
            &accumulator.verification_key.circuit_size,
            builder,
            driver,
        )?;

        let output = SumcheckVerifier::verify(
            &mut transcript,
            &mut accumulator.target_sum,
            &accumulator.relation_parameters,
            &accumulator.alphas,
            &mut accumulator.gate_challenges,
            &padding_indicator_array,
            builder,
            driver,
        )?;

        let unshifted_commitments = [
            accumulator.precomputed_commitments.elements.to_vec(),
            accumulator.witness_commitments.elements.to_vec(),
        ]
        .concat();
        let unshifted_scalars = [
            output.claimed_evaluations.precomputed.elements.to_vec(),
            output.claimed_evaluations.witness.elements.to_vec(),
        ]
        .concat();

        let to_be_shifted_commitments = accumulator.witness_commitments.to_be_shifted().to_vec();
        let shifted_scalars = output.claimed_evaluations.shifted_witness.elements.to_vec();

        let mut claim_batcher = ClaimBatcher {
            unshifted: Batch {
                commitments: unshifted_commitments,
                evaluations: unshifted_scalars,
                scalar: FieldCT::from(C::ScalarField::ONE),
            },
            shifted: Batch {
                commitments: to_be_shifted_commitments,
                evaluations: shifted_scalars,
                scalar: FieldCT::from(C::ScalarField::ONE),
            },
        };

        let mut opening_claim = ShpleminiVerifier::compute_batch_opening_claim(
            &padding_indicator_array,
            &mut claim_batcher,
            &output.challenges,
            &GoblinElement::one(builder),
            &mut transcript,
            builder,
            driver,
        )?;

        KZG::reduce_verify_batch_opening_claim(&mut opening_claim, &mut transcript, builder, driver)
    }

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
    fn padding_indicator_array<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        const VIRTUAL_LOG_N: usize,
    >(
        log_n: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        let one = FieldCT::from(C::ScalarField::ONE);
        let zero = FieldCT::from(C::ScalarField::ZERO);

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
                    &FieldCT::from(big_domain[i]),
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
    fn constrain_log_circuit_size<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        const VIRTUAL_LOG_N: usize,
    >(
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        n: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let one = FieldCT::from(C::ScalarField::ONE);
        let mut accumulated_circuit_size = FieldCT::from(C::ScalarField::ONE);

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
}
